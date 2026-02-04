"""
BluSec 2.0 - BLE GATT Server (Gate)
Implements BLE GATT server for challenge-response communication using bless.

The gate advertises a BluSec2 service with two characteristics:
  - Challenge (READ | NOTIFY): 64 bytes = challenge(32) + HMAC signature(32)
  - Response  (WRITE):         32 bytes = HMAC response from trusted device

Trusted devices connect as GATT clients (via bleak), read the current
challenge, and write back a cryptographic response.
"""

import asyncio
import logging
from typing import Any, Optional

from bless import (
    BlessServer,
    BlessGATTCharacteristic,
    GATTCharacteristicProperties,
    GATTAttributePermissions,
)
from bleak import BleakScanner  # kept for RSSI proximity checks

from blusec2_crypto import BluSec2Crypto, CHALLENGE_INTERVAL

# UUID for BluSec 2.0 service and characteristics
BLUSEC2_SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
CHALLENGE_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef1"
RESPONSE_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef2"
RSSI_THRESHOLD = -70  # dBm - adjust based on desired proximity
RSSI_UNAVAILABLE = -999.0  # Sentinel value when RSSI cannot be determined


class BluSec2GateServer:
    """
    BLE GATT Server implementation for the gate.

    Manages challenge generation, response verification, and proximity checks.
    The gate is *passive*: it advertises, the trusted device connects.
    """

    def __init__(
        self,
        master_key: bytes,
        device_id: bytes,
        rssi_threshold: int = RSSI_THRESHOLD,
        server_name: str = "BluSec2-Gate",
    ):
        """
        Initialize the gate server.

        Args:
            master_key: Shared master key with trusted device.
            device_id: Expected device identifier.
            rssi_threshold: Minimum RSSI for proximity verification (dBm).
            server_name: BLE advertised name.
        """
        self.master_key = master_key
        self.device_id = device_id
        self.rssi_threshold = rssi_threshold
        self.server_name = server_name

        self.current_challenge: Optional[bytes] = None
        self.current_timestamp: Optional[int] = None
        self.challenge_lock = asyncio.Lock()

        self.server: Optional[BlessServer] = None
        self.auth_event = asyncio.Event()
        self.last_response: Optional[bytes] = None

        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # GATT callbacks
    # ------------------------------------------------------------------

    def _on_read(
        self, characteristic: BlessGATTCharacteristic, **kwargs
    ) -> bytearray:
        """Handle read requests on any characteristic."""
        self.logger.debug(
            "Read request on %s, value length=%d",
            characteristic.uuid,
            len(characteristic.value) if characteristic.value else 0,
        )
        return characteristic.value

    def _on_write(
        self, characteristic: BlessGATTCharacteristic, value: Any, **kwargs
    ):
        """Handle write requests — specifically the Response characteristic."""
        char_uuid = str(characteristic.uuid).lower()
        response_uuid = RESPONSE_CHAR_UUID.lower()

        if char_uuid == response_uuid:
            self.logger.info("Received response (%d bytes)", len(value))
            characteristic.value = value
            self.last_response = bytes(value)
            self.auth_event.set()
        else:
            self.logger.warning(
                "Unexpected write to characteristic %s", characteristic.uuid
            )

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def start(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        """Start the GATT server and begin advertising."""
        if loop is None:
            loop = asyncio.get_running_loop()

        gatt = {
            BLUSEC2_SERVICE_UUID: {
                CHALLENGE_CHAR_UUID: {
                    "Properties": (
                        GATTCharacteristicProperties.read
                        | GATTCharacteristicProperties.notify
                    ),
                    "Permissions": GATTAttributePermissions.readable,
                    "Value": bytearray(64),
                },
                RESPONSE_CHAR_UUID: {
                    "Properties": GATTCharacteristicProperties.write,
                    "Permissions": GATTAttributePermissions.writeable,
                    "Value": bytearray(32),
                },
            }
        }

        self.server = BlessServer(
            name=self.server_name,
            loop=loop,
        )
        self.server.read_request_func = self._on_read
        self.server.write_request_func = self._on_write

        await self.server.add_gatt(gatt)
        await self.server.start()

        # Seed the first challenge
        await self._rotate_challenge()

        self.logger.info(
            "BluSec2 Gate GATT server started, advertising '%s'",
            self.server_name,
        )

    async def stop(self):
        """Stop the GATT server."""
        if self.server:
            await self.server.stop()
            self.server = None
            self.logger.info("BluSec2 Gate GATT server stopped")

    # ------------------------------------------------------------------
    # Challenge management
    # ------------------------------------------------------------------

    async def _rotate_challenge(self):
        """Generate a new challenge and update the Challenge characteristic."""
        async with self.challenge_lock:
            self.current_challenge = BluSec2Crypto.generate_challenge()
            self.current_timestamp = BluSec2Crypto.get_current_timestamp()

            signature = BluSec2Crypto.sign_challenge(
                self.master_key,
                self.current_challenge,
                self.current_timestamp,
            )

            challenge_data = bytearray(self.current_challenge + signature)

            char = self.server.get_characteristic(CHALLENGE_CHAR_UUID)
            if char is None:
                self.logger.error(
                    "Challenge characteristic %s not found in GATT table",
                    CHALLENGE_CHAR_UUID,
                )
                return
            char.value = challenge_data

            self.server.update_value(
                BLUSEC2_SERVICE_UUID, CHALLENGE_CHAR_UUID
            )

            self.logger.info(
                "Challenge rotated for timestamp %d", self.current_timestamp
            )

    async def challenge_rotation_task(self, interval: int = CHALLENGE_INTERVAL):
        """
        Background task to rotate challenges every *interval* seconds.

        WARNING: Do NOT run this task concurrently with wait_for_authentication()
        for single auth requests, as it can cause race conditions where the
        challenge changes between snapshot and verification. Each call to
        wait_for_authentication() generates its own fresh challenge.

        This task is only useful for:
        - Long-running GATT servers handling multiple concurrent connections
        - Pre-rotating challenges before auth requests arrive
        - Testing time-window based replay protection

        For typical PAM/CLI usage, do NOT start this task.
        """
        while True:
            await asyncio.sleep(interval)
            await self._rotate_challenge()

    # ------------------------------------------------------------------
    # Proximity verification (still uses BleakScanner)
    # ------------------------------------------------------------------

    async def verify_proximity(
        self, device_address: str
    ) -> tuple[bool, float]:
        """
        Verify device is in close proximity using RSSI.

        Args:
            device_address: BLE MAC address of device.

        Returns:
            Tuple of (is_close, rssi_value).
        """
        try:
            devices = await BleakScanner.discover(timeout=5.0)

            for device in devices:
                if device.address.upper() == device_address.upper():
                    rssi = device.rssi
                    # Bleak may report None for RSSI in some cases
                    if rssi is None:
                        self.logger.warning(
                            "Device %s found but RSSI unavailable",
                            device_address,
                        )
                        return False, RSSI_UNAVAILABLE

                    is_close = rssi >= self.rssi_threshold

                    self.logger.info(
                        "Device %s RSSI: %d dBm "
                        "(threshold: %d dBm, in range: %s)",
                        device_address,
                        rssi,
                        self.rssi_threshold,
                        is_close,
                    )
                    return is_close, float(rssi)

            self.logger.warning(
                "Device %s not found in scan", device_address
            )
            return False, RSSI_UNAVAILABLE

        except Exception as e:
            self.logger.error("RSSI check failed: %s", e)
            return False, RSSI_UNAVAILABLE

    # ------------------------------------------------------------------
    # Authentication flow
    # ------------------------------------------------------------------

    async def wait_for_authentication(
        self,
        device_address: str,
        timeout: float = 30.0,
        skip_proximity_scan: bool = True,
    ) -> tuple[bool, Optional[bytes]]:
        """
        Wait for a trusted device to complete challenge-response.

        The gate is passive (GATT server). The trusted device connects,
        reads the Challenge characteristic, and writes a response.

        Args:
            device_address: BLE MAC address of trusted device (for logging).
            timeout: Seconds to wait for a response write.
            skip_proximity_scan: Skip active scanning for device advertisements.
                                The ability to complete the GATT challenge-response
                                itself proves proximity (default: True).

        Returns:
            Tuple of (success, ephemeral_key).
        """
        self.logger.info(
            "Waiting for authentication from %s", device_address
        )

        # Step 1: Optional proximity scan (DEPRECATED)
        # The trusted device acts as a GATT client and typically doesn't
        # advertise, so this scan will fail unless the device implements
        # separate advertising. Connection-based proximity (successful
        # GATT response) is sufficient for most deployments.
        if not skip_proximity_scan:
            is_close, rssi = await self.verify_proximity(device_address)
            if not is_close:
                self.logger.warning(
                    "Proximity check failed: RSSI %.0f < %d",
                    rssi,
                    self.rssi_threshold,
                )
                return False, None

        # Step 2: Clear state before rotating challenge to avoid race condition
        self.auth_event.clear()
        self.last_response = None

        # Step 3: Fresh challenge so device gets a new one
        # Snapshot the challenge and timestamp to prevent background rotation
        # from invalidating the response
        await self._rotate_challenge()
        async with self.challenge_lock:
            challenge_snapshot = self.current_challenge
            timestamp_snapshot = self.current_timestamp

        # Step 4: Wait for device to write its response

        try:
            await asyncio.wait_for(self.auth_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.warning("Timed out waiting for response")
            return False, None

        response = self.last_response
        if response is None or len(response) != 32:
            self.logger.warning("Invalid response length")
            return False, None

        # Step 5: Verify response (with ±1 window tolerance for clock drift)
        # Use snapshots to avoid issues with background challenge rotation
        matched_ts = BluSec2Crypto.find_matching_timestamp(
            self.master_key,
            challenge_snapshot,
            response,
            self.device_id,
            timestamp_snapshot,
        )

        if matched_ts is None:
            self.logger.warning("Invalid challenge response")
            return False, None

        # Step 6: Derive ephemeral key using the matched timestamp
        ephemeral_key = BluSec2Crypto.derive_ephemeral_key(
            self.master_key,
            challenge_snapshot,
            response,
            self.device_id,
            matched_ts,
        )

        self.logger.info(
            "Authentication successful — ephemeral key derived "
            "(proximity verified via successful GATT challenge-response)"
        )
        return True, ephemeral_key


# ------------------------------------------------------------------
# Example / standalone usage
# ------------------------------------------------------------------

async def main():
    """Example usage of BluSec2GateServer as a GATT server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # In production, load from secure storage
    master_key = bytes.fromhex(
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
    )
    device_id = b"ESP32-DEVICE-001"
    device_address = "AA:BB:CC:DD:EE:FF"  # Replace with actual device MAC

    gate = BluSec2GateServer(master_key, device_id)

    loop = asyncio.get_running_loop()
    await gate.start(loop)

    # NOTE: challenge_rotation_task() is NOT started here to avoid race
    # conditions during authentication. Each call to wait_for_authentication()
    # generates a fresh challenge, which is sufficient for single auth attempts.
    # Only start the background rotation task if you need to handle multiple
    # concurrent auth requests or want to rotate challenges independently.

    print("BluSec 2.0 Gate GATT Server Started")
    print("=" * 50)
    print(f"Device ID: {device_id.decode()}")
    print(f"RSSI Threshold: {RSSI_THRESHOLD} dBm")
    print()

    try:
        print("Waiting for trusted device to connect...")
        success, ephemeral_key = await gate.wait_for_authentication(
            device_address
        )

        if success:
            print("\nAuthentication successful!")
            print(f"Ephemeral key: {ephemeral_key.hex()[:32]}...")
        else:
            print("\nAuthentication failed!")

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await gate.stop()


if __name__ == "__main__":
    asyncio.run(main())
