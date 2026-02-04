"""
BluSec 2.0 - BLE GATT Client (Trusted Device)
Connects to the gate's GATT server, reads challenges, and writes responses.

For ESP32: See ESP32_EXAMPLE pseudo-code below.
For mobile: Port to Android (Java/Kotlin) or iOS (Swift).
"""

import asyncio
import logging
from typing import Optional
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from blusec2_crypto import BluSec2Crypto

# UUID definitions (must match gate server)
BLUSEC2_SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
CHALLENGE_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef1"
RESPONSE_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef2"


class BluSec2TrustedDevice:
    """
    BLE GATT Client for trusted device.

    Connects to the gate's GATT server, subscribes to challenge
    notifications, verifies them, and writes cryptographic responses.
    """

    def __init__(self, master_key: bytes, device_id: bytes):
        """
        Initialize trusted device.

        Args:
            master_key: Shared master key from pairing.
            device_id: This device's unique identifier.
        """
        self.master_key = master_key
        self.device_id = device_id
        self.logger = logging.getLogger(__name__)

        # Queue of validated challenges awaiting response (replaces raw
        # attribute polling to eliminate race conditions).
        self._challenge_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def handle_challenge(
        self,
        characteristic: BleakGATTCharacteristic,
        data: bytearray,
    ):
        """
        Handle incoming challenge notification from the gate.

        Validates the challenge signature and enqueues valid challenges
        for the response loop.

        Args:
            characteristic: The GATT characteristic that sent the notification.
            data: Challenge (32 bytes) + HMAC signature (32 bytes).
        """
        try:
            challenge = bytes(data[:32])
            signature = bytes(data[32:])

            self.logger.info(
                "Received challenge: %s...", challenge.hex()[:32]
            )

            # Verify challenge signature (±1 window tolerance for clock drift)
            timestamp = BluSec2Crypto.get_current_timestamp()
            is_valid = BluSec2Crypto.verify_challenge_signature(
                self.master_key, challenge, signature, timestamp
            )

            if not is_valid:
                self.logger.warning(
                    "Invalid challenge signature — ignoring"
                )
                return

            self.logger.info("Challenge signature verified")
            self._challenge_queue.put_nowait(challenge)

        except Exception as e:
            self.logger.error("Error handling challenge: %s", e)

    def _build_response(self, challenge: bytes) -> Optional[bytes]:
        """
        Generate HMAC response for a validated challenge.

        Args:
            challenge: The 32-byte challenge from the gate.

        Returns:
            32-byte response, or None on error.
        """
        try:
            timestamp = BluSec2Crypto.get_current_timestamp()

            response = BluSec2Crypto.generate_response(
                self.master_key,
                challenge,
                self.device_id,
                timestamp,
            )

            self.logger.info(
                "Generated response: %s...", response.hex()[:32]
            )
            return response

        except Exception as e:
            self.logger.error("Error generating response: %s", e)
            return None

    async def listen_and_respond(self, gate_address: str):
        """
        Connect to gate GATT server and handle challenge-response.

        Subscribes to challenge notifications.  Validated challenges are
        placed on an internal queue by handle_challenge(); this coroutine
        consumes them and writes responses back to the gate.

        Args:
            gate_address: BLE MAC address of the gate.
        """
        try:
            async with BleakClient(gate_address) as client:
                self.logger.info("Connected to gate %s", gate_address)

                # Subscribe to challenge notifications
                await client.start_notify(
                    CHALLENGE_CHAR_UUID,
                    self.handle_challenge,
                )

                self.logger.info("Listening for challenges...")

                while client.is_connected:
                    try:
                        challenge = await asyncio.wait_for(
                            self._challenge_queue.get(), timeout=1.0
                        )
                    except asyncio.TimeoutError:
                        continue

                    response = self._build_response(challenge)
                    if response:
                        await client.write_gatt_char(
                            RESPONSE_CHAR_UUID,
                            response,
                            response=True,
                        )
                        self.logger.info("Response sent to gate")

        except Exception as e:
            self.logger.error("Connection error: %s", e)


# ---------------------------------------------------------------------
# ESP32 Arduino/ESP-IDF pseudo-code (BLE GATT Client)
# ---------------------------------------------------------------------
ESP32_EXAMPLE = """
/*
 * BluSec 2.0 Trusted Device - ESP32 Implementation (BLE Client)
 *
 * The ESP32 acts as a GATT *client*, connecting to the gate's GATT server.
 * It subscribes to the Challenge characteristic (READ | NOTIFY) and writes
 * its response to the Response characteristic (WRITE).
 *
 * Requires:
 *   - ESP32 BLE Arduino library (or ESP-IDF BLE stack)
 *   - mbedtls (ships with ESP-IDF)
 *   - NTP time sync for accurate timestamps
 */

#include <BLEDevice.h>
#include <BLEClient.h>
#include "mbedtls/md.h"
#include "mbedtls/constant_time.h"   // for mbedtls_ct_memcmp
#include <time.h>

#define BLUSEC2_SERVICE_UUID "12345678-1234-5678-1234-56789abcdef0"
#define CHALLENGE_CHAR_UUID  "12345678-1234-5678-1234-56789abcdef1"
#define RESPONSE_CHAR_UUID   "12345678-1234-5678-1234-56789abcdef2"

// Stored in encrypted NVS flash
uint8_t master_key[32];

// IMPORTANT: device_id length must match the Python-side value exactly.
// The HMAC input is: challenge(32) + device_id(N) + timestamp(8).
// If the lengths differ, the HMAC will not match.
uint8_t device_id[16] = "ESP32-DEVICE-001";

// Gate BLE address (set during pairing)
static BLEAddress gateAddress("AA:BB:CC:DD:EE:FF");

BLEClient          *pClient;
BLERemoteService   *pRemoteService;
BLERemoteCharacteristic *pChallengeChar;
BLERemoteCharacteristic *pResponseChar;

// ------------------------------------------------------------------
// Timestamp — uses NTP-synced wall-clock, NOT millis()
// ------------------------------------------------------------------
uint32_t get_current_timestamp() {
    time_t now;
    time(&now);
    return (uint32_t)(now / 11);
}

// ------------------------------------------------------------------
// Constant-time signature verification (prevents timing attacks)
// ------------------------------------------------------------------
bool verify_challenge_signature(
    const uint8_t *key,
    const uint8_t *challenge,
    const uint8_t *signature,
    uint32_t timestamp
) {
    uint8_t expected[32];
    uint8_t data[40];  // 32 challenge + 8 timestamp (big-endian)

    memcpy(data, challenge, 32);
    // Store timestamp as big-endian 8 bytes (match Python int.to_bytes(8,'big'))
    for (int i = 7; i >= 0; i--) {
        data[32 + (7 - i)] = (timestamp >> (i * 8)) & 0xFF;
    }

    mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        key, 32,
        data, 40,
        expected
    );

    // Constant-time comparison — prevents timing side-channel attacks
    return mbedtls_ct_memcmp(expected, signature, 32) == 0;
}

void generate_response(
    const uint8_t *key,
    const uint8_t *challenge,
    const uint8_t *dev_id,
    uint32_t timestamp,
    uint8_t *response
) {
    uint8_t data[56];  // 32 challenge + 16 device_id + 8 timestamp

    memcpy(data, challenge, 32);
    memcpy(data + 32, dev_id, 16);
    for (int i = 7; i >= 0; i--) {
        data[48 + (7 - i)] = (timestamp >> (i * 8)) & 0xFF;
    }

    mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        key, 32,
        data, 56,
        response
    );
}

// ------------------------------------------------------------------
// BLE notification callback — called when gate updates the challenge
// ------------------------------------------------------------------
void challengeNotifyCallback(
    BLERemoteCharacteristic *pChar,
    uint8_t *pData,
    size_t length,
    bool isNotify
) {
    if (length != 64) return;  // 32 challenge + 32 signature

    uint8_t challenge[32], signature[32];
    memcpy(challenge, pData, 32);
    memcpy(signature, pData + 32, 32);

    uint32_t timestamp = get_current_timestamp();

    if (verify_challenge_signature(master_key, challenge, signature, timestamp)) {
        uint8_t response[32];
        generate_response(master_key, challenge, device_id, timestamp, response);

        // Write response to gate's Response characteristic
        pResponseChar->writeValue(response, 32, true);
        Serial.println("Challenge verified — response sent");
    } else {
        Serial.println("Invalid challenge signature");
    }
}

// ------------------------------------------------------------------
// Arduino setup / loop
// ------------------------------------------------------------------
void setup() {
    Serial.begin(115200);

    // Load master key from encrypted NVS
    load_master_key_from_nvs(master_key);

    // Sync time via NTP (required for matching gate timestamps)
    configTime(0, 0, "pool.ntp.org");
    Serial.println("Waiting for NTP sync...");
    struct tm timeinfo;
    while (!getLocalTime(&timeinfo)) {
        delay(500);
    }
    Serial.println("NTP synced");

    BLEDevice::init("BluSec2-Device");
    pClient = BLEDevice::createClient();

    Serial.println("BluSec 2.0 Trusted Device Ready (Client Mode)");
}

void loop() {
    if (!pClient->isConnected()) {
        Serial.println("Connecting to gate...");
        if (pClient->connect(gateAddress)) {
            pRemoteService = pClient->getService(BLUSEC2_SERVICE_UUID);
            if (pRemoteService == nullptr) {
                Serial.println("BluSec2 service not found on gate");
                pClient->disconnect();
            } else {
                pChallengeChar = pRemoteService->getCharacteristic(CHALLENGE_CHAR_UUID);
                pResponseChar  = pRemoteService->getCharacteristic(RESPONSE_CHAR_UUID);

                // Subscribe to challenge notifications
                pChallengeChar->registerForNotify(challengeNotifyCallback);
                Serial.println("Connected — listening for challenges");
            }
        }
    }
    delay(1000);
}
*/
"""


# ------------------------------------------------------------------
# Example / standalone usage
# ------------------------------------------------------------------

async def main():
    """Example usage of BluSec2TrustedDevice."""
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
    gate_address = "AA:BB:CC:DD:EE:FF"  # Replace with actual gate MAC

    device = BluSec2TrustedDevice(master_key, device_id)

    print("BluSec 2.0 Trusted Device Started")
    print("=" * 50)
    print(f"Device ID: {device_id.decode()}")
    print(f"Connecting to gate: {gate_address}")
    print()

    try:
        await device.listen_and_respond(gate_address)
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == "__main__":
    print("Python reference implementation for testing/development")
    print("For production, use ESP32 implementation (see ESP32_EXAMPLE).")
    print()
    # Uncomment to run Python version:
    # asyncio.run(main())
