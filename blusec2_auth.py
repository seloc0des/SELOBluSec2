"""
BluSec 2.0 - Complete Authentication Module
Integrates cryptography, BLE communication, and password verification
"""

import os
import re
import asyncio
import logging
import getpass
from typing import Optional
from pathlib import Path

from blusec2_crypto import BluSec2Crypto
from blusec2_gate_server import BluSec2GateServer


class BluSec2Authenticator:
    """
    Complete authentication flow orchestrator
    
    Manages the entire authentication process from proximity verification
    through password validation
    """
    
    def __init__(
        self,
        config_dir: str = "/etc/blusec2",
        user: Optional[str] = None
    ):
        """
        Initialize authenticator
        
        Args:
            config_dir: Directory containing configuration and keys
            user: Username to authenticate
        """
        self.config_dir = Path(config_dir)
        self.user = user or getpass.getuser()
        self._validate_username(self.user)
        self.logger = logging.getLogger(__name__)

        # Session state set after successful authentication
        self.session_ephemeral_key: Optional[bytes] = None

        # Load configuration
        self.master_key = self._load_master_key()
        self.device_id = self._load_device_id()
        self.device_address = self._load_device_address()
        
        # Initialize gate server
        self.gate = BluSec2GateServer(self.master_key, self.device_id)
    
    @staticmethod
    def _validate_username(username: str):
        """Reject usernames with path-traversal or unsafe characters."""
        if not re.fullmatch(r'[a-zA-Z0-9._-]+', username):
            raise ValueError(
                f"Invalid username '{username}': "
                "only alphanumeric, dot, underscore, and hyphen are allowed"
            )

    def _load_master_key(self) -> bytes:
        """Load master key from secure storage"""
        key_file = self.config_dir / "master_key.bin"
        
        if not key_file.exists():
            raise FileNotFoundError(
                f"Master key not found at {key_file}. "
                "Run 'blusec2 --mode setup' first."
            )
        
        with open(key_file, 'rb') as f:
            key = f.read()
        
        if len(key) != 32:
            raise ValueError("Invalid master key length")
        
        return key
    
    def _load_device_id(self) -> bytes:
        """Load trusted device ID"""
        device_file = self.config_dir / "device_id.txt"
        
        if not device_file.exists():
            raise FileNotFoundError(f"Device ID not found at {device_file}")
        
        with open(device_file, 'r') as f:
            device_id = f.read().strip()
        
        return device_id.encode('utf-8')
    
    def _load_device_address(self) -> str:
        """Load trusted device BLE address"""
        addr_file = self.config_dir / "device_address.txt"
        
        if not addr_file.exists():
            raise FileNotFoundError(
                f"Device address not found at {addr_file}"
            )
        
        with open(addr_file, 'r') as f:
            return f.read().strip()
    
    def _load_encrypted_password_hash(self) -> bytes:
        """Load encrypted password hash for user"""
        hash_file = self.config_dir / f"password_hashes/{self.user}.bin"
        
        if not hash_file.exists():
            raise FileNotFoundError(
                f"Password hash not found for user {self.user}"
            )
        
        with open(hash_file, 'rb') as f:
            return f.read()
    
    async def authenticate(
        self,
        password: Optional[str] = None,
        prompt: bool = True,
        proximity_only: bool = False,
    ) -> bool:
        """
        Complete authentication flow.

        Factor 1 (proximity): challenge-response via BLE proves device is near
        and derives a session-unique ephemeral key.
        Factor 2 (knowledge): password verified against stored hash (skipped
        when proximity_only=True, e.g. PAM MFA mode where pam_unix already
        verified the password).

        The stored hash is encrypted with the persistent master_key for
        at-rest protection.  The ephemeral key provides session-bound forward
        secrecy: each authentication session derives a unique key that cannot
        be reconstructed from past or future sessions.

        On success the ephemeral key is stored as self.session_ephemeral_key
        for optional downstream use (session encryption, audit proof).

        Args:
            password: User password (if not provided and prompt=True, will prompt).
            prompt: Whether to prompt for password if not provided.
            proximity_only: If True, only verify BLE proximity (skip password).

        Returns:
            bool: True if authentication successful.
        """
        try:
            self.logger.info("Starting authentication for user: %s", self.user)

            # Start gate GATT server if not already running
            if self.gate.server is None:
                loop = asyncio.get_running_loop()
                await self.gate.start(loop)

            # Step 1: Verify proximity via challenge-response
            success, ephemeral_key = await self.gate.wait_for_authentication(
                self.device_address
            )

            if not success or ephemeral_key is None:
                self.logger.warning("Proximity verification failed")
                print("Authentication failed: Trusted device not in range")
                return False

            self.logger.info("Proximity verified via challenge-response")

            # Proximity-only mode (e.g. PAM MFA where password was already
            # verified by pam_unix)
            if proximity_only:
                self.session_ephemeral_key = ephemeral_key
                self.logger.info(
                    "Proximity-only auth successful for user: %s", self.user
                )
                print("Proximity verification successful")
                return True

            # Step 2: Get password
            if password is None and prompt:
                password = getpass.getpass("Password: ")
            elif password is None:
                raise ValueError("Password required but not provided")

            # Step 3: Decrypt password hash using persistent master key
            encrypted_hash = self._load_encrypted_password_hash()

            decrypted_bytes = BluSec2Crypto.decrypt_password_hash(
                encrypted_hash,
                self.master_key,
            )

            if decrypted_bytes is None:
                self.logger.error("Failed to decrypt password hash")
                print("Authentication failed: Decryption error")
                return False

            decrypted_hash = decrypted_bytes.decode("utf-8")

            # Step 4: Verify password (Argon2)
            if not BluSec2Crypto.verify_password(password, decrypted_hash):
                self.logger.warning("Password verification failed")
                print("Authentication failed: Incorrect password")
                return False

            # Step 5: Bind proximity proof to successful authentication
            # The ephemeral key is session-unique and proves that both
            # proximity and password were verified in this session.
            self.session_ephemeral_key = ephemeral_key
            self.logger.info(
                "Authentication successful for user: %s", self.user
            )
            print("Authentication successful")
            return True

        except Exception as e:
            self.logger.error("Authentication error: %s", e, exc_info=True)
            print(f"Authentication failed: {e}")
            return False

    async def close(self):
        """Stop the gate server."""
        await self.gate.stop()


class BluSec2SetupManager:
    """
    Setup and pairing management
    
    Handles initial device pairing and user enrollment
    """
    
    def __init__(self, config_dir: str = "/etc/blusec2"):
        """
        Initialize setup manager
        
        Args:
            config_dir: Directory for configuration storage
        """
        self.config_dir = Path(config_dir)
        self.logger = logging.getLogger(__name__)
    
    async def perform_pairing(
        self,
        device_address: str,
        device_id: str
    ) -> tuple[bytes, bytes]:
        """
        Perform initial ECDH pairing with trusted device
        
        Args:
            device_address: BLE MAC address of device
            device_id: Unique identifier for device
            
        Returns:
            Tuple of (master_key, device_id_bytes)
        """
        self.logger.info("Starting pairing with device: %s", device_address)
        
        # Generate gate keypair
        gate_private, gate_public = BluSec2Crypto.generate_ecdh_keypair()
        gate_public_bytes = BluSec2Crypto.serialize_public_key(gate_public)
        
        print("Gate public key generated")
        print(f"Public key (hex): {gate_public_bytes.hex()}")
        print()
        print("Please send this public key to the trusted device")
        print("and enter the device's public key below:")
        print()
        
        # In production, this would be automated via BLE
        device_public_hex = input("Device public key (hex): ").strip()
        device_public_bytes = bytes.fromhex(device_public_hex)
        device_public = BluSec2Crypto.deserialize_public_key(device_public_bytes)
        
        # Derive master key
        master_key = BluSec2Crypto.derive_master_key(gate_private, device_public)
        
        print()
        print("✓ Pairing successful!")
        print("Master key derived and will be saved to config.")
        
        return master_key, device_id.encode('utf-8')
    
    def save_pairing_config(
        self,
        master_key: bytes,
        device_id: bytes,
        device_address: str
    ):
        """
        Save pairing configuration to disk
        
        Args:
            master_key: Derived master key
            device_id: Device identifier
            device_address: Device BLE address
        """
        # Create config directory
        self.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Save master key (encrypted in production)
        key_file = self.config_dir / "master_key.bin"
        with open(key_file, 'wb') as f:
            f.write(master_key)
        os.chmod(key_file, 0o600)
        
        # Save device ID
        device_id_file = self.config_dir / "device_id.txt"
        with open(device_id_file, 'w') as f:
            f.write(device_id.decode('utf-8'))
        os.chmod(device_id_file, 0o600)
        
        # Save device address
        addr_file = self.config_dir / "device_address.txt"
        with open(addr_file, 'w') as f:
            f.write(device_address)
        os.chmod(addr_file, 0o600)
        
        self.logger.info("Pairing configuration saved to %s", self.config_dir)
    
    def _load_master_key(self) -> bytes:
        """Load master key from secure storage."""
        key_file = self.config_dir / "master_key.bin"
        if not key_file.exists():
            raise FileNotFoundError(
                f"Master key not found at {key_file}. "
                "Run 'blusec2 --mode setup' first."
            )
        with open(key_file, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("Invalid master key length")
        return key

    def enroll_user(self, username: str, password: str):
        """
        Enroll a user with encrypted password hash.

        The password hash is encrypted with the persistent master_key.
        During authentication the challenge-response protocol proves
        proximity as a separate factor, while the master_key decrypts
        the stored hash for password verification.

        Args:
            username: Username to enroll.
            password: User's password.
        """
        BluSec2Authenticator._validate_username(username)

        # Create password hash directory
        hash_dir = self.config_dir / "password_hashes"
        hash_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Load the persistent master key
        master_key = self._load_master_key()

        # Hash password with Argon2
        password_hash = BluSec2Crypto.hash_password(password)
        password_hash_bytes = password_hash.encode("utf-8")

        # Encrypt with master key (AES-256-GCM)
        encrypted_hash = BluSec2Crypto.encrypt_password_hash(
            password_hash_bytes, master_key
        )

        # Save encrypted hash
        hash_file = hash_dir / f"{username}.bin"
        with open(hash_file, "wb") as f:
            f.write(encrypted_hash)
        os.chmod(hash_file, 0o600)

        self.logger.info("User %s enrolled successfully", username)
        print(f"User {username} enrolled")


# Command-line interface
async def cli_main():
    """Command-line interface for BluSec 2.0"""
    import argparse
    
    parser = argparse.ArgumentParser(description="BluSec 2.0 Authentication")
    parser.add_argument(
        '--mode',
        choices=['auth', 'setup', 'enroll'],
        required=True,
        help="Operation mode"
    )
    parser.add_argument('--user', help="Username for authentication")
    parser.add_argument('--device-address', help="BLE MAC address of device")
    parser.add_argument('--device-id', help="Device identifier")
    parser.add_argument('--config-dir', default="/etc/blusec2", help="Config directory")
    parser.add_argument('--verbose', action='store_true', help="Verbose logging")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if args.mode == 'auth':
        # Authentication mode
        if not args.user:
            print("Error: --user required for auth mode")
            return 1
        
        auth = BluSec2Authenticator(args.config_dir, args.user)
        try:
            success = await auth.authenticate()
            return 0 if success else 1
        finally:
            await auth.close()
    
    elif args.mode == 'setup':
        # Setup/pairing mode
        if not args.device_address or not args.device_id:
            print("Error: --device-address and --device-id required for setup")
            return 1
        
        setup = BluSec2SetupManager(args.config_dir)
        master_key, device_id = await setup.perform_pairing(
            args.device_address,
            args.device_id
        )
        setup.save_pairing_config(master_key, device_id, args.device_address)
        return 0
    
    elif args.mode == 'enroll':
        # User enrollment mode
        if not args.user:
            print("Error: --user required for enroll mode")
            return 1
        
        password = getpass.getpass(f"Password for {args.user}: ")
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            print("Error: Passwords do not match")
            return 1
        
        setup = BluSec2SetupManager(args.config_dir)
        setup.enroll_user(args.user, password)
        return 0


def cli_main_sync():
    """Sync entry point for console_scripts."""
    raise SystemExit(asyncio.run(cli_main()))


if __name__ == "__main__":
    cli_main_sync()
