"""
BluSec 2.0 - Core Cryptographic Module
Implements ECDH key exchange, challenge-response protocol, and ephemeral key derivation
"""

import time
import hmac
import hashlib
import secrets
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Time window for challenge-response (11 seconds)
CHALLENGE_INTERVAL = 11


class BluSec2Crypto:
    """
    Core cryptographic operations for BluSec 2.0
    
    Handles:
    - ECDH key exchange for initial pairing
    - Master key derivation
    - Challenge-response protocol
    - Ephemeral key derivation
    - Password hash encryption/decryption
    """
    
    @staticmethod
    def get_current_timestamp() -> int:
        """
        Get current time window (11-second intervals)
        
        Returns:
            int: Current timestamp divided by CHALLENGE_INTERVAL
        """
        return int(time.time() // CHALLENGE_INTERVAL)
    
    @staticmethod
    def generate_ecdh_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """
        Generate ECDH keypair for initial pairing
        
        Uses SECP256R1 (NIST P-256) curve for compatibility and security
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Serialize public key for transmission
        
        Args:
            public_key: EC public key to serialize
            
        Returns:
            bytes: Serialized public key in X9.62 uncompressed format
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    @staticmethod
    def deserialize_public_key(key_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """
        Deserialize public key from bytes
        
        Args:
            key_bytes: Serialized public key bytes
            
        Returns:
            EC public key object
        """
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), key_bytes
        )
    
    @staticmethod
    def derive_master_key(
        private_key: ec.EllipticCurvePrivateKey,
        peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        """
        Derive master key from ECDH shared secret
        
        Args:
            private_key: Own private key
            peer_public_key: Peer's public key
            
        Returns:
            bytes: 32-byte master key
        """
        # Perform ECDH key exchange
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive master key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'BluSec2-Master',
            info=b'v1',
        )
        
        return hkdf.derive(shared_secret)
    
    @staticmethod
    def generate_challenge() -> bytes:
        """
        Generate a random 32-byte challenge
        
        Returns:
            bytes: Random challenge value
        """
        return secrets.token_bytes(32)
    
    @staticmethod
    def sign_challenge(master_key: bytes, challenge: bytes, timestamp: Optional[int] = None) -> bytes:
        """
        Sign a challenge with HMAC to authenticate it
        
        Args:
            master_key: Shared master key
            challenge: Challenge bytes
            timestamp: Optional timestamp (uses current if not provided)
            
        Returns:
            bytes: HMAC signature
        """
        if timestamp is None:
            timestamp = BluSec2Crypto.get_current_timestamp()
        
        data = challenge + timestamp.to_bytes(8, 'big')
        return hmac.new(master_key, data, hashlib.sha256).digest()
    
    @staticmethod
    def verify_challenge_signature(
        master_key: bytes,
        challenge: bytes,
        signature: bytes,
        timestamp: Optional[int] = None,
        tolerance: int = 1,
    ) -> bool:
        """
        Verify challenge signature in constant time

        Checks the given timestamp plus ±tolerance windows to handle
        clock drift at 11-second window boundaries.

        Args:
            master_key: Shared master key
            challenge: Challenge bytes
            signature: HMAC signature to verify
            timestamp: Optional timestamp (uses current if not provided)
            tolerance: Number of adjacent time windows to accept (default 1)

        Returns:
            bool: True if signature is valid in any accepted window
        """
        if timestamp is None:
            timestamp = BluSec2Crypto.get_current_timestamp()
        for offset in range(-tolerance, tolerance + 1):
            expected = BluSec2Crypto.sign_challenge(
                master_key, challenge, timestamp + offset
            )
            if hmac.compare_digest(signature, expected):
                return True
        return False
    
    @staticmethod
    def generate_response(
        master_key: bytes,
        challenge: bytes,
        device_id: bytes,
        timestamp: Optional[int] = None
    ) -> bytes:
        """
        Generate response to a challenge
        
        Args:
            master_key: Shared master key
            challenge: Challenge received from gate
            device_id: Unique device identifier
            timestamp: Optional timestamp (uses current if not provided)
            
        Returns:
            bytes: Challenge response
        """
        if timestamp is None:
            timestamp = BluSec2Crypto.get_current_timestamp()
        
        data = challenge + device_id + timestamp.to_bytes(8, 'big')
        return hmac.new(master_key, data, hashlib.sha256).digest()
    
    @staticmethod
    def verify_response(
        master_key: bytes,
        challenge: bytes,
        response: bytes,
        device_id: bytes,
        timestamp: Optional[int] = None
    ) -> bool:
        """
        Verify challenge response in constant time
        
        Args:
            master_key: Shared master key
            challenge: Challenge that was sent
            response: Response received from device
            device_id: Expected device identifier
            timestamp: Optional timestamp (uses current if not provided)
            
        Returns:
            bool: True if response is valid
        """
        expected = BluSec2Crypto.generate_response(
            master_key, challenge, device_id, timestamp
        )
        return hmac.compare_digest(response, expected)

    @staticmethod
    def find_matching_timestamp(
        master_key: bytes,
        challenge: bytes,
        response: bytes,
        device_id: bytes,
        timestamp: Optional[int] = None,
        tolerance: int = 1,
    ) -> Optional[int]:
        """
        Find which timestamp (within tolerance) produced the response.

        Checks the given timestamp plus ±tolerance windows to handle
        clock drift at 11-second window boundaries.

        Args:
            master_key: Shared master key
            challenge: Challenge that was sent
            response: Response received from device
            device_id: Expected device identifier
            timestamp: Center timestamp to check (uses current if not provided)
            tolerance: Number of adjacent time windows to check (default 1)

        Returns:
            int: The matching timestamp, or None if no window matches
        """
        if timestamp is None:
            timestamp = BluSec2Crypto.get_current_timestamp()
        for offset in range(-tolerance, tolerance + 1):
            ts = timestamp + offset
            if BluSec2Crypto.verify_response(
                master_key, challenge, response, device_id, ts
            ):
                return ts
        return None

    @staticmethod
    def derive_ephemeral_key(
        master_key: bytes,
        challenge: bytes,
        response: bytes,
        device_id: bytes,
        timestamp: Optional[int] = None
    ) -> bytes:
        """
        Derive ephemeral decryption key from challenge-response
        
        This key is unique to the current time window and requires valid
        proximity proof (challenge-response).
        
        Args:
            master_key: Shared master key
            challenge: Challenge value
            response: Valid response from device
            device_id: Device identifier
            timestamp: Optional timestamp (uses current if not provided)
            
        Returns:
            bytes: 32-byte ephemeral key
        """
        if timestamp is None:
            timestamp = BluSec2Crypto.get_current_timestamp()
        
        # Key material: master key
        # Salt: challenge + response (proves proximity)
        # Info: protocol identifier + timestamp + device_id
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=challenge + response,
            info=b'BluSec2-Ephemeral' + timestamp.to_bytes(8, 'big') + device_id,
        )
        
        return hkdf.derive(master_key)
    
    @staticmethod
    def encrypt_password_hash(password_hash: bytes, ephemeral_key: bytes) -> bytes:
        """
        Encrypt password hash with ephemeral key using AES-256-GCM
        
        Args:
            password_hash: Password hash to encrypt
            ephemeral_key: Ephemeral encryption key
            
        Returns:
            bytes: nonce (12 bytes) + ciphertext + tag
        """
        aesgcm = AESGCM(ephemeral_key)
        nonce = secrets.token_bytes(12)
        
        # Encrypt with empty associated data
        ciphertext = aesgcm.encrypt(nonce, password_hash, None)
        
        # Return nonce + ciphertext (ciphertext includes auth tag)
        return nonce + ciphertext
    
    @staticmethod
    def decrypt_password_hash(encrypted_data: bytes, ephemeral_key: bytes) -> Optional[bytes]:
        """
        Decrypt password hash with ephemeral key
        
        Args:
            encrypted_data: nonce + ciphertext + tag
            ephemeral_key: Ephemeral decryption key
            
        Returns:
            bytes: Decrypted password hash, or None if decryption fails
        """
        try:
            aesgcm = AESGCM(ephemeral_key)
            
            # Extract nonce and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Decrypt
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception:
            # Decryption failed (wrong key, corrupted data, or tampered)
            return None
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using Argon2id

        Args:
            password: Plain text password

        Returns:
            str: Argon2-encoded hash string
        """
        ph = PasswordHasher()
        return ph.hash(password)

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verify a password against its Argon2 hash

        Args:
            password: Plain text password
            password_hash: Stored Argon2 hash string

        Returns:
            bool: True if password matches
        """
        ph = PasswordHasher()
        try:
            return ph.verify(password_hash, password)
        except VerifyMismatchError:
            return False


# Example usage and testing
if __name__ == "__main__":
    print("BluSec 2.0 Cryptographic Module Test")
    print("=" * 50)
    
    # Simulate pairing
    print("\n1. Pairing - ECDH Key Exchange")
    gate_private, gate_public = BluSec2Crypto.generate_ecdh_keypair()
    device_private, device_public = BluSec2Crypto.generate_ecdh_keypair()
    
    # Exchange public keys and derive master key
    gate_master_key = BluSec2Crypto.derive_master_key(gate_private, device_public)
    device_master_key = BluSec2Crypto.derive_master_key(device_private, gate_public)
    
    print(f"Gate master key: {gate_master_key.hex()[:32]}...")
    print(f"Device master key: {device_master_key.hex()[:32]}...")
    print(f"Keys match: {gate_master_key == device_master_key}")
    
    # Simulate challenge-response
    print("\n2. Challenge-Response Protocol")
    master_key = gate_master_key
    device_id = b"ESP32-DEVICE-001"
    
    challenge = BluSec2Crypto.generate_challenge()
    timestamp = BluSec2Crypto.get_current_timestamp()
    
    # Gate signs challenge
    challenge_signature = BluSec2Crypto.sign_challenge(master_key, challenge, timestamp)
    print(f"Challenge: {challenge.hex()[:32]}...")
    print(f"Challenge signature: {challenge_signature.hex()[:32]}...")
    
    # Device verifies and responds
    is_valid = BluSec2Crypto.verify_challenge_signature(
        master_key, challenge, challenge_signature, timestamp
    )
    print(f"Challenge signature valid: {is_valid}")
    
    response = BluSec2Crypto.generate_response(master_key, challenge, device_id, timestamp)
    print(f"Device response: {response.hex()[:32]}...")
    
    # Gate verifies response
    response_valid = BluSec2Crypto.verify_response(
        master_key, challenge, response, device_id, timestamp
    )
    print(f"Response valid: {response_valid}")
    
    # Derive ephemeral key
    print("\n3. Ephemeral Key Derivation")
    ephemeral_key = BluSec2Crypto.derive_ephemeral_key(
        master_key, challenge, response, device_id, timestamp
    )
    print(f"Ephemeral key: {ephemeral_key.hex()[:32]}...")
    
    # Encrypt and decrypt password hash
    print("\n4. Password Hash Encryption")
    password = "MySecurePassword123!"
    password_hash = BluSec2Crypto.hash_password(password)
    password_hash_bytes = password_hash.encode('utf-8')
    print(f"Password hash (Argon2): {password_hash[:48]}...")

    encrypted = BluSec2Crypto.encrypt_password_hash(password_hash_bytes, ephemeral_key)
    print(f"Encrypted: {encrypted.hex()[:32]}...")

    decrypted_bytes = BluSec2Crypto.decrypt_password_hash(encrypted, ephemeral_key)
    decrypted_hash = decrypted_bytes.decode('utf-8')
    print(f"Decrypted: {decrypted_hash[:48]}...")
    print(f"Decryption successful: {decrypted_hash == password_hash}")

    # Verify password
    print("\n5. Password Verification")
    print(f"Correct password: {BluSec2Crypto.verify_password(password, decrypted_hash)}")
    print(f"Wrong password: {BluSec2Crypto.verify_password('WrongPassword', decrypted_hash)}")
    
    # Test time window
    print("\n6. Time Window Test")
    print(f"Current timestamp: {timestamp}")
    print(f"Keys rotate every {CHALLENGE_INTERVAL} seconds")
    
    # Simulate next time window
    next_timestamp = timestamp + 1
    next_ephemeral = BluSec2Crypto.derive_ephemeral_key(
        master_key, challenge, response, device_id, next_timestamp
    )
    print(f"Next window ephemeral key: {next_ephemeral.hex()[:32]}...")
    print(f"Keys are different: {ephemeral_key != next_ephemeral}")
    
    # Try decrypting with wrong ephemeral key
    wrong_decrypt = BluSec2Crypto.decrypt_password_hash(encrypted, next_ephemeral)
    print(f"Decryption with wrong key fails: {wrong_decrypt is None}")
    
    print("\n" + "=" * 50)
    print("All tests completed successfully!")
