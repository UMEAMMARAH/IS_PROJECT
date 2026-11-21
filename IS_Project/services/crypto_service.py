"""
SecureVault Cryptographic Services
1. Production Document Security: AES-256-GCM (Authenticated Encryption with Associated Data)
2. Integrity Verification: SHA-256 Cryptographic Digest
3. Academic Security Demonstration: DES (Data Encryption Standard) - Educational Only
"""

import os
import hashlib
import hmac
from typing import Tuple
from flask import current_app
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def _get_master_key(key: bytes = None) -> bytes:
    """Derive a 256-bit AES master key from application SECRET_KEY if not provided."""
    if key and len(key) == 32:
        return key
    secret = current_app.config.get('SECRET_KEY', 'default-vault-secure-key-3f8a912e')
    return hashlib.sha256(secret.encode('utf-8')).digest()


# --------------------------------------------------------------------------
# 1. AES-256-GCM Authenticated Encryption for Real Vault Documents
# --------------------------------------------------------------------------

def encrypt_document_data(data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
    """
    Encrypt document bytes using AES-256-GCM.
    Returns: (ciphertext_with_tag, nonce)
    Nonce is 12 bytes generated via cryptographically secure os.urandom.
    """
    master_key = _get_master_key(key)
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)  # Recommended standard GCM nonce length
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return ciphertext, nonce


def decrypt_document_data(ciphertext: bytes, nonce: bytes, key: bytes = None) -> bytes:
    """
    Decrypt and authenticate document bytes using AES-256-GCM.
    Guarantees both confidentiality and ciphertext integrity.
    Raises InvalidTag if ciphertext or nonce was tampered with.
    """
    master_key = _get_master_key(key)
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --------------------------------------------------------------------------
# 2. SHA-256 Cryptographic File Integrity Verification
# --------------------------------------------------------------------------

def compute_sha256(data: bytes) -> str:
    """Compute the SHA-256 hexadecimal hash digest for document integrity validation."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def verify_sha256(data: bytes, expected_hash: str) -> bool:
    """
    Verify document integrity using constant-time comparison to prevent timing attacks.
    """
    actual_hash = compute_sha256(data)
    return hmac.compare_digest(actual_hash.lower(), expected_hash.lower())


# --------------------------------------------------------------------------
# 3. Academic DES (Data Encryption Standard) Demonstration Module
# --------------------------------------------------------------------------

def academic_des_demonstration(sample_text: str = "SecureVault DES Academic Demo") -> dict:
    """
    Academic Demonstration of the Data Encryption Standard (DES).
    
    INFORMATION SECURITY COURSE CONCEPTS:
      - Block Size: 64 bits (8 bytes)
      - Key Size: 56 effective bits (8 bytes with 1 parity bit per byte)
      - Architecture: Feistel Network structure with 16 rounds
      - Security Analysis:
          * Insecure for modern usage: 56-bit key space (2^56 ~ 7.2 x 10^16 keys)
            can be brute-forced in hours by modern hardware (EFF Deep Crack, COPACOBANA).
          * Vulnerable to Sweet32 collision attacks due to small 64-bit block size.
          * Replaced by AES (Advanced Encryption Standard, Rijndael, 128/256-bit keys).
    
    NOTICE: This implementation is for classroom/academic presentation purposes only.
    All real SecureVault documents are protected with AES-256-GCM.
    """
    # 8-byte key and 8-byte IV for DES
    des_key = b"VltSec56"  # 8 bytes (56 bits + 8 parity bits)
    des_iv = b"InitVect"   # 8 bytes block IV

    data_bytes = sample_text.encode('utf-8')

    # PKCS7 padding to align with DES 64-bit (8-byte) block boundary
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()

    # Encrypt with TripleDES/DES
    cipher = Cipher(algorithms.TripleDES(des_key * 3), modes.CBC(des_iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Decrypt
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    recovered_plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

    return {
        "algorithm": "DES (Demonstrated via TripleDES-56)",
        "block_size_bits": 64,
        "key_size_bits": 56,
        "mode": "CBC with PKCS7 padding",
        "sample_input": sample_text,
        "ciphertext_hex": ciphertext.hex(),
        "recovered_plaintext": recovered_plaintext.decode('utf-8'),
        "integrity_verified": recovered_plaintext.decode('utf-8') == sample_text,
        "security_verdict": "Obsolete & Insecure (Demonstration Only; AES-256-GCM used in production)"
    }
