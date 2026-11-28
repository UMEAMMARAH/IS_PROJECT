"""
SecureVault Cryptographic Services  (Member 2)

1. Document protection : AES-256-GCM with ENVELOPE ENCRYPTION
     - every document gets its own random 256-bit Data Encryption Key (DEK)
     - the DEK is wrapped (encrypted) with a Master Key (KEK) that is kept
       OUTSIDE the database and OUTSIDE the encrypted-file folder
     - the document's unique id is bound into both layers as AAD, so a
       ciphertext cannot be swapped between documents undetected
2. Integrity           : AES-GCM authentication tag + SHA-256 digest of plaintext
3. Academic demo       : DES / 3DES (educational only, never used for documents)

Only the well-known `cryptography` library is used. No algorithm is
implemented from scratch.
"""

import os
import base64
import hashlib
import hmac
from typing import Tuple
from flask import current_app, has_app_context
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

NONCE_SIZE = 12                 # 96-bit nonce, the recommended size for GCM
KEY_SIZE = 32                   # 256-bit keys
FILE_MAGIC = b"SVG1"            # format marker + version of the encrypted file
_DOC_AAD_PREFIX = b"SecureVault-DOC-v1|"
_DEK_AAD_PREFIX = b"SecureVault-DEK-v1|"


class DocumentCryptoError(Exception):
    """Base class for document cryptography failures."""


class IntegrityError(DocumentCryptoError):
    """Raised when a stored document fails authentication (tampered, swapped,
    truncated, or decrypted with the wrong key)."""


# --------------------------------------------------------------------------
# Master key (KEK) management
# --------------------------------------------------------------------------

def _default_key_file() -> str:
    if has_app_context():
        configured = current_app.config.get('VAULT_KEY_FILE')
        if configured:
            return configured
        return os.path.join(current_app.root_path, 'database', 'master.key')
    return os.path.join(os.getcwd(), 'database', 'master.key')


def _decode_key(text: str) -> bytes:
    key = base64.urlsafe_b64decode(text.strip().encode('ascii'))
    if len(key) != KEY_SIZE:
        raise DocumentCryptoError("Master key must be exactly 32 bytes (256 bits).")
    return key


def get_master_key() -> bytes:
    """
    Load the 256-bit master key (key-encryption key).

    Lookup order (first match wins):
      1. VAULT_MASTER_KEY environment variable (base64url, 32 bytes)
      2. VAULT_MASTER_KEY in the Flask config (used by the test suite)
      3. Key file (default: database/master.key). Created automatically with
         os.urandom(32) on first run and restricted to the owner (chmod 600).

    The master key is deliberately NOT derived from Flask's SECRET_KEY, so
    leaking the session-signing secret does not expose any document.
    """
    env_key = os.environ.get('VAULT_MASTER_KEY')
    if env_key:
        return _decode_key(env_key)

    if has_app_context():
        cfg_key = current_app.config.get('VAULT_MASTER_KEY')
        if cfg_key:
            return _decode_key(cfg_key)

    path = _default_key_file()
    if os.path.exists(path):
        with open(path, 'r', encoding='ascii') as f:
            return _decode_key(f.read())

    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = os.urandom(KEY_SIZE)
    # O_EXCL: never overwrite an existing key (that would orphan every document)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as f:
        f.write(base64.urlsafe_b64encode(key).decode('ascii'))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best effort (Windows ignores POSIX modes)
    return key


def generate_master_key_text() -> str:
    """Return a fresh random master key as base64url text (for .env / key file)."""
    return base64.urlsafe_b64encode(os.urandom(KEY_SIZE)).decode('ascii')


# --------------------------------------------------------------------------
# 1. AES-256-GCM envelope encryption for real vault documents
# --------------------------------------------------------------------------

def _doc_aad(doc_uid: str) -> bytes:
    return _DOC_AAD_PREFIX + doc_uid.encode('utf-8')


def _dek_aad(doc_uid: str) -> bytes:
    return _DEK_AAD_PREFIX + doc_uid.encode('utf-8')


def encrypt_document(plaintext: bytes, doc_uid: str, master_key: bytes = None) -> Tuple[bytes, bytes]:
    """
    Envelope-encrypt a document.

    Returns (file_blob, wrapped_dek):
      file_blob   = MAGIC || nonce(12) || AES-256-GCM(DEK, plaintext) || tag(16)
      wrapped_dek = nonce(12) || AES-256-GCM(master_key, DEK) || tag(16)

    `doc_uid` is authenticated as AAD in both layers.
    """
    master = master_key or get_master_key()
    dek = AESGCM.generate_key(bit_length=256)          # fresh key per document

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, _doc_aad(doc_uid))
    file_blob = FILE_MAGIC + nonce + ciphertext

    wrap_nonce = os.urandom(NONCE_SIZE)
    wrapped_dek = wrap_nonce + AESGCM(master).encrypt(wrap_nonce, dek, _dek_aad(doc_uid))
    return file_blob, wrapped_dek


def unwrap_dek(wrapped_dek: bytes, doc_uid: str, master_key: bytes = None) -> bytes:
    master = master_key or get_master_key()
    if len(wrapped_dek) < NONCE_SIZE + KEY_SIZE + 16:
        raise IntegrityError("Wrapped document key is malformed.")
    try:
        return AESGCM(master).decrypt(wrapped_dek[:NONCE_SIZE], wrapped_dek[NONCE_SIZE:], _dek_aad(doc_uid))
    except InvalidTag:
        raise IntegrityError("Document key failed authentication (wrong master key or altered key record).")


def decrypt_document(file_blob: bytes, wrapped_dek: bytes, doc_uid: str, master_key: bytes = None) -> bytes:
    """
    Authenticate and decrypt a document. Raises IntegrityError if the file,
    the wrapped key, the document id, or the master key do not match.
    """
    if len(file_blob) < len(FILE_MAGIC) + NONCE_SIZE + 16 or not file_blob.startswith(FILE_MAGIC):
        raise IntegrityError("Encrypted file is truncated or has an unknown format.")
    dek = unwrap_dek(wrapped_dek, doc_uid, master_key)
    body = file_blob[len(FILE_MAGIC):]
    try:
        return AESGCM(dek).decrypt(body[:NONCE_SIZE], body[NONCE_SIZE:], _doc_aad(doc_uid))
    except InvalidTag:
        raise IntegrityError("Encrypted file failed authentication (modified, corrupted or swapped).")


def rewrap_dek(wrapped_dek: bytes, doc_uid: str, old_master: bytes, new_master: bytes) -> bytes:
    """
    Master-key rotation: re-encrypt only the small DEK under a new master key.
    The (possibly huge) document files do not need to be touched.
    """
    dek = unwrap_dek(wrapped_dek, doc_uid, old_master)
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(new_master).encrypt(nonce, dek, _dek_aad(doc_uid))


# --------------------------------------------------------------------------
# Legacy helpers (kept so Member 1's existing tests keep working)
# --------------------------------------------------------------------------

def encrypt_document_data(data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
    """Plain AES-256-GCM with an explicit key. Returns (ciphertext_with_tag, nonce)."""
    aesgcm = AESGCM(key if (key and len(key) == KEY_SIZE) else get_master_key())
    nonce = os.urandom(NONCE_SIZE)
    return aesgcm.encrypt(nonce, data, None), nonce


def decrypt_document_data(ciphertext: bytes, nonce: bytes, key: bytes = None) -> bytes:
    """Plain AES-256-GCM decrypt. Raises cryptography InvalidTag on tampering."""
    aesgcm = AESGCM(key if (key and len(key) == KEY_SIZE) else get_master_key())
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