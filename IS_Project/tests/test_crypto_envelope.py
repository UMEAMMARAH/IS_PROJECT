"""
Member 2 - Cryptographic test cases (envelope encryption, AES-256-GCM).

Each test maps to a claim in the cryptographic design section of the report.
"""
import os
import pytest
from services.crypto_service import (
    encrypt_document, decrypt_document, unwrap_dek, rewrap_dek,
    get_master_key, generate_master_key_text, IntegrityError,
    FILE_MAGIC, NONCE_SIZE,
)

PLAINTEXT = b"CONFIDENTIAL: Final exam paper 2026 - do not distribute"


def test_roundtrip(app):
    """C1: encrypt then decrypt returns the original bytes."""
    blob, wrapped = encrypt_document(PLAINTEXT, "doc-aaa")
    assert decrypt_document(blob, wrapped, "doc-aaa") == PLAINTEXT


def test_stored_blob_contains_no_plaintext(app):
    """C2: the stored file reveals nothing readable (storage-exposure scenario)."""
    blob, _ = encrypt_document(PLAINTEXT, "doc-aaa")
    assert PLAINTEXT not in blob
    assert b"CONFIDENTIAL" not in blob
    assert blob.startswith(FILE_MAGIC)


def test_fresh_key_and_nonce_every_time(app):
    """C3: same plaintext never gives the same ciphertext or the same DEK."""
    b1, w1 = encrypt_document(PLAINTEXT, "doc-aaa")
    b2, w2 = encrypt_document(PLAINTEXT, "doc-aaa")
    assert b1 != b2 and w1 != w2
    assert unwrap_dek(w1, "doc-aaa") != unwrap_dek(w2, "doc-aaa")


def test_each_document_has_its_own_key(app):
    """C4: compromising one document's DEK does not expose another's."""
    _, w1 = encrypt_document(b"one", "doc-1")
    _, w2 = encrypt_document(b"two", "doc-2")
    assert unwrap_dek(w1, "doc-1") != unwrap_dek(w2, "doc-2")


@pytest.mark.parametrize("offset", [len(FILE_MAGIC) + NONCE_SIZE + 2, -1, len(FILE_MAGIC) + 1])
def test_modified_file_is_detected(app, offset):
    """C5: flipping one bit in the ciphertext, tag or nonce is detected."""
    blob, wrapped = encrypt_document(PLAINTEXT, "doc-aaa")
    bad = bytearray(blob)
    bad[offset] ^= 0x01
    with pytest.raises(IntegrityError):
        decrypt_document(bytes(bad), wrapped, "doc-aaa")


def test_truncated_file_is_detected(app):
    """C6: a truncated or empty file is rejected, not crashed on."""
    blob, wrapped = encrypt_document(PLAINTEXT, "doc-aaa")
    for bad in (blob[:10], blob[:-5], b""):
        with pytest.raises(IntegrityError):
            decrypt_document(bad, wrapped, "doc-aaa")


def test_ciphertext_swap_between_documents_is_detected(app):
    """C7: AAD binding - file A presented as document B fails authentication."""
    blob_a, wrapped_a = encrypt_document(b"document A", "doc-A")
    with pytest.raises(IntegrityError):
        decrypt_document(blob_a, wrapped_a, "doc-B")


def test_swapped_wrapped_key_is_detected(app):
    """C8: using another document's wrapped key with this file fails."""
    blob_a, _ = encrypt_document(b"document A", "doc-A")
    _, wrapped_b = encrypt_document(b"document B", "doc-B")
    with pytest.raises(IntegrityError):
        decrypt_document(blob_a, wrapped_b, "doc-A")


def test_wrong_master_key_cannot_decrypt(app):
    """C9: without the master key, file + wrapped DEK are useless (DB+disk leak)."""
    blob, wrapped = encrypt_document(PLAINTEXT, "doc-aaa")
    attacker_key = os.urandom(32)
    with pytest.raises(IntegrityError):
        decrypt_document(blob, wrapped, "doc-aaa", master_key=attacker_key)


def test_master_key_rotation_rewraps_without_touching_file(app):
    """C10: key rotation only re-encrypts the small DEK, file is unchanged."""
    old = get_master_key()
    new = os.urandom(32)
    blob, wrapped = encrypt_document(PLAINTEXT, "doc-aaa", master_key=old)
    new_wrapped = rewrap_dek(wrapped, "doc-aaa", old, new)
    assert decrypt_document(blob, new_wrapped, "doc-aaa", master_key=new) == PLAINTEXT
    with pytest.raises(IntegrityError):
        decrypt_document(blob, new_wrapped, "doc-aaa", master_key=old)


def test_master_key_is_not_derived_from_secret_key(app):
    """C11: leaking Flask SECRET_KEY must not reveal the master key."""
    import hashlib
    derived = hashlib.sha256(app.config['SECRET_KEY'].encode()).digest()
    assert get_master_key() != derived
    assert len(get_master_key()) == 32


def test_master_key_file_is_created_once_and_reused(tmp_path):
    """C12: first run creates a random key file; later runs reuse the same key."""
    from app import create_app
    from config import TestConfig

    class FileKeyConfig(TestConfig):
        VAULT_MASTER_KEY = None
        VAULT_KEY_FILE = str(tmp_path / "master.key")

    app = create_app(FileKeyConfig)
    with app.app_context():
        k1 = get_master_key()
        k2 = get_master_key()
    assert k1 == k2 and len(k1) == 32
    assert os.path.exists(FileKeyConfig.VAULT_KEY_FILE)


def test_generate_master_key_text_is_32_bytes():
    import base64
    assert len(base64.urlsafe_b64decode(generate_master_key_text())) == 32