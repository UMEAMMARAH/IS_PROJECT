"""
SecureVault - Comprehensive Information Security Course Topics Test Suite
University Semester Project: Secure Document Management System

Tested Topics:
  1. Password Hashing & Key Derivation (PBKDF2/scrypt, salts, verification)
  2. Symmetric Cryptography (AES-256-GCM authenticated encryption & nonces)
  3. Academic Legacy Cryptography (DES demonstration, 64-bit blocks, 56-bit keys)
  4. Cryptographic Hashing & File Integrity (SHA-256, constant-time validation, tamper detection)
  5. SQL Injection Prevention (Parameterized queries & ORM safety against injection payloads)
  6. Cross-Site Scripting (XSS) Prevention (Jinja2 auto-escaping & header protections)
  7. Cross-Site Request Forgery (CSRF) Protection (Token enforcement on state-changing POSTs)
  8. Role-Based Access Control (RBAC) & Document Authorization (Privilege escalation & isolation)
  9. Defensive Limits & Session Anti-Caching (File size caps, cache-control headers, session invalidation)
"""

import io
import pytest
from cryptography.exceptions import InvalidTag
from werkzeug.datastructures import FileStorage

from authentication.models import User, Document, DocumentShare
from services.crypto_service import (
    encrypt_document_data,
    decrypt_document_data,
    compute_sha256,
    verify_sha256,
    academic_des_demonstration
)
from services.document_service import (
    save_uploaded_document,
    retrieve_document_bytes,
    delete_user_document,
    share_document_with_user,
    revoke_document_share
)
from tests.conftest import extract_csrf_token


# ==============================================================================
# TOPIC 1: SECURE PASSWORD HASHING
# ==============================================================================

def test_password_hashing_security():
    """
    Topic 1: Password Hashing
    Verifies that passwords are never stored in plaintext, use cryptographic salting,
    and different hashes are generated for identical passwords due to unique salts.
    """
    user = User(full_name="Crypto Tester", username="cryptotester", email="crypto@vault.io", role="User")
    password = "SuperSecretPassword2026!"
    user.set_password(password)

    # 1. Plaintext must never match hash
    assert user.password_hash != password
    assert len(user.password_hash) > 50

    # 2. Werkzeug hash contains algorithm prefix (scrypt or pbkdf2)
    assert any(alg in user.password_hash for alg in ['scrypt:', 'pbkdf2:'])

    # 3. Successful verification
    assert user.check_password(password) is True
    assert user.check_password("WrongPassword123!") is False

    # 4. Salt randomness: same password produces different hash
    user2 = User(full_name="Tester Two", username="testertwo", email="tester2@vault.io", role="User")
    user2.set_password(password)
    assert user.password_hash != user2.password_hash


# ==============================================================================
# TOPIC 2: AES-256-GCM AUTHENTICATED ENCRYPTION
# ==============================================================================

def test_aes_256_gcm_encryption_roundtrip():
    """
    Topic 2: AES-256-GCM
    Verifies authenticated symmetric encryption, unique 12-byte nonce per execution,
    and successful plaintext recovery.
    """
    secret_key = b"12345678901234567890123456789012"  # 32 bytes = 256 bits
    plaintext = b"SecureVault Confidential Research Document: Grade Rubric 2026"

    ciphertext1, nonce1 = encrypt_document_data(plaintext, key=secret_key)
    ciphertext2, nonce2 = encrypt_document_data(plaintext, key=secret_key)

    # 1. Nonce must be 12 bytes
    assert len(nonce1) == 12
    assert len(nonce2) == 12
    # 2. Nonces must be unique (probabilistic security)
    assert nonce1 != nonce2

    # 3. Ciphertexts must be different even for identical plaintexts
    assert ciphertext1 != ciphertext2

    # 4. Decrypt successfully
    recovered = decrypt_document_data(ciphertext1, nonce1, key=secret_key)
    assert recovered == plaintext


def test_aes_256_gcm_tamper_detection():
    """
    Topic 2 & 4: Authenticated Ciphertext Tamper Detection
    Verifies that any modification to ciphertext or authentication tag raises InvalidTag.
    """
    secret_key = b"12345678901234567890123456789012"
    plaintext = b"Cryptographic Authentication Payload"

    ciphertext, nonce = encrypt_document_data(plaintext, key=secret_key)

    # Tamper with one bit of the ciphertext
    tampered_bytes = bytearray(ciphertext)
    tampered_bytes[5] ^= 0x01
    tampered_ciphertext = bytes(tampered_bytes)

    # Decryption MUST fail and reject the tampered payload
    with pytest.raises(InvalidTag):
        decrypt_document_data(tampered_ciphertext, nonce, key=secret_key)


# ==============================================================================
# TOPIC 3: ACADEMIC DES (DATA ENCRYPTION STANDARD) DEMONSTRATION
# ==============================================================================

def test_academic_des_demonstration():
    """
    Topic 3: Legacy DES Analysis
    Verifies the academic DES demonstration module, proving Feistel block operation,
    56-bit key structure, and documented security deprecation.
    """
    result = academic_des_demonstration("Information Security DES Demonstration")
    assert result["block_size_bits"] == 64
    assert result["key_size_bits"] == 56
    assert result["integrity_verified"] is True
    assert "Obsolete & Insecure" in result["security_verdict"]
    assert result["recovered_plaintext"] == "Information Security DES Demonstration"


# ==============================================================================
# TOPIC 4: SECURE HASHING & SHA-256 INTEGRITY
# ==============================================================================

def test_sha256_digest_and_tamper_verification():
    """
    Topic 4: Secure Hashing
    Verifies SHA-256 hash calculation and constant-time integrity verification.
    """
    document_data = b"Final Exam Answer Sheet - Confidential"
    digest = compute_sha256(document_data)

    # 1. Digest is 64 hex characters (256 bits)
    assert len(digest) == 64
    assert isinstance(digest, str)

    # 2. Verification succeeds on unaltered data
    assert verify_sha256(document_data, digest) is True

    # 3. Verification fails on altered data (even 1 character change)
    tampered_data = b"Final Exam Answer Sheet - ConfidentiaL"
    assert verify_sha256(tampered_data, digest) is False


# ==============================================================================
# TOPIC 5: SQL INJECTION DEFENSE (SQLi)
# ==============================================================================

def test_sql_injection_defense_on_login(client, regular_user):
    """
    Topic 5: SQL Injection Resistance
    Tests classic SQL injection attack strings against login authentication.
    The ORM parameterized queries must safely treat payloads as literal values.
    """
    sqli_payloads = [
        "' OR '1'='1",
        "admin' --",
        "' OR 1=1 --",
        "\" OR \"\"=\"",
        "'; DROP TABLE users; --"
    ]

    for payload in sqli_payloads:
        # Fetch login form to obtain valid CSRF token
        get_res = client.get('/login')
        token = extract_csrf_token(get_res.get_data(as_text=True))

        post_res = client.post('/login', data={
            'csrf_token': token,
            'email': payload,
            'password': 'password123'
        })
        # Must return 200 with invalid credentials or invalid email format, never 500 error or bypass
        assert post_res.status_code == 200
        html = post_res.get_data(as_text=True)
        assert ("Invalid email" in html or "Invalid email or password" in html or "valid" in html)


def test_sql_injection_defense_on_admin_search(authenticated_admin):
    """
    Topic 5: SQL Injection in Admin Search
    Ensures searching with SQL injection syntax does not trigger SQL syntax errors.
    """
    res = authenticated_admin.get("/admin/users?q=%27+OR+1%3D1+--")
    assert res.status_code == 200


# ==============================================================================
# TOPIC 6: CROSS-SITE SCRIPTING DEFENSE (XSS)
# ==============================================================================

def test_xss_autoescaping_in_templates(authenticated_client):
    """
    Topic 6: Cross-Site Scripting (XSS)
    Verifies that user-supplied input containing HTML/script tags is escaped by Jinja2.
    """
    xss_payload = "<script>alert('XSS_ATTACK_VECTOR')</script>"

    # 1. Update full name with script tag
    get_res = authenticated_client.get('/profile')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    res = authenticated_client.post('/profile', data={
        'profile-csrf_token': token,
        'profile-full_name': xss_payload,
        'profile-submit': '1'
    }, follow_redirects=True)

    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Raw script tag must NOT be executed or unescaped in DOM
    assert "<script>alert('XSS_ATTACK_VECTOR')</script>" not in html
    # Escaped HTML entities must be present
    assert "&lt;script&gt;alert(&#39;XSS_ATTACK_VECTOR&#39;)&lt;/script&gt;" in html or \
           "&lt;script&gt;alert('XSS_ATTACK_VECTOR')&lt;/script&gt;" in html


# ==============================================================================
# TOPIC 7: CROSS-SITE REQUEST FORGERY DEFENSE (CSRF)
# ==============================================================================

def test_csrf_token_required_on_state_changes(authenticated_client):
    """
    Topic 7: CSRF Protection
    Ensures state-changing POST requests without CSRF token are strictly rejected.
    """
    # 1. Attempt profile update without CSRF token
    post_res = authenticated_client.post('/profile', data={
        'profile-full_name': 'Forged Profile Name',
        'profile-submit': '1'
    })
    assert post_res.status_code in (400, 403)

    # 2. Attempt logout without CSRF token
    logout_res = authenticated_client.post('/logout')
    assert logout_res.status_code in (400, 403)


# ==============================================================================
# TOPIC 8: ACCESS CONTROL (RBAC) & DOCUMENT AUTHORIZATION
# ==============================================================================

def test_document_authorization_and_sharing_lifecycle(app, regular_user):
    """
    Topic 8: Access Control & Authorization
    Tests document upload, encryption, permission check, sharing, and revocation.
    """
    with app.app_context():
        # Create second user
        user_b = User(
            full_name="Bob Collaborator",
            username="bob_collab",
            email="bob@vault.io",
            role="User",
            is_active=True
        )
        user_b.set_password("BobPassword2026!")
        from extensions import db
        db.session.add(user_b)
        db.session.commit()

        # 1. User A uploads an encrypted document
        file_content = b"Financial Q4 Budget Plan - Top Secret"
        file_obj = FileStorage(
            stream=io.BytesIO(file_content),
            filename="budget_q4.pdf",
            content_type="application/pdf"
        )
        doc = save_uploaded_document(file_obj, "Q4 Budget", regular_user, "127.0.0.1")
        assert doc.id is not None
        assert doc.is_encrypted is True
        assert doc.file_hash == compute_sha256(file_content)

        # 2. User A can retrieve and decrypt the file
        decrypted_bytes, filename, mime = retrieve_document_bytes(doc.id, regular_user)
        assert decrypted_bytes == file_content
        assert filename == "budget_q4.pdf"

        # 3. User B cannot retrieve User A's private document (Horizontal Privilege Escalation check)
        with pytest.raises(Exception):
            retrieve_document_bytes(doc.id, user_b)

        # 4. User A shares the document with User B as Viewer
        share = share_document_with_user(doc.id, regular_user, user_b.email, "Viewer")
        assert share.shared_with_email == "bob@vault.io"
        assert share.shared_with_user_id == user_b.id

        # 5. Now User B can retrieve and decrypt the file
        b_bytes, _, _ = retrieve_document_bytes(doc.id, user_b)
        assert b_bytes == file_content

        # 6. User A revokes the share
        revoke_document_share(share.id, regular_user)

        # 7. User B loses access immediately
        with pytest.raises(Exception):
            retrieve_document_bytes(doc.id, user_b)


# ==============================================================================
# TOPIC 9: DEFENSIVE LIMITS & SESSION SECURITY
# ==============================================================================

def test_security_headers_and_anti_caching(client, regular_user):
    """
    Topic 9: Anti-Caching & Defensive Headers
    Verifies that responses contain headers to defeat caching and MIME-sniffing.
    """
    # Login regular user
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))
    login_res = client.post('/login', data={
        'csrf_token': token,
        'email': regular_user.email,
        'password': 'SecurePass123!'
    }, follow_redirects=True)

    assert login_res.status_code == 200
    headers = login_res.headers

    # 1. Anti-caching headers (prevents back-button retrieval post logout)
    assert 'no-store' in headers.get('Cache-Control', '')
    assert 'no-cache' in headers.get('Cache-Control', '')

    # 2. MIME-type sniffing defense
    assert headers.get('X-Content-Type-Options') == 'nosniff'

    # 3. Clickjacking defense
    assert headers.get('X-Frame-Options') == 'SAMEORIGIN'
