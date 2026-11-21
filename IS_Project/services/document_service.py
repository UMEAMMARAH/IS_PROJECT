"""
SecureVault Document Management Service
Handles authenticated upload, AES-256-GCM encryption, disk storage,
decryption, SHA-256 integrity verification, access control, and deletion.
"""

import os
import uuid
from flask import current_app, abort
from werkzeug.utils import secure_filename
from extensions import db
from authentication.models import User, Document, DocumentShare
from services.crypto_service import encrypt_document_data, decrypt_document_data, compute_sha256, verify_sha256
from services.audit_service import record_audit_event, get_recent_audit_events, get_audit_count

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'xlsx', 'xls', 'txt', 'csv', 'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 Megabytes


def get_vault_storage_dir() -> str:
    """Returns absolute path to secure encrypted storage directory."""
    storage_dir = os.path.join(current_app.root_path, 'database', 'vault_storage')
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def is_allowed_file(filename: str) -> bool:
    """Validate file extension against safe whitelist."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def save_uploaded_document(file_storage, title: str, owner_user: User, client_ip: str = "N/A") -> Document:
    """
    Encrypt and store an uploaded document with integrity verification.
    """
    if not file_storage or not file_storage.filename:
        raise ValueError("No file selected for upload.")

    original_name = secure_filename(file_storage.filename)
    if not original_name or not is_allowed_file(original_name):
        raise ValueError(f"File type not permitted. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    # Read binary stream
    file_bytes = file_storage.read()
    if len(file_bytes) == 0:
        raise ValueError("Uploaded file is empty.")
    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds maximum allowed size of 50 MB.")

    # 1. Compute SHA-256 integrity digest on raw plaintext
    file_hash = compute_sha256(file_bytes)

    # 2. Encrypt using AES-256-GCM
    ciphertext, nonce = encrypt_document_data(file_bytes)

    # 3. Store on disk: Nonce (12 bytes) prepended to ciphertext
    stored_name = f"{uuid.uuid4().hex}_{original_name}.enc"
    storage_dir = get_vault_storage_dir()
    stored_path = os.path.join(storage_dir, stored_name)

    with open(stored_path, 'wb') as f:
        f.write(nonce + ciphertext)

    # 4. Create database record
    doc_title = title.strip() if (title and title.strip()) else original_name
    document = Document(
        user_id=owner_user.id,
        title=doc_title,
        original_filename=original_name,
        stored_filename=stored_name,
        file_path=stored_path,
        file_size=len(file_bytes),
        mime_type=file_storage.mimetype or 'application/octet-stream',
        file_hash=file_hash,
        is_encrypted=True
    )
    db.session.add(document)
    db.session.commit()

    # 5. Record security audit event
    record_audit_event(
        owner_user.id,
        "Document upload",
        {
            "document_id": document.id,
            "title": document.title,
            "size_bytes": document.file_size,
            "sha256": document.file_hash,
            "cipher": "AES-256-GCM"
        },
        client_ip
    )

    return document


def retrieve_document_bytes(document_id: int, requesting_user: User, client_ip: str = "N/A"):
    """
    Authenticate, decrypt, and verify integrity of requested document.
    Enforces authorization: owner, active share recipient, or Admin.
    """
    document = db.session.get(Document, document_id)
    if not document:
        abort(404)

    # Access Control Check
    is_owner = (document.user_id == requesting_user.id)
    is_admin = requesting_user.is_admin
    has_share = DocumentShare.query.filter(
        DocumentShare.document_id == document.id,
        (DocumentShare.shared_with_email == requesting_user.email.lower()) |
        (DocumentShare.shared_with_user_id == requesting_user.id)
    ).first() is not None

    if not (is_owner or is_admin or has_share):
        record_audit_event(
            requesting_user.id,
            "Unauthorized access attempt",
            {"target_document_id": document.id, "reason": "No permission grant"},
            client_ip
        )
        abort(403)

    if not os.path.exists(document.file_path):
        abort(404)

    # Read encrypted package from storage
    with open(document.file_path, 'rb') as f:
        raw_payload = f.read()

    nonce = raw_payload[:12]
    ciphertext = raw_payload[12:]

    # Decrypt with AES-256-GCM
    decrypted_bytes = decrypt_document_data(ciphertext, nonce)

    # Integrity verification
    if not verify_sha256(decrypted_bytes, document.file_hash):
        record_audit_event(
            requesting_user.id,
            "Security Violation: Integrity Failure",
            {"document_id": document.id, "alert": "SHA-256 checksum mismatch"},
            client_ip
        )
        raise ValueError("Document integrity verification failed! The file may have been tampered with.")

    record_audit_event(
        requesting_user.id,
        "Document download",
        {"document_id": document.id, "title": document.title},
        client_ip
    )

    return decrypted_bytes, document.original_filename, document.mime_type


def delete_user_document(document_id: int, requesting_user: User, client_ip: str = "N/A") -> bool:
    """
    Securely delete document record and physical encrypted storage.
    Enforces ownership or administrator privileges.
    """
    document = db.session.get(Document, document_id)
    if not document:
        abort(404)

    if document.user_id != requesting_user.id and not requesting_user.is_admin:
        record_audit_event(
            requesting_user.id,
            "Unauthorized deletion attempt",
            {"target_document_id": document.id},
            client_ip
        )
        abort(403)

    # Remove file on disk if exists
    if os.path.exists(document.file_path):
        try:
            os.remove(document.file_path)
        except OSError:
            pass

    doc_title = document.title
    db.session.delete(document)
    db.session.commit()

    record_audit_event(
        requesting_user.id,
        "Document deletion",
        {"document_id": document_id, "title": doc_title},
        client_ip
    )
    return True


def share_document_with_user(document_id: int, sharer_user: User, recipient_email: str, permission_tier: str, client_ip: str = "N/A") -> DocumentShare:
    """
    Grant document permission to a recipient by email address.
    """
    document = db.session.get(Document, document_id)
    if not document:
        abort(404)

    if document.user_id != sharer_user.id and not sharer_user.is_admin:
        abort(403)

    clean_email = recipient_email.strip().lower()
    if clean_email == sharer_user.email.lower():
        raise ValueError("You cannot share a document with yourself.")

    valid_tiers = {'Viewer', 'Editor', 'Auditor'}
    if permission_tier not in valid_tiers:
        permission_tier = 'Viewer'

    # Check if recipient is a registered user
    recipient_user = User.query.filter(User.email.ilike(clean_email)).first()
    recipient_id = recipient_user.id if recipient_user else None

    # Check existing share
    existing_share = DocumentShare.query.filter_by(
        document_id=document.id,
        shared_with_email=clean_email
    ).first()

    if existing_share:
        existing_share.permission_tier = permission_tier
        existing_share.shared_with_user_id = recipient_id
        share = existing_share
    else:
        share = DocumentShare(
            document_id=document.id,
            shared_by_user_id=sharer_user.id,
            shared_with_email=clean_email,
            shared_with_user_id=recipient_id,
            permission_tier=permission_tier
        )
        db.session.add(share)

    db.session.commit()

    record_audit_event(
        sharer_user.id,
        "Document sharing",
        {
            "document_id": document.id,
            "recipient_email": clean_email,
            "tier": permission_tier
        },
        client_ip
    )
    return share


def revoke_document_share(share_id: int, requesting_user: User, client_ip: str = "N/A") -> bool:
    """
    Revoke a previously granted document access permission.
    """
    share = db.session.get(DocumentShare, share_id)
    if not share:
        abort(404)

    doc = share.document
    if doc.user_id != requesting_user.id and not requesting_user.is_admin:
        abort(403)

    recipient = share.shared_with_email
    db.session.delete(share)
    db.session.commit()

    record_audit_event(
        requesting_user.id,
        "Permission revoked",
        {"document_id": doc.id, "revoked_from": recipient},
        client_ip
    )
    return True


def get_user_dashboard_metrics(user_id: int) -> dict:
    """
    Calculate and return genuine database-driven dashboard metrics for a user.
    """
    user_docs = Document.query.filter_by(user_id=user_id).all()
    total_docs = len(user_docs)

    # Count documents shared by user
    shared_docs = DocumentShare.query.filter_by(shared_by_user_id=user_id).count()

    # Calculate real storage
    storage_bytes = sum(d.file_size for d in user_docs)
    if storage_bytes < 1024:
        storage_str = f"{storage_bytes} B"
    elif storage_bytes < 1024 * 1024:
        storage_str = f"{storage_bytes / 1024:.1f} KB"
    elif storage_bytes < 1024 * 1024 * 1024:
        storage_str = f"{storage_bytes / (1024 * 1024):.2f} MB"
    else:
        storage_str = f"{storage_bytes / (1024 * 1024 * 1024):.2f} GB"

    # Percentage based on 10 GB quota
    quota_bytes = 10 * 1024 * 1024 * 1024
    storage_percent = min(100.0, max(0.0, round((storage_bytes / quota_bytes) * 100, 2)))

    # Real recent activity count and list
    recent_activity_count = get_audit_count(user_id=user_id)
    recent_activities = get_recent_audit_events(limit=5, user_id=user_id)
    recent_documents = Document.query.filter_by(user_id=user_id).order_by(Document.created_at.desc()).limit(5).all()

    return {
        "total_docs": total_docs,
        "shared_docs": shared_docs,
        "storage_bytes": storage_bytes,
        "storage_used_str": storage_str,
        "storage_percent": storage_percent,
        "recent_activity_count": recent_activity_count,
        "recent_documents": recent_documents,
        "recent_activities": recent_activities
    }
