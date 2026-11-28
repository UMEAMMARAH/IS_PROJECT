"""
SecureVault Document Management Service  (Member 2)

Handles upload, envelope encryption (AES-256-GCM), storage, decryption,
integrity verification, sharing, revocation and deletion.

ACCESS-CONTROL RULES (enforced here, on the server, for every operation):

    Role                 view/download/verify   edit (replace file)   delete   share/revoke
    Owner                yes                    yes                   yes      yes
    Editor (shared)      yes                    yes                   no       no
    Viewer (shared)      yes                    no                    no       no
    Admin (not shared)   NO                     NO                    NO       NO
    Any other user       NO                     NO                    NO       NO

An Admin role governs user ACCOUNTS only. It never grants access to the
contents of someone else's documents (least privilege).
"""

import os
import uuid
import mimetypes
from datetime import datetime, timezone

from flask import current_app, abort
from werkzeug.utils import secure_filename

from extensions import db
from authentication.models import User, Document, DocumentShare
from services.crypto_service import (
    encrypt_document, decrypt_document, compute_sha256, verify_sha256, IntegrityError,
)
from services.audit_service import record_audit_event, get_recent_audit_events, get_audit_count

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'xlsx', 'xls', 'txt', 'csv', 'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 Megabytes
VALID_TIERS = ('Viewer', 'Editor')

# ---- permission matrix -----------------------------------------------------
OWNER, EDITOR, VIEWER = 'Owner', 'Editor', 'Viewer'
ACTION_MATRIX = {
    'view':     {OWNER, EDITOR, VIEWER},
    'download': {OWNER, EDITOR, VIEWER},
    'verify':   {OWNER, EDITOR, VIEWER},
    'edit':     {OWNER, EDITOR},
    'delete':   {OWNER},
    'share':    {OWNER},
}
_LEVEL_RANK = {VIEWER: 1, EDITOR: 2, OWNER: 3}


class DocumentIntegrityError(ValueError):
    """The stored document failed authentication or its SHA-256 check."""


def _now():
    return datetime.now(timezone.utc)


def _as_utc(dt):
    """SQLite returns naive datetimes; treat them as UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---- storage helpers -------------------------------------------------------

def get_vault_storage_dir() -> str:
    """Absolute path to the encrypted-file folder (separate from the database file)."""
    storage_dir = os.path.join(current_app.root_path, 'database', 'vault_storage')
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def _storage_path(document: Document) -> str:
    # basename() guards against a tampered DB row pointing outside the vault folder
    return os.path.join(get_vault_storage_dir(), os.path.basename(document.stored_filename))


def _write_atomic(path: str, data: bytes) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def is_allowed_file(filename: str) -> bool:
    """Validate file extension against safe whitelist."""
    if '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _read_and_validate_upload(file_storage):
    """Common checks for upload and replace. Returns (clean_name, bytes, mime)."""
    if not file_storage or not file_storage.filename:
        raise ValueError("No file selected for upload.")
    original_name = secure_filename(file_storage.filename)
    if not original_name or not is_allowed_file(original_name):
        raise ValueError(f"File type not permitted. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    file_bytes = file_storage.read(MAX_FILE_SIZE + 1)
    if len(file_bytes) == 0:
        raise ValueError("Uploaded file is empty.")
    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError("File exceeds maximum allowed size of 50 MB.")
    # The browser-supplied MIME type is untrusted: derive it from the extension
    mime = mimetypes.guess_type(original_name)[0] or 'application/octet-stream'
    return original_name, file_bytes, mime


# ---- authorization ---------------------------------------------------------

def get_access_level(user: User, document: Document):
    """
    Returns 'Owner', 'Editor', 'Viewer' or None.
    Expired shares are ignored. Admin status is deliberately NOT considered.
    """
    if user is None or document is None:
        return None
    if document.user_id == user.id:
        return OWNER

    now = _now()
    best = None
    email = (user.email or '').lower()
    for share in document.shares:
        matches = (share.shared_with_user_id == user.id) or (share.shared_with_email.lower() == email)
        if not matches:
            continue
        exp = _as_utc(share.expires_at)
        if exp is not None and exp <= now:
            continue
        tier = share.permission_tier if share.permission_tier in _LEVEL_RANK else None
        if tier and (best is None or _LEVEL_RANK[tier] > _LEVEL_RANK[best]):
            best = tier
    return best


def authorize(user: User, document: Document, action: str, client_ip: str = "N/A") -> str:
    """
    Central authorization gate used by EVERY document operation.
    Returns the user's access level, or aborts with 403 and writes an audit record.
    """
    if action not in ACTION_MATRIX:
        raise ValueError(f"Unknown action '{action}'")
    level = get_access_level(user, document)
    if level is None or level not in ACTION_MATRIX[action]:
        record_audit_event(
            user.id,
            "Unauthorized access attempt",
            {"target_document_id": document.id, "attempted_action": action,
             "access_level": level or "None"},
            client_ip,
        )
        abort(403)
    return level


def get_document_for_user(document_id: int, user: User, action: str = 'view', client_ip: str = "N/A"):
    """Load a document by id and authorize the action. Returns (document, access_level)."""
    document = db.session.get(Document, document_id)
    if not document:
        abort(404)
    level = authorize(user, document, action, client_ip)
    return document, level


def get_shared_with_user(user: User):
    """Active (non-expired) shares that give this user access to someone else's documents."""
    now = _now()
    email = user.email.lower()
    shares = DocumentShare.query.filter(
        (DocumentShare.shared_with_user_id == user.id) |
        (DocumentShare.shared_with_email == email)
    ).order_by(DocumentShare.created_at.desc()).all()
    active = []
    for s in shares:
        exp = _as_utc(s.expires_at)
        if exp is not None and exp <= now:
            continue
        if s.document.user_id == user.id:
            continue
        active.append(s)
    return active


# ---- core operations -------------------------------------------------------

def _decrypt_and_check(document: Document, client_ip: str, actor_id: int) -> bytes:
    """
    Read the encrypted file, decrypt+authenticate it, then confirm the SHA-256.
    On any failure: mark the document FAILED, write an audit record, raise
    DocumentIntegrityError (never a raw crypto exception / HTTP 500).
    """
    path = _storage_path(document)
    if not os.path.exists(path):
        record_audit_event(actor_id, "Security Violation: Integrity Failure",
                           {"document_id": document.id, "alert": "Encrypted file missing from storage"}, client_ip)
        document.integrity_status = 'FAILED'
        db.session.commit()
        raise DocumentIntegrityError("The encrypted file is missing from storage.")

    with open(path, 'rb') as f:
        blob = f.read()

    try:
        plaintext = decrypt_document(blob, document.wrapped_key, document.doc_uid)
        if not verify_sha256(plaintext, document.file_hash):
            raise IntegrityError("SHA-256 digest does not match the stored value.")
    except IntegrityError as exc:
        document.integrity_status = 'FAILED'
        db.session.commit()
        record_audit_event(actor_id, "Security Violation: Integrity Failure",
                           {"document_id": document.id, "alert": str(exc)}, client_ip)
        raise DocumentIntegrityError(
            "Document integrity verification failed! The file may have been tampered with.")
    return plaintext


def save_uploaded_document(file_storage, title: str, owner_user: User, client_ip: str = "N/A") -> Document:
    """Validate, hash, envelope-encrypt and store an uploaded document."""
    original_name, file_bytes, mime = _read_and_validate_upload(file_storage)

    doc_uid = uuid.uuid4().hex
    file_hash = compute_sha256(file_bytes)
    blob, wrapped_key = encrypt_document(file_bytes, doc_uid)

    stored_name = f"{doc_uid}.enc"          # random name: leaks nothing about the content
    stored_path = os.path.join(get_vault_storage_dir(), stored_name)
    _write_atomic(stored_path, blob)

    doc_title = title.strip() if (title and title.strip()) else original_name
    document = Document(
        user_id=owner_user.id,
        title=doc_title[:255],
        original_filename=original_name,
        doc_uid=doc_uid,
        stored_filename=stored_name,
        wrapped_key=wrapped_key,
        file_size=len(file_bytes),
        mime_type=mime,
        file_hash=file_hash,
        is_encrypted=True,
        integrity_status='Verified',
        last_verified_at=_now(),
        version=1,
    )
    try:
        db.session.add(document)
        db.session.commit()
    except Exception:
        db.session.rollback()
        if os.path.exists(stored_path):
            os.remove(stored_path)
        raise

    record_audit_event(
        owner_user.id, "Document upload",
        {"document_id": document.id, "title": document.title, "size_bytes": document.file_size,
         "sha256": document.file_hash, "cipher": "AES-256-GCM"},
        client_ip,
    )
    return document


def retrieve_document_bytes(document_id: int, requesting_user: User, client_ip: str = "N/A", purpose: str = 'download'):
    """
    Authorize, decrypt and integrity-check a document.
    purpose is 'download' or 'view' (both need at least Viewer access).
    Returns (plaintext_bytes, original_filename, mime_type).
    """
    action = 'view' if purpose == 'view' else 'download'
    document, _level = get_document_for_user(document_id, requesting_user, action, client_ip)
    plaintext = _decrypt_and_check(document, client_ip, requesting_user.id)
    record_audit_event(
        requesting_user.id,
        "Document view" if action == 'view' else "Document download",
        {"document_id": document.id, "title": document.title}, client_ip,
    )
    return plaintext, document.original_filename, document.mime_type


def verify_document_integrity(document_id: int, requesting_user: User, client_ip: str = "N/A") -> dict:
    """
    On-demand integrity check (GCM authentication tag + SHA-256).
    Returns {'ok': bool, 'status': str, 'checked_at': datetime, 'message': str}.
    """
    document, _level = get_document_for_user(document_id, requesting_user, 'verify', client_ip)
    try:
        _decrypt_and_check(document, client_ip, requesting_user.id)
    except DocumentIntegrityError as exc:
        return {"ok": False, "status": "FAILED", "checked_at": _now(), "message": str(exc)}

    document.integrity_status = 'Verified'
    document.last_verified_at = _now()
    db.session.commit()
    record_audit_event(requesting_user.id, "Integrity check passed",
                       {"document_id": document.id, "sha256": document.file_hash}, client_ip)
    return {"ok": True, "status": "Verified", "checked_at": document.last_verified_at,
            "message": "AES-GCM authentication tag and SHA-256 digest both match."}


def replace_document_file(document_id: int, requesting_user: User, file_storage, client_ip: str = "N/A") -> Document:
    """Editor/Owner uploads a new version. A fresh key and nonce are generated."""
    document, level = get_document_for_user(document_id, requesting_user, 'edit', client_ip)
    original_name, file_bytes, mime = _read_and_validate_upload(file_storage)

    blob, wrapped_key = encrypt_document(file_bytes, document.doc_uid)
    document.wrapped_key = wrapped_key
    document.original_filename = original_name
    document.mime_type = mime
    document.file_size = len(file_bytes)
    document.file_hash = compute_sha256(file_bytes)
    document.version = (document.version or 1) + 1
    document.integrity_status = 'Verified'
    document.last_verified_at = _now()
    try:
        db.session.flush()
        _write_atomic(_storage_path(document), blob)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    record_audit_event(
        requesting_user.id, "Document modified",
        {"document_id": document.id, "new_version": document.version, "access_level": level,
         "sha256": document.file_hash}, client_ip,
    )
    return document


def delete_user_document(document_id: int, requesting_user: User, client_ip: str = "N/A") -> bool:
    """
    Owner-only deletion. Removes the encrypted file AND the wrapped key (the
    database row), so any leftover copy of the file can never be decrypted
    ("crypto-shredding").
    """
    document, _level = get_document_for_user(document_id, requesting_user, 'delete', client_ip)

    path = _storage_path(document)
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass

    doc_title = document.title
    db.session.delete(document)
    db.session.commit()
    record_audit_event(requesting_user.id, "Document deletion",
                       {"document_id": document_id, "title": doc_title}, client_ip)
    return True


def share_document_with_user(document_id: int, sharer_user: User, recipient_email: str,
                             permission_tier: str, client_ip: str = "N/A", expires_at=None) -> DocumentShare:
    """Owner grants Viewer or Editor access, optionally with an expiry time."""
    document, _level = get_document_for_user(document_id, sharer_user, 'share', client_ip)

    clean_email = (recipient_email or '').strip().lower()
    if not clean_email or '@' not in clean_email:
        raise ValueError("Please enter a valid recipient email address.")
    if clean_email == sharer_user.email.lower():
        raise ValueError("You cannot share a document with yourself.")
    if permission_tier not in VALID_TIERS:
        raise ValueError("Permission must be Viewer or Editor.")
    if expires_at is not None and _as_utc(expires_at) <= _now():
        raise ValueError("The expiry time must be in the future.")

    recipient_user = User.query.filter(User.email.ilike(clean_email)).first()
    recipient_id = recipient_user.id if recipient_user else None

    share = DocumentShare.query.filter_by(document_id=document.id, shared_with_email=clean_email).first()
    if share:
        share.permission_tier = permission_tier
        share.shared_with_user_id = recipient_id
        share.expires_at = expires_at
    else:
        share = DocumentShare(
            document_id=document.id, shared_by_user_id=sharer_user.id,
            shared_with_email=clean_email, shared_with_user_id=recipient_id,
            permission_tier=permission_tier, expires_at=expires_at,
        )
        db.session.add(share)
    db.session.commit()

    record_audit_event(
        sharer_user.id, "Document sharing",
        {"document_id": document.id, "recipient_email": clean_email, "tier": permission_tier,
         "expires_at": expires_at.isoformat() if expires_at else "never"},
        client_ip,
    )
    return share


def revoke_document_share(share_id: int, requesting_user: User, client_ip: str = "N/A") -> bool:
    """Owner revokes a share. Takes effect immediately on the next request."""
    share = db.session.get(DocumentShare, share_id)
    if not share:
        abort(404)
    document, _level = get_document_for_user(share.document_id, requesting_user, 'share', client_ip)

    recipient = share.shared_with_email
    db.session.delete(share)
    db.session.commit()
    record_audit_event(requesting_user.id, "Permission revoked",
                       {"document_id": document.id, "revoked_from": recipient}, client_ip)
    return True


# ---- dashboard -------------------------------------------------------------

def get_user_dashboard_metrics(user_id: int) -> dict:
    """Calculate genuine database-driven dashboard metrics for a user."""
    user_docs = Document.query.filter_by(user_id=user_id).all()
    total_docs = len(user_docs)
    shared_docs = DocumentShare.query.filter_by(shared_by_user_id=user_id).count()

    storage_bytes = sum(d.file_size for d in user_docs)
    if storage_bytes < 1024:
        storage_str = f"{storage_bytes} B"
    elif storage_bytes < 1024 * 1024:
        storage_str = f"{storage_bytes / 1024:.1f} KB"
    elif storage_bytes < 1024 * 1024 * 1024:
        storage_str = f"{storage_bytes / (1024 * 1024):.2f} MB"
    else:
        storage_str = f"{storage_bytes / (1024 * 1024 * 1024):.2f} GB"

    quota_bytes = 10 * 1024 * 1024 * 1024
    storage_percent = min(100.0, max(0.0, round((storage_bytes / quota_bytes) * 100, 2)))

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
        "recent_activities": recent_activities,
    }