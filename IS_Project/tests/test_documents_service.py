"""
Member 2 - Document management, authorization and sharing test cases.

Every row of the permission matrix in services/document_service.py is proven
here, together with integrity checking, revocation and share expiry.
"""
import io
import os
from datetime import datetime, timedelta, timezone

import pytest
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import Forbidden, NotFound

from extensions import db
from authentication.models import User, Document
import services.document_service as ds
from services.document_service import (
    save_uploaded_document, retrieve_document_bytes, replace_document_file,
    delete_user_document, share_document_with_user, revoke_document_share,
    verify_document_integrity, get_access_level, get_shared_with_user,
    DocumentIntegrityError,
)

SECRET = b"Q4 Budget - TOP SECRET - figures: 4,200,000"


def make_user(username, email, role="User"):
    u = User(full_name=username.title(), username=username, email=email, role=role, is_active=True)
    u.set_password("Passw0rd!x")
    db.session.add(u)
    db.session.commit()
    return u


def upload(user, content=SECRET, name="budget.txt", title="Budget"):
    f = FileStorage(stream=io.BytesIO(content), filename=name, content_type="text/plain")
    return save_uploaded_document(f, title, user, "127.0.0.1")


def new_file(content, name="v2.txt"):
    return FileStorage(stream=io.BytesIO(content), filename=name, content_type="text/plain")


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    """Keep test files out of the real vault folder."""
    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setattr(ds, "get_vault_storage_dir", lambda: str(vault))
    return vault


@pytest.fixture
def people(app):
    return {
        "owner": make_user("owner", "owner@vault.io"),
        "editor": make_user("editor", "editor@vault.io"),
        "viewer": make_user("viewer", "viewer@vault.io"),
        "stranger": make_user("stranger", "stranger@vault.io"),
        "admin": make_user("admin2", "admin2@vault.io", role="Admin"),
    }


@pytest.fixture
def shared_doc(people):
    doc = upload(people["owner"])
    share_document_with_user(doc.id, people["owner"], "editor@vault.io", "Editor")
    share_document_with_user(doc.id, people["owner"], "viewer@vault.io", "Viewer")
    return doc


# ---------------------------------------------------------------- storage ---

def test_upload_stores_only_ciphertext_on_disk(people, isolated_storage):
    doc = upload(people["owner"])
    files = list(isolated_storage.iterdir())
    assert len(files) == 1
    raw = files[0].read_bytes()
    assert SECRET not in raw and b"TOP SECRET" not in raw
    assert files[0].name == f"{doc.doc_uid}.enc"
    assert "budget" not in files[0].name          # original name not leaked on disk


def test_database_holds_no_plaintext_and_no_path(people):
    doc = upload(people["owner"])
    assert not hasattr(doc, "file_path")
    assert isinstance(doc.wrapped_key, bytes) and SECRET not in doc.wrapped_key
    assert doc.integrity_status == "Verified"


def test_owner_roundtrip(people):
    doc = upload(people["owner"])
    data, name, mime = retrieve_document_bytes(doc.id, people["owner"])
    assert data == SECRET and name == "budget.txt" and mime == "text/plain"


def test_disallowed_extension_and_empty_file_rejected(people):
    with pytest.raises(ValueError):
        upload(people["owner"], name="evil.exe")
    with pytest.raises(ValueError):
        upload(people["owner"], content=b"", name="empty.txt")


# ------------------------------------------------------ permission matrix ---

def test_access_levels(people, shared_doc):
    assert get_access_level(people["owner"], shared_doc) == "Owner"
    assert get_access_level(people["editor"], shared_doc) == "Editor"
    assert get_access_level(people["viewer"], shared_doc) == "Viewer"
    assert get_access_level(people["stranger"], shared_doc) is None
    assert get_access_level(people["admin"], shared_doc) is None


def test_stranger_cannot_access(people, shared_doc):
    """Scenario 1: unauthorized document access."""
    with pytest.raises(Forbidden):
        retrieve_document_bytes(shared_doc.id, people["stranger"])


def test_admin_has_no_automatic_access(people, shared_doc):
    """Scenario 5 / spec Q5.4: Admin role does NOT open confidential documents."""
    admin = people["admin"]
    with pytest.raises(Forbidden):
        retrieve_document_bytes(shared_doc.id, admin)
    with pytest.raises(Forbidden):
        delete_user_document(shared_doc.id, admin)
    with pytest.raises(Forbidden):
        share_document_with_user(shared_doc.id, admin, "x@y.io", "Viewer")
    with pytest.raises(Forbidden):
        replace_document_file(shared_doc.id, admin, new_file(b"hack"))


def test_viewer_can_read_but_not_edit_delete_or_share(people, shared_doc):
    v = people["viewer"]
    assert retrieve_document_bytes(shared_doc.id, v)[0] == SECRET
    with pytest.raises(Forbidden):
        replace_document_file(shared_doc.id, v, new_file(b"changed"))
    with pytest.raises(Forbidden):
        delete_user_document(shared_doc.id, v)
    with pytest.raises(Forbidden):
        share_document_with_user(shared_doc.id, v, "x@y.io", "Viewer")


def test_editor_can_replace_but_not_delete_or_share(people, shared_doc):
    e = people["editor"]
    updated = replace_document_file(shared_doc.id, e, new_file(b"edited content"))
    assert updated.version == 2
    assert retrieve_document_bytes(shared_doc.id, people["owner"])[0] == b"edited content"
    with pytest.raises(Forbidden):
        delete_user_document(shared_doc.id, e)
    with pytest.raises(Forbidden):
        share_document_with_user(shared_doc.id, e, "x@y.io", "Viewer")


def test_only_owner_can_delete_and_delete_removes_file_and_key(people, shared_doc, isolated_storage):
    delete_user_document(shared_doc.id, people["owner"])
    assert list(isolated_storage.iterdir()) == []
    assert db.session.get(Document, shared_doc.id) is None


def test_id_manipulation_unknown_document_is_404(people):
    """Scenario 2: guessing ids never returns data."""
    with pytest.raises(NotFound):
        retrieve_document_bytes(99999, people["owner"])


def test_invalid_permission_tier_rejected(people):
    doc = upload(people["owner"])
    with pytest.raises(ValueError):
        share_document_with_user(doc.id, people["owner"], "viewer@vault.io", "Auditor")
    with pytest.raises(ValueError):
        share_document_with_user(doc.id, people["owner"], "owner@vault.io", "Viewer")


# ----------------------------------------------------- revoke and expiry ---

def test_revocation_takes_effect_immediately(people):
    """Scenario 6: access works, then fails right after revocation."""
    doc = upload(people["owner"])
    share = share_document_with_user(doc.id, people["owner"], "viewer@vault.io", "Viewer")
    assert retrieve_document_bytes(doc.id, people["viewer"])[0] == SECRET
    revoke_document_share(share.id, people["owner"])
    with pytest.raises(Forbidden):
        retrieve_document_bytes(doc.id, people["viewer"])


def test_non_owner_cannot_revoke(people, shared_doc):
    share = shared_doc.shares[0]
    with pytest.raises(Forbidden):
        revoke_document_share(share.id, people["viewer"])


def test_expired_share_is_rejected(people):
    doc = upload(people["owner"])
    share = share_document_with_user(
        doc.id, people["owner"], "viewer@vault.io", "Viewer",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    assert retrieve_document_bytes(doc.id, people["viewer"])[0] == SECRET
    share.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)   # time passes
    db.session.commit()
    with pytest.raises(Forbidden):
        retrieve_document_bytes(doc.id, people["viewer"])
    assert get_shared_with_user(people["viewer"]) == []


def test_expiry_in_the_past_rejected(people):
    doc = upload(people["owner"])
    with pytest.raises(ValueError):
        share_document_with_user(doc.id, people["owner"], "viewer@vault.io", "Viewer",
                                 expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))


# --------------------------------------------------------------- integrity ---

def test_modified_file_on_disk_is_detected(people, isolated_storage):
    """Scenario 4: file altered outside the application."""
    doc = upload(people["owner"])
    path = isolated_storage / f"{doc.doc_uid}.enc"
    raw = bytearray(path.read_bytes())
    raw[-3] ^= 0xFF
    path.write_bytes(bytes(raw))

    with pytest.raises(DocumentIntegrityError):
        retrieve_document_bytes(doc.id, people["owner"])
    assert db.session.get(Document, doc.id).integrity_status == "FAILED"

    result = verify_document_integrity(doc.id, people["owner"])
    assert result["ok"] is False


def test_swapped_files_between_documents_detected(people, isolated_storage):
    a = upload(people["owner"], content=b"document A", name="a.txt")
    b = upload(people["owner"], content=b"document B", name="b.txt")
    pa = isolated_storage / f"{a.doc_uid}.enc"
    pb = isolated_storage / f"{b.doc_uid}.enc"
    pa_bytes, pb_bytes = pa.read_bytes(), pb.read_bytes()
    pa.write_bytes(pb_bytes)
    pb.write_bytes(pa_bytes)
    with pytest.raises(DocumentIntegrityError):
        retrieve_document_bytes(a.id, people["owner"])


def test_deleted_file_is_reported_not_crashed(people, isolated_storage):
    doc = upload(people["owner"])
    (isolated_storage / f"{doc.doc_uid}.enc").unlink()
    with pytest.raises(DocumentIntegrityError):
        retrieve_document_bytes(doc.id, people["owner"])


def test_verify_integrity_passes_on_untouched_file(people):
    doc = upload(people["owner"])
    result = verify_document_integrity(doc.id, people["owner"])
    assert result["ok"] is True and result["status"] == "Verified"


def test_stranger_cannot_run_integrity_check(people):
    doc = upload(people["owner"])
    with pytest.raises(Forbidden):
        verify_document_integrity(doc.id, people["stranger"])


# ------------------------------------------------------------------- audit ---

def test_security_events_are_audited_without_content(people, shared_doc):
    from authentication.models import AuditLog
    with pytest.raises(Forbidden):
        retrieve_document_bytes(shared_doc.id, people["stranger"])
    actions = [a.action for a in AuditLog.query.all()]
    assert "Document upload" in actions
    assert "Unauthorized access attempt" in actions
    assert "Document sharing" in actions
    for entry in AuditLog.query.all():
        assert "TOP SECRET" not in (entry.details or "")