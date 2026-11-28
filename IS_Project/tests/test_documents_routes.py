"""
Member 2 - HTTP-level tests: the pages render and the SERVER enforces permissions
(not the UI). Uses the real Flask routes with logged-in sessions.
"""
import io
import pytest
from extensions import db
from authentication.models import User, Document
import services.document_service as ds
from services.document_service import share_document_with_user, save_uploaded_document
from werkzeug.datastructures import FileStorage

PW = "Passw0rd!x"


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setattr(ds, "get_vault_storage_dir", lambda: str(vault))


def mk(username, email, role="User"):
    u = User(full_name=username.title(), username=username, email=email, role=role, is_active=True)
    u.set_password(PW)
    db.session.add(u)
    db.session.commit()
    return u


def login(client, email):
    client.post("/login", data={"email": email, "password": PW}, follow_redirects=True)


@pytest.fixture
def world(app):
    # CSRF protection is covered by its own test below and by Member 1's suite;
    # switch it off here so these tests can focus on authorization.
    app.config["WTF_CSRF_ENABLED"] = False
    owner = mk("owner", "owner@vault.io")
    viewer = mk("viewer", "viewer@vault.io")
    editor = mk("editor", "editor@vault.io")
    stranger = mk("stranger", "stranger@vault.io")
    admin = mk("boss", "boss@vault.io", role="Admin")
    f = FileStorage(stream=io.BytesIO(b"hello secret world"), filename="note.txt")
    doc = save_uploaded_document(f, "My Note", owner, "127.0.0.1")
    share_document_with_user(doc.id, owner, "viewer@vault.io", "Viewer")
    share_document_with_user(doc.id, owner, "editor@vault.io", "Editor")
    return {"doc": doc, "owner": owner}


def client_for(app, email):
    c = app.test_client()
    login(c, email)
    return c


def test_owner_sees_details_page(app, world):
    c = client_for(app, "owner@vault.io")
    r = c.get(f"/documents/{world['doc'].id}")
    assert r.status_code == 200
    assert b"My Note" in r.data and b"Your access: Owner" in r.data
    assert b"viewer@vault.io" in r.data          # owner sees who has access


def test_my_documents_page_renders_with_shares(app, world):
    c = client_for(app, "viewer@vault.io")
    assert c.get("/documents").status_code == 200   # used to crash on shared rows
    c2 = client_for(app, "owner@vault.io")
    assert c2.get("/documents").status_code == 200
    assert c2.get("/documents/permissions").status_code == 200


def test_shared_documents_page(app, world):
    c = client_for(app, "viewer@vault.io")
    r = c.get("/documents/shared")
    assert r.status_code == 200 and b"My Note" in r.data and b"Viewer" in r.data


def test_stranger_gets_403_on_details_view_download_verify(app, world):
    c = client_for(app, "stranger@vault.io")
    i = world["doc"].id
    assert c.get(f"/documents/{i}").status_code == 403
    assert c.get(f"/documents/{i}/view").status_code == 403
    assert c.get(f"/documents/{i}/download").status_code == 403
    assert c.post(f"/documents/{i}/verify").status_code == 403


def test_admin_cannot_open_other_users_document(app, world):
    c = client_for(app, "boss@vault.io")
    assert c.get(f"/documents/{world['doc'].id}").status_code == 403
    assert c.get(f"/documents/{world['doc'].id}/download").status_code == 403


def test_logged_out_user_is_redirected(app, world):
    c = app.test_client()
    r = c.get(f"/documents/{world['doc'].id}")
    assert r.status_code in (302, 401)


def test_viewer_download_and_inline_view(app, world):
    c = client_for(app, "viewer@vault.io")
    r = c.get(f"/documents/{world['doc'].id}/download")
    assert r.status_code == 200 and r.data == b"hello secret world"
    v = c.get(f"/documents/{world['doc'].id}/view")
    assert v.status_code == 200 and v.data == b"hello secret world"
    assert "sandbox" in v.headers["Content-Security-Policy"]
    assert "no-store" in v.headers["Cache-Control"]


def test_viewer_cannot_delete_or_replace_via_http(app, world):
    c = client_for(app, "viewer@vault.io")
    i = world["doc"].id
    assert c.post(f"/documents/{i}/delete").status_code == 403
    r = c.post(f"/documents/{i}/replace",
               data={"document_file": (io.BytesIO(b"evil"), "evil.txt")},
               content_type="multipart/form-data")
    assert r.status_code == 403
    assert db.session.get(Document, i) is not None


def test_editor_can_replace_via_http(app, world):
    c = client_for(app, "editor@vault.io")
    i = world["doc"].id
    r = c.post(f"/documents/{i}/replace",
               data={"document_file": (io.BytesIO(b"edited by editor"), "note.txt")},
               content_type="multipart/form-data", follow_redirects=True)
    assert r.status_code == 200
    owner = client_for(app, "owner@vault.io")
    assert owner.get(f"/documents/{i}/download").data == b"edited by editor"


def test_verify_button_reports_tampering(app, world, tmp_path):
    import os
    vault = ds.get_vault_storage_dir()
    path = os.path.join(vault, f"{world['doc'].doc_uid}.enc")
    raw = bytearray(open(path, "rb").read())
    raw[-2] ^= 0x55
    open(path, "wb").write(bytes(raw))
    c = client_for(app, "owner@vault.io")
    r = c.post(f"/documents/{world['doc'].id}/verify", follow_redirects=True)
    assert b"INTEGRITY FAILURE" in r.data
    d = c.get(f"/documents/{world['doc'].id}/download", follow_redirects=True)   # no 500
    assert d.status_code == 200 and b"tampered" in d.data


def test_unknown_document_id_is_404(app, world):
    c = client_for(app, "owner@vault.io")
    assert c.get("/documents/99999").status_code == 404


def test_csrf_token_required_on_new_post_routes(app, world):
    """POST routes added by Member 2 are CSRF-protected."""
    from tests.conftest import extract_csrf_token
    app.config["WTF_CSRF_ENABLED"] = True
    c = app.test_client()
    page = c.get("/login")
    token = extract_csrf_token(page.get_data(as_text=True))
    c.post("/login", data={"email": "owner@vault.io", "password": PW, "csrf_token": token})
    i = world["doc"].id
    assert c.post(f"/documents/{i}/verify").status_code == 400
    assert c.post(f"/documents/{i}/replace").status_code == 400


def test_share_form_with_expiry_creates_time_limited_share(app, world):
    """The share form's expiry option is parsed and stored (access is time-limited)."""
    from authentication.models import DocumentShare
    c = client_for(app, "owner@vault.io")
    r = c.post("/documents/share", data={
        "document_id": world["doc"].id, "recipient_email": "stranger@vault.io",
        "permission_tier": "Viewer", "expires_in_hours": "24"}, follow_redirects=True)
    assert r.status_code == 200
    share = DocumentShare.query.filter_by(shared_with_email="stranger@vault.io").first()
    assert share is not None and share.expires_at is not None
    s = client_for(app, "stranger@vault.io")
    assert s.get(f"/documents/{world['doc'].id}/download").status_code == 200   # active now
    assert b"expires" in c.get("/documents/permissions").data
