"""
Member 2 - Document pages and actions (Details, Shared With Me, View, Verify, Replace).

Every route is @login_required and every document operation goes through
services.document_service.authorize(), so the server (not the UI) decides.
"""
import io
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file
from flask_login import current_user, login_required

from services.document_service import (
    get_document_for_user, get_shared_with_user, retrieve_document_bytes,
    verify_document_integrity, replace_document_file, get_access_level,
    ACTION_MATRIX,
)

docs_bp = Blueprint('docs', __name__, url_prefix='/documents')

# Only these types are shown inline in the browser; everything else downloads.
INLINE_MIME_TYPES = {'application/pdf', 'text/plain', 'image/png', 'image/jpeg'}


@docs_bp.route('/shared')
@login_required
def shared_documents():
    """Shared Documents page: documents other people shared with the logged-in user."""
    shares = get_shared_with_user(current_user)
    return render_template('shared_documents.html', user=current_user, shares=shares)


@docs_bp.route('/<int:document_id>')
@login_required
def document_detail(document_id: int):
    """Document Details page: metadata, integrity status and what this user may do."""
    document, level = get_document_for_user(document_id, current_user, 'view', request.remote_addr)
    can = {action: (level in allowed) for action, allowed in ACTION_MATRIX.items()}
    shares = list(document.shares) if level == 'Owner' else []
    return render_template('document_detail.html', user=current_user, doc=document,
                           level=level, can=can, shares=shares)


@docs_bp.route('/<int:document_id>/view')
@login_required
def view_document(document_id: int):
    """Open a document in the browser (safe types only), otherwise download it."""
    try:
        data, filename, mime = retrieve_document_bytes(
            document_id, current_user, request.remote_addr, purpose='view')
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for('docs.document_detail', document_id=document_id))

    inline = mime in INLINE_MIME_TYPES
    response = send_file(io.BytesIO(data), mimetype=mime if inline else 'application/octet-stream',
                         as_attachment=not inline, download_name=filename)
    # A decrypted document must never be cached or run scripts in our origin
    response.headers['Content-Security-Policy'] = "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'"
    response.headers['Cache-Control'] = 'no-store'
    return response


@docs_bp.route('/<int:document_id>/verify', methods=['POST'])
@login_required
def verify_document(document_id: int):
    """Run the on-demand integrity check (AES-GCM tag + SHA-256)."""
    result = verify_document_integrity(document_id, current_user, request.remote_addr)
    flash(result['message'] if result['ok'] else f"INTEGRITY FAILURE: {result['message']}",
          "success" if result['ok'] else "error")
    return redirect(url_for('docs.document_detail', document_id=document_id))


@docs_bp.route('/<int:document_id>/replace', methods=['POST'])
@login_required
def replace_document(document_id: int):
    """Editor/Owner uploads a new version of the file."""
    try:
        doc = replace_document_file(document_id, current_user,
                                    request.files.get('document_file'), request.remote_addr)
        flash(f"New version saved (v{doc.version}), re-encrypted with a fresh key.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for('docs.document_detail', document_id=document_id))
