import os
import click
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import current_user, login_required
from flask_wtf.csrf import CSRFError

from config import Config
from extensions import db, login_manager, csrf, limiter
from authentication.models import User
from authentication.routes import auth_bp
from admin.routes import admin_bp
from services.audit_service import record_audit_event


def create_app(config_class=Config):
    """
    SecureVault Application Factory.
    Configures security extensions, blueprints, and database tables.
    """
    app = Flask(
        __name__,
        template_folder='frontend',
        static_folder='static'
    )
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # -------------------------------------------------------------
    # Main Blueprint: Core dashboard and real document management
    # -------------------------------------------------------------
    import io
    from flask import Blueprint, send_file
    from authentication.models import Document, DocumentShare
    from services.document_service import (
        get_user_dashboard_metrics,
        save_uploaded_document,
        retrieve_document_bytes,
        delete_user_document,
        share_document_with_user,
        revoke_document_share
    )
    from services.crypto_service import academic_des_demonstration
    
    main_bp = Blueprint('main', __name__)

    @main_bp.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('main.dashboard'))
        return redirect(url_for('auth.login'))

    @main_bp.route('/dashboard')
    @login_required
    def dashboard():
        """User Dashboard: Displays authentic database-driven metrics and real user documents."""
        metrics = get_user_dashboard_metrics(current_user.id)
        return render_template('dashboard.html', user=current_user, metrics=metrics)

    @main_bp.route('/documents')
    @login_required
    def documents():
        """My Documents view: displays actual stored documents owned or shared."""
        user_docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.created_at.desc()).all()
        shared_with_user = DocumentShare.query.filter(
            (DocumentShare.shared_with_email == current_user.email.lower()) |
            (DocumentShare.shared_with_user_id == current_user.id)
        ).all()
        metrics = get_user_dashboard_metrics(current_user.id)
        return render_template('document.html', user=current_user, documents=user_docs, shared_docs=shared_with_user, metrics=metrics)

    @main_bp.route('/documents/upload', methods=['GET', 'POST'])
    @login_required
    def upload_document():
        """Upload Document: Encrypts file with AES-256-GCM and stores on disk with SHA-256 integrity."""
        if request.method == 'POST':
            file_storage = request.files.get('document_file')
            doc_title = request.form.get('title', '').strip()
            try:
                doc = save_uploaded_document(file_storage, doc_title, current_user, request.remote_addr)
                flash(f"Document '{doc.title}' encrypted with AES-256-GCM and securely stored!", "success")
                return redirect(url_for('main.documents'))
            except Exception as e:
                flash(f"Upload failed: {str(e)}", "error")
                return redirect(url_for('main.upload_document'))

        return render_template('upload.html', user=current_user)

    @main_bp.route('/documents/<int:document_id>/download')
    @login_required
    def download_document(document_id: int):
        """Authenticated Document Download: Decrypts file on the fly and verifies SHA-256 integrity."""
        try:
            file_bytes, filename, mime_type = retrieve_document_bytes(document_id, current_user, request.remote_addr)
            return send_file(
                io.BytesIO(file_bytes),
                as_attachment=True,
                download_name=filename,
                mimetype=mime_type
            )
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for('main.documents'))

    @main_bp.route('/documents/<int:document_id>/delete', methods=['POST'])
    @login_required
    def delete_document_route(document_id: int):
        """Secure Document Deletion: Removes encrypted file from disk and record from database."""
        delete_user_document(document_id, current_user, request.remote_addr)
        flash("Document deleted securely.", "success")
        return redirect(url_for('main.documents'))

    @main_bp.route('/documents/permissions')
    @login_required
    def share_permissions():
        """Sharing & Permissions: Real document selector and active cryptographic access leases."""
        user_docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.created_at.desc()).all()
        active_shares = DocumentShare.query.filter_by(shared_by_user_id=current_user.id).order_by(DocumentShare.created_at.desc()).all()
        return render_template('share&permissions.html', user=current_user, user_docs=user_docs, active_shares=active_shares)

    @main_bp.route('/documents/share', methods=['POST'])
    @login_required
    def share_document_route():
        """Grant access delegation to recipient email."""
        doc_id = request.form.get('document_id', type=int)
        recipient_email = request.form.get('recipient_email', '').strip()
        permission_tier = request.form.get('permission_tier', 'Viewer').strip()

        if not doc_id or not recipient_email:
            flash("Please select a document and enter a valid recipient email.", "error")
            return redirect(url_for('main.share_permissions'))

        try:
            share = share_document_with_user(doc_id, current_user, recipient_email, permission_tier, request.remote_addr)
            flash(f"Document access successfully delegated to {share.shared_with_email} as {share.permission_tier}!", "success")
        except Exception as e:
            flash(f"Sharing failed: {str(e)}", "error")

        return redirect(url_for('main.share_permissions'))

    @main_bp.route('/documents/share/<int:share_id>/revoke', methods=['POST'])
    @login_required
    def revoke_share_route(share_id: int):
        """Revoke a previously granted document permission lease."""
        revoke_document_share(share_id, current_user, request.remote_addr)
        flash("Document access permission successfully revoked.", "info")
        return redirect(url_for('main.share_permissions'))

    @main_bp.route('/academic/des-demo')
    def des_demo():
        """Academic Demonstration of DES (Information Security Course Topic)."""
        demo_result = academic_des_demonstration()
        return {
            "status": "Academic Demonstration Only",
            "course_topic": "Symmetric Encryption & Block Ciphers (DES vs AES)",
            "details": demo_result
        }

    app.register_blueprint(main_bp)

    # -------------------------------------------------------------
    # Context Processors: Inject current_user and helpers into templates
    # -------------------------------------------------------------
    @app.context_processor
    def inject_global_vars():
        return {
            'app_name': 'SecureVault',
            'current_year': 2026
        }

    # -------------------------------------------------------------
    # Security Response Headers: Defense against caching & frame attacks
    # -------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        # Prevent caching of authenticated pages to defeat browser back-button access post-logout
        if current_user.is_authenticated or request.path in ('/dashboard', '/documents', '/profile', '/admin/users'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

    # -------------------------------------------------------------
    # Error Handlers: Uniform error feedback and security defenses
    # -------------------------------------------------------------
    @app.errorhandler(403)
    def forbidden_error(error):
        record_audit_event(
            current_user.id if current_user.is_authenticated else None,
            "Security Violation: HTTP 403 Forbidden",
            {"path": request.path},
            request.remote_addr
        )
        return render_template('403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        record_audit_event(
            current_user.id if current_user.is_authenticated else None,
            "Security Violation: CSRF Token Failure",
            {"description": error.description, "path": request.path},
            request.remote_addr
        )
        flash("Security token validation failed. Please refresh the page and try again.", "error")
        return render_template('403.html', reason="CSRF verification failed"), 400

    @app.errorhandler(429)
    def ratelimit_handler(e):
        record_audit_event(
            None,
            "Security Alert: Rate limit exceeded",
            {"ip": request.remote_addr, "path": request.path},
            request.remote_addr
        )
        return render_template('login.html', form=None, error="Too many requests. Please wait a moment before trying again."), 429

    # -------------------------------------------------------------
    # Database Initialization Hook
    # -------------------------------------------------------------
    with app.app_context():
        # Ensure database directory exists
        db_dir = os.path.join(app.root_path, 'database')
        os.makedirs(db_dir, exist_ok=True)
        # Create all tables automatically on startup
        db.create_all()

    # -------------------------------------------------------------
    # CLI Command: Create Initial Administrator Securely
    # -------------------------------------------------------------
    @app.cli.command("create-admin")
    @click.option('--username', prompt="Admin Username", help="Admin username")
    @click.option('--email', prompt="Admin Email", help="Admin email address")
    @click.option('--fullname', prompt="Admin Full Name", help="Admin full name")
    @click.password_option('--password', prompt="Admin Password", confirmation_prompt=True, help="Admin password")
    def create_admin(username, email, fullname, password):
        """Create the first system administrator account with strict security checks."""
        import re
        # Validate password strength
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[\W_]", password):
            click.echo("Error: Password does not meet security policy (min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special symbol).")
            return

        existing_user = User.query.filter(
            (User.username.ilike(username.strip())) | (User.email.ilike(email.strip()))
        ).first()

        if existing_user:
            click.echo(f"Error: User with username '{username}' or email '{email}' already exists.")
            return

        admin_user = User(
            full_name=fullname.strip(),
            username=username.strip(),
            email=email.strip().lower(),
            role='Admin',
            is_active=True
        )
        admin_user.set_password(password)

        try:
            db.session.add(admin_user)
            db.session.commit()
            record_audit_event(
                admin_user.id,
                "Administrator created via CLI",
                {"username": admin_user.username, "email": admin_user.email},
                "CLI"
            )
            click.echo(f"Administrator '{username}' successfully created!")
        except Exception as e:
            db.session.rollback()
            click.echo(f"Database error during admin creation: {e}")

    @app.cli.command("init-db")
    def init_db():
        """Initialize and create all database tables."""
        db.create_all()
        click.echo("Database initialized successfully.")

    return app


# Application entry point
app = create_app()

if __name__ == '__main__':
    # Default development server host & port
    app.run(host='127.0.0.1', port=5000, debug=True)
