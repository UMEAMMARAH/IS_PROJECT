from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, login_manager


class User(UserMixin, db.Model):
    """
    SecureVault User Model for Authentication and Role-Based Access Control.
    
    Fields:
      - id: Primary Key
      - full_name: User's real name
      - username: Unique alphanumeric identifier
      - email: Unique contact and login identifier
      - password_hash: Cryptographic hash of user's password (salted)
      - role: 'Admin' or 'User' (System RBAC)
      - is_active: Account enablement flag (True=Active, False=Deactivated)
      - created_at: Registration timestamp
      - updated_at: Last profile/state update timestamp
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='User')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships to documents, shares, and audit records
    documents = db.relationship('Document', backref='owner', lazy=True, cascade='all, delete-orphan')
    shares_given = db.relationship('DocumentShare', foreign_keys='DocumentShare.shared_by_user_id', backref='sharer', lazy=True, cascade='all, delete-orphan')
    shares_received = db.relationship('DocumentShare', foreign_keys='DocumentShare.shared_with_user_id', backref='recipient', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='actor', lazy=True)

    def set_password(self, password: str) -> None:
        """
        Securely hash password using Werkzeug's default recommended algorithm (scrypt/pbkdf2).
        Plaintext passwords are NEVER persisted.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """
        Verify input plaintext password against the stored cryptographic hash.
        """
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        """Helper to quickly check if user possesses Administrator privileges."""
        return self.role.strip().lower() == 'admin'

    def to_dict(self) -> dict:
        """
        Safe dictionary representation for internal usage or APIs.
        Notice: Password hash is explicitly EXCLUDED.
        """
        return {
            "id": self.id,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}' active={self.is_active}>"


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader callback."""
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


class AuditLog(db.Model):
    """
    Persistent Security and Application Audit Trail in SQLite.
    Tracks authentication, document actions, and administrative operations.
    """
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True, default='N/A')
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'actor_name': self.actor.full_name if self.actor else 'System / Anonymous',
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

    def __repr__(self):
        return f"<AuditLog id={self.id} action='{self.action}' user_id={self.user_id}>"


class Document(db.Model):
    """
    SecureVault Document Entity.
    Stores metadata, integrity checksums, and encrypted storage coordinates.
    """
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True, index=True)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # in bytes
    mime_type = db.Column(db.String(100), nullable=False, default='application/octet-stream')
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256 integrity hash
    is_encrypted = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    shares = db.relationship('DocumentShare', backref='document', lazy=True, cascade='all, delete-orphan')

    @property
    def formatted_size(self) -> str:
        """Human-readable file size."""
        b = self.file_size
        if b < 1024:
            return f"{b} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 * 1024 * 1024:
            return f"{b / (1024 * 1024):.1f} MB"
        else:
            return f"{b / (1024 * 1024 * 1024):.2f} GB"

    @property
    def file_extension(self) -> str:
        """Extract uppercase file extension."""
        parts = self.original_filename.rsplit('.', 1)
        return parts[1].upper() if len(parts) > 1 else 'FILE'

    @property
    def is_shared(self) -> bool:
        """Returns True if document has any active shares."""
        return len(self.shares) > 0

    def __repr__(self):
        return f"<Document id={self.id} title='{self.title}' size={self.file_size}>"


class DocumentShare(db.Model):
    """
    Access Control Delegation & Permissions for Documents.
    """
    __tablename__ = 'document_shares'

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False, index=True)
    shared_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    shared_with_email = db.Column(db.String(120), nullable=False, index=True)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    permission_tier = db.Column(db.String(50), nullable=False, default='Viewer')  # 'Viewer', 'Editor', 'Auditor'
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<DocumentShare id={self.id} doc={self.document_id} to='{self.shared_with_email}' tier='{self.permission_tier}'>"
