# SecureVault – Secure Document Management System

## Member 1: Authentication, RBAC, Session Management & Administrative User Governance

SecureVault is an enterprise-grade Information Security semester project developed to provide end-to-end encrypted document storage, cryptographic access delegation, role-based governance, and immutable audit logs.

This repository houses the core **Member 1** implementation, delivering authentication, user management, RBAC, session security, rate limiting, and administrative user governance.

---

## 1. Project Overview & Member 1 Responsibilities

### Member 1 Responsibilities
- **User Authentication**: Secure user registration, credential verification, and session lifecycle management.
- **Role-Based Access Control (RBAC)**: Enforcing system-level permissions between `Admin` and `User` with server-side decorators (`@login_required`, `@admin_required`).
- **Session Security & Hardening**: Defense against session fixation, CSRF attacks, credential brute-forcing, open redirect vulnerabilities, and insecure cookies (`HttpOnly`, `SameSite=Lax`).
- **Profile & Credential Management**: Self-service profile updates and secure password rotation with current password verification and complexity validation.
- **Admin User Governance**: Searchable user dashboard, role modification, account activation/deactivation, and safeguards preventing self-deactivation or demotion of the last active administrator.
- **Audit Logging Bridge**: Dedicated integration interface (`services/audit_service.py`) for Member 3's audit module.
- **Frontend Integration**: Connecting the Stitch AI frontend (`dashboard.html`, `document.html`, `share&permissions.html`, `upload.html`, `login.html`, `profile.html`, `admin_users.html`).

---

## 2. Technologies Used

- **Language & Runtime**: Python 3.10+
- **Framework**: Flask 3.0+
- **Database ORM**: Flask-SQLAlchemy / SQLite
- **Session & Identity**: Flask-Login
- **Password Security**: Werkzeug (`scrypt` / `pbkdf2:sha256` key derivation)
- **Form Security & CSRF**: Flask-WTF & WTForms
- **Rate Limiting**: Flask-Limiter
- **Testing**: pytest
- **Frontend**: HTML5, Tailwind CSS, Material Symbols Outlined, Google Inter font

---

## 3. Project Structure

```text
IS_Project/
│
├── app.py                     # Flask application factory, routes & CLI commands
├── config.py                  # Base, Development, and Testing configurations
├── extensions.py              # Centralized extensions (db, login_manager, csrf, limiter)
├── requirements.txt           # Project Python dependencies
├── .env.example               # Template environment configuration
├── .gitignore                 # Version control ignores
├── README.md                  # Comprehensive project documentation
│
├── authentication/            # Authentication & Identity Module
│   ├── __init__.py            # Blueprint and export definitions
│   ├── models.py              # User SQLAlchemy model (hashed passwords, RBAC)
│   ├── forms.py               # Flask-WTF forms with security validation
│   ├── routes.py              # /register, /login, /logout, /profile endpoints
│   └── decorators.py          # @login_required, @admin_required RBAC decorators
│
├── admin/                     # Administrative Governance Module
│   ├── __init__.py            # Admin blueprint definition
│   └── routes.py              # /admin/users, toggle-status, change-role with safeguards
│
├── services/                  # Cross-Module Service Interfaces
│   ├── __init__.py
│   └── audit_service.py       # Integration hook for Member 3 audit logging
│
├── database/                  # SQLite storage directory
│   └── app.db                 # Auto-generated SQLite database
│
├── frontend/                  # Jinja2 HTML Templates (Preserving Stitch AI Design)
│   ├── dashboard.html         # User overview dashboard
│   ├── document.html          # My Documents view (Member 2 surface)
│   ├── share&permissions.html # Document Sharing & Access (Member 2 surface)
│   ├── upload.html            # Document Upload (Member 2 surface)
│   ├── login.html             # Unified Sign In / Registration interface
│   ├── register.html          # Dedicated registration template alias
│   ├── profile.html           # User Profile & Password Change interface
│   ├── admin_users.html       # Admin User Management & RBAC panel
│   ├── 403.html               # Custom HTTP 403 Forbidden error page
│   └── 404.html               # Custom HTTP 404 Not Found error page
│
├── static/                    # Static Assets
│   ├── css/
│   ├── js/
│   └── images/
│
└── tests/                     # Automated Test Suite (All 15 Scenarios)
    ├── __init__.py
    ├── conftest.py            # Test fixtures and CSRF token extraction utilities
    ├── test_registration.py   # Registration, duplicate handling, password hashing
    ├── test_login.py          # Login, inactive accounts, session fixation, logout
    ├── test_authorization.py  # RBAC enforcement, 403 checks, CSRF rejection
    └── test_admin.py          # Admin governance, search, last-admin safeguards
```

---

## 4. Installation & Setup Instructions

### Step 1: Clone or Navigate to the Workspace
```powershell
cd E:\7-Semester\IS\Final_Project\IS_Project
```

### Step 2: Create and Activate a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```

---

## 5. Database Initialization & First Administrator Setup

### Automatic Initialization
The SQLite database and tables are created automatically on the first application launch.

You can also explicitly initialize the database using the Flask CLI:
```powershell
flask init-db
```

### Securely Creating the First Administrator
Administrative privileges cannot be obtained via public registration. To create the first system administrator safely without hardcoding secrets:
```powershell
flask create-admin
```
You will be prompted for:
- **Admin Username**: e.g., `sysadmin`
- **Admin Email**: e.g., `admin@vault.io`
- **Admin Full Name**: e.g., `System Administrator`
- **Admin Password**: (min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special character)

---

## 6. How to Run the Application

Run the development server using Flask:
```powershell
python app.py
```
Or via the Flask CLI:
```powershell
flask run --host=127.0.0.1 --port=5000
```
Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## 7. How to Run Automated Tests

To execute the entire 16-test automated security suite:
```powershell
pytest -v
```

All 15 required scenarios from the specification are implemented and verified:
- **TEST 1**: Successful registration.
- **TEST 2**: Duplicate email rejection.
- **TEST 3**: Duplicate username rejection.
- **TEST 4**: Invalid password rejection.
- **TEST 5**: Successful authenticated session establishment.
- **TEST 6**: Secure password hashing in database (no plaintext).
- **TEST 7**: Unauthorized dashboard redirect to login.
- **TEST 8**: Normal user accessing admin pages blocked with HTTP 403 Forbidden.
- **TEST 9**: Administrator access to `/admin/users` granted (HTTP 200).
- **TEST 10**: Deactivated account login denied.
- **TEST 11**: Logout via POST with CSRF and session invalidation.
- **TEST 12**: Role escalation prevention (public registration forced to `User`).
- **TEST 13**: Deactivated accounts prevented from authenticating.
- **TEST 14**: Safeguards protecting against self-deactivation or demoting the last active administrator.
- **TEST 15**: Rejection of requests with invalid or missing CSRF tokens (HTTP 400).
- **TEST 16**: Admin user search and status toggle verification.

---

## 8. Authentication & Application Security Architecture

1. **Password Hashing**:
   - Uses Werkzeug password hashing implementing salted `scrypt` or `pbkdf2:sha256`.
   - Raw plaintext passwords are never saved, transmitted in logs, or exposed in frontend responses.
2. **Password Policy**:
   - Enforces minimum 8 characters, at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special symbol.
3. **Session Hardening & Cookie Protection**:
   - `SESSION_COOKIE_HTTPONLY = True`: Blocks JavaScript access (`document.cookie`), mitigating cross-site scripting (XSS) session theft.
   - `SESSION_COOKIE_SAMESITE = 'Lax'`: Protects cookies against cross-site request forgery.
   - `PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)`: Automatically expires idle sessions.
4. **Session Fixation Defense**:
   - On successful authentication in `auth.login`, the previous session is flushed, a fresh session token is minted, and the authenticated identity is attached.
5. **Rate Limiting**:
   - Powered by `Flask-Limiter` (`10 requests per minute` on `POST /login`) to protect against dictionary attacks and brute-force credential stuffing.
6. **CSRF Protection**:
   - Every state-changing endpoint (`POST /login`, `POST /register`, `POST /logout`, `POST /profile`, `POST /admin/users/...`) is guarded by Flask-WTF CSRF tokens.
   - Missing or tampered CSRF tokens trigger an audit alert and are rejected with HTTP 400.
7. **Open Redirect Mitigation**:
   - The `next` parameter is validated against the application's hostname with `is_safe_url()` before performing any redirection.

---

## 9. Role-Based Access Control (RBAC) Architecture

SecureVault maintains two system-level roles:
- **`User`**: Standard user permitted to view the dashboard, upload encrypted files, share documents, and manage their profile.
- **`Admin`**: System administrator permitted to view all accounts, search identities, activate/deactivate users, and promote/demote roles.

### Authorization Decorators (`authentication/decorators.py`)
- `@login_required`: Restricts routes to authenticated sessions.
- `@admin_required`: Restricts endpoints to authenticated users with `role == 'Admin'`. Non-admin users are returned **HTTP 403 Forbidden**.

### Administrative Safeguards
- **Self-Deactivation Prevention**: An administrator cannot deactivate their own account.
- **Last Active Admin Protection**: The system prevents deactivating or demoting the last active administrator, ensuring the system cannot become administratively orphaned.

---

## 10. Integration Guide for Team Members

### For Member 2 (Documents, Upload, Encryption, Permissions):
Member 2 can immediately access the authenticated user context in any route or template:
```python
from flask import Blueprint, render_template, request
from authentication.decorators import login_required
from flask_login import current_user

document_bp = Blueprint('documents', __name__, url_prefix='/documents')

@document_bp.route('/upload', methods=['POST'])
@login_required
def process_upload():
    # User identity is securely available:
    owner_id = current_user.id
    owner_username = current_user.username
    owner_email = current_user.email
    owner_role = current_user.role
    # Member 2 encrypts and stores document metadata linked to owner_id
    ...
```

### For Member 3 (Audit Logging & Tamper-Evident Logs):
Member 3 does not need to alter authentication routes. Member 1 has implemented the unified bridge in:
`services/audit_service.py`

Whenever authentication, login failures, password rotations, account toggles, or role modifications take place, `record_audit_event()` is called:
```python
record_audit_event(user_id, action, details, ip_address)
```
Member 3 can easily bind their cryptographic signing or database table directly inside `record_audit_event()` in `services/audit_service.py`.
