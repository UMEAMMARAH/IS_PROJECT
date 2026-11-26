# SecureVault – Secure Document Management System

SecureVault is an Information Security semester project providing encrypted document storage, owner-controlled document sharing, role-based governance, and audit logging.

This repository contains the **Member 1** implementation (authentication, RBAC, session security, admin user governance) together with the supporting security services used across the project (cryptography, document authorization, security headers).

---

## 1. Project Overview & Member 1 Responsibilities

- **User Authentication**: Registration, credential verification, logout, and session lifecycle management.
- **Role-Based Access Control (RBAC)**: `Admin` and `User` roles enforced server-side with `@login_required` and `@admin_required`.
- **Discretionary Access Control (DAC)**: Document owners decide who may access their documents (sharing).
- **Document Isolation**: Users cannot access documents they do not own or that were not shared with them.
- **Session Security & Hardening**: Protection against session fixation, CSRF, brute-force attacks, open redirects, and insecure cookies.
- **Profile & Credential Management**: Profile updates and password rotation with current-password verification.
- **Admin User Governance**: Searchable user list, role changes, activation/deactivation, with safeguards for self-deactivation and the last active administrator.
- **Audit Logging Bridge**: `services/audit_service.py` exposes `record_audit_event()` for the audit module.
- **Frontend Integration**: Jinja2 templates built from the Stitch AI design.

---

## 2. Technologies Used

| Area | Technology |
|---|---|
| Language | Python 3.10+ (tested on 3.13) |
| Framework | Flask 3.0+ |
| Database | Flask-SQLAlchemy / SQLite |
| Sessions & identity | Flask-Login |
| Password hashing | Werkzeug (`scrypt` / `pbkdf2:sha256`) |
| Forms & CSRF | Flask-WTF / WTForms |
| Rate limiting | Flask-Limiter |
| Cryptography | `cryptography` library (AES-256-GCM, SHA-256, 3DES demo) |
| Testing | pytest |
| Frontend | HTML5, Tailwind CSS, Material Symbols, Inter font |

---

## 3. Project Structure

```text
IS_Project/
├── app.py                     # Application factory, routes, CLI commands
├── config.py                  # Base, Development, Testing configurations
├── extensions.py              # db, login_manager, csrf, limiter
├── requirements.txt
├── .env.example
├── README.md
│
├── authentication/            # Authentication & identity module
│   ├── models.py              # User model (hashed passwords, role)
│   ├── forms.py               # WTForms with validation
│   ├── routes.py              # /register, /login, /logout, /profile
│   └── decorators.py          # @login_required, @admin_required
│
├── admin/                     # Administrative governance module
│   └── routes.py              # /admin/users, toggle-status, change-role
│
├── services/
│   ├── audit_service.py       # Audit logging bridge
│   └── crypto_service.py      # AES-256-GCM, SHA-256, 3DES demo
│                              # VERIFY: list any other services/modules (documents, sharing)
│
├── database/app.db            # Auto-generated SQLite database
├── frontend/                  # Jinja2 templates (dashboard, document, upload,
│                              #   share&permissions, login, register, profile,
│                              #   admin_users, 403, 404)
├── static/                    # css/, js/, images/
│
└── tests/                     # 27 automated tests
    ├── conftest.py
    ├── test_registration.py
    ├── test_login.py
    ├── test_authorization.py
    ├── test_admin.py
    └── test_security_course.py
```

---

## 4. Installation & Setup

```powershell
cd E:\7-Semester\IS\Final_Project\IS_Project
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set a strong `SECRET_KEY`. Never commit `.env`.

---

## 5. Database Initialization & First Administrator

Tables are created automatically on first launch, or explicitly with:

```powershell
flask init-db
```

Admin privileges cannot be obtained through public registration. Create the first administrator with:

```powershell
flask create-admin
```

You will be prompted for username, email, full name, and password (min 8 characters, with uppercase, lowercase, number, and special character).

---

## 6. Running the Application

```powershell
python app.py
# or
flask run --host=127.0.0.1 --port=5000
```

Open `http://127.0.0.1:5000`.

---

## 7. Automated Tests

```powershell
pytest -v
```

**Result: 27 passed.**

| File | What it verifies |
|---|---|
| `test_registration.py` | Successful registration, duplicate email, duplicate username, password stored hashed, role-escalation attempt blocked |
| `test_login.py` | Valid login, wrong password, inactive account denied, logout, account deactivation |
| `test_authorization.py` | Unauthenticated redirect, normal user gets 403 on admin pages, admin access granted, CSRF rejection |
| `test_admin.py` | User search and status toggle, last-administrator protection |
| `test_security_course.py` | Password hashing, AES-256-GCM round trip, SHA-256 tamper detection, SQL injection defense (login and admin search), XSS auto-escaping, CSRF on state changes, document authorization and sharing lifecycle, security headers and anti-caching, 3DES academic demonstration |

<!-- VERIFY: run `pytest --collect-only -q` and confirm this table matches all 27 tests. -->

---

## 8. Authentication & Application Security Architecture

1. **Password hashing**: Werkzeug with per-password salt, using `scrypt` or `pbkdf2:sha256`. Plaintext passwords are never stored or logged.
2. **Password policy**: Minimum 8 characters with uppercase, lowercase, digit, and special character.
3. **Cookie hardening**: `HttpOnly` (blocks JavaScript access, limiting XSS session theft), `SameSite=Lax`, 60-minute session lifetime.
4. **Session fixation defense**: The session is cleared and re-issued on successful login.
5. **Rate limiting**: 10 requests per minute on `POST /login` (Flask-Limiter) against brute force.
6. **CSRF protection**: All state-changing endpoints require a Flask-WTF token. Missing or invalid tokens return HTTP 400.
7. **Open redirect mitigation**: The `next` parameter is validated with `is_safe_url()`.
8. **SQL injection defense**: All queries go through the SQLAlchemy ORM (parameterized).
9. **XSS defense**: Jinja2 auto-escaping on all template output.
10. **Security headers & anti-caching**: Security headers are set on responses, and sensitive pages are not cached, so the Back button cannot reveal pages after logout.

---

## 9. Cryptography Used

| Purpose | Algorithm | Notes |
|---|---|---|
| Password storage | scrypt / PBKDF2-HMAC-SHA256 | Salted, slow key derivation |
| Document encryption | **AES-256-GCM** | Authenticated encryption: confidentiality plus integrity |
| Integrity verification | **SHA-256** | Digest used to detect tampering |
| Session cookies | HMAC-signed (`itsdangerous`) | Tamper-evident cookies |
| CSRF tokens | Random, signed tokens | Bound to the session |
| Academic demo | 3DES-CBC | Demonstration only, **not** used to protect documents |

<!-- VERIFY: add key generation / key storage details (e.g. os.urandom, per-document keys, key wrapping, RSA) from crypto_service.py. -->

### About the 3DES demonstration

`crypto_service.py` includes a small DES-family example to contrast legacy and modern encryption:

| | 3DES-CBC (demo) | AES-256-GCM (real use) |
|---|---|---|
| Block size | 64-bit | 128-bit |
| Effective key strength | ~112 bits (56 if the key is repeated) | 256 bits |
| Integrity protection | None | Built in (authentication tag) |
| Status | Deprecated by NIST | Current standard |

The demo repeats a single key three times, which reduces 3DES to single DES. This is intentional for illustration; it must never be used to protect real data.

---

## 10. Access Control Architecture

### RBAC (Role-Based Access Control)

Access to system functions is decided by the user's **role**:

- **`User`**: dashboard, upload, share own documents, manage profile.
- **`Admin`**: everything a User can do, plus view/search accounts, activate/deactivate users, change roles.

Enforced by `@login_required` (authenticated sessions) and `@admin_required` (returns **HTTP 403** to non-admins).

### DAC (Discretionary Access Control)

Access to a **document** is decided by its **owner**. The owner can grant or revoke access for other users through the sharing feature. A user may open a document only if they own it or it was shared with them; otherwise the request is denied. This is verified by `test_document_authorization_and_sharing_lifecycle`.

| | RBAC | DAC |
|---|---|---|
| Who decides | The system (role assignment by admin) | The resource owner |
| Applied to | System functions (admin panel) | Individual documents |
| In SecureVault | `Admin` / `User` roles | Per-document sharing |

### Principle of Least Privilege

- New registrations are always created as `User`; the role cannot be set through the registration form.
- Normal users cannot reach any `/admin/*` route.
- Documents are private by default and shared only per document, per user.
- Deactivated accounts cannot authenticate.

### Administrative Safeguards

- An administrator cannot deactivate their own account.
- The last active administrator cannot be deactivated or demoted.

---

## 11. Integration Guide

### Documents, Upload, Encryption, Permissions

```python
from authentication.decorators import login_required
from flask_login import current_user

@document_bp.route('/upload', methods=['POST'])
@login_required
def process_upload():
    owner_id = current_user.id
    ...
```

Always verify ownership or share permission before returning a document.

### Audit Logging

```python
record_audit_event(user_id, action, details, ip_address)
```

Called on logins, login failures, password changes, account toggles, role changes, and CSRF failures. Audit storage and signing are implemented behind `services/audit_service.py`.

---

## 12. Security Concepts Summary

| Concept | How SecureVault applies it |
|---|---|
| Authentication | Password login with hashed credentials, rate limiting, session fixation defense |
| Authorization | Decorators plus document ownership/share checks |
| RBAC | `Admin` / `User` roles |
| DAC | Owner-controlled document sharing |
| Least privilege | Default `User` role, private-by-default documents, admin-only routes |
| Session security | HttpOnly, SameSite=Lax, 60-minute expiry, anti-caching headers |

---

## 13. Known Limitations

- SQLite and the Flask development server are for development only; production needs a real database, HTTPS, and `SESSION_COOKIE_SECURE=True`.
- Rate limiting uses in-memory storage by default and resets on restart.
- The 3DES demo is intentionally insecure and for teaching only.