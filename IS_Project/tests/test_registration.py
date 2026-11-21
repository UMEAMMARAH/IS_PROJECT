import pytest
from authentication.models import User
from tests.conftest import extract_csrf_token


def test_successful_registration(client, db):
    """
    TEST 1: Successful registration.
    Expected: User is created in the database with User role and active status.
    """
    # 1. Fetch registration form to retrieve valid CSRF token
    get_res = client.get('/register')
    assert get_res.status_code == 200
    token = extract_csrf_token(get_res.get_data(as_text=True))
    assert token != ""

    # 2. Submit valid registration data
    post_res = client.post('/register', data={
        'csrf_token': token,
        'full_name': 'Alice Johnson',
        'username': 'alice_j',
        'email': 'alice@vault.io',
        'password': 'StrongPassword2026!',
        'confirm_password': 'StrongPassword2026!'
    }, follow_redirects=True)

    assert post_res.status_code == 200
    assert "Account registered successfully" in post_res.get_data(as_text=True)

    # 3. Verify user in database
    user = User.query.filter_by(username='alice_j').first()
    assert user is not None
    assert user.email == 'alice@vault.io'
    assert user.full_name == 'Alice Johnson'
    assert user.role == 'User'  # Must receive User role
    assert user.is_active is True


def test_duplicate_email_registration(client, regular_user):
    """
    TEST 2: Duplicate email registration.
    Expected: Registration rejected due to unique email constraint.
    """
    get_res = client.get('/register')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    post_res = client.post('/register', data={
        'csrf_token': token,
        'full_name': 'Another User',
        'username': 'unique_user_99',
        'email': regular_user.email,  # Existing email
        'password': 'StrongPassword2026!',
        'confirm_password': 'StrongPassword2026!'
    })

    assert post_res.status_code == 200
    content = post_res.get_data(as_text=True)
    assert "An account with this email address already exists." in content


def test_duplicate_username_registration(client, regular_user):
    """
    TEST 3: Duplicate username registration.
    Expected: Registration rejected due to unique username constraint.
    """
    get_res = client.get('/register')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    post_res = client.post('/register', data={
        'csrf_token': token,
        'full_name': 'New User',
        'username': regular_user.username,  # Existing username
        'email': 'totally_unique@vault.io',
        'password': 'StrongPassword2026!',
        'confirm_password': 'StrongPassword2026!'
    })

    assert post_res.status_code == 200
    content = post_res.get_data(as_text=True)
    assert "This username is already taken." in content


def test_password_storage_hashing(client, db):
    """
    TEST 6: Password storage.
    Expected: Database contains cryptographic password hash, NEVER plaintext password.
    """
    get_res = client.get('/register')
    token = extract_csrf_token(get_res.get_data(as_text=True))
    plain_password = "SecretPassword123!"

    client.post('/register', data={
        'csrf_token': token,
        'full_name': 'Bob Smith',
        'username': 'bob_smith',
        'email': 'bob@vault.io',
        'password': plain_password,
        'confirm_password': plain_password
    }, follow_redirects=True)

    user = User.query.filter_by(username='bob_smith').first()
    assert user is not None
    # Must NOT equal plaintext
    assert user.password_hash != plain_password
    # Must verify using check_password
    assert user.check_password(plain_password) is True
    # Must start with standard Werkzeug hash prefix (scrypt or pbkdf2)
    assert user.password_hash.startswith(('scrypt:', 'pbkdf2:'))


def test_role_escalation_attempt(client, db):
    """
    TEST 12: Role escalation attempt.
    Expected: Normal users cannot assign themselves Admin privileges during registration.
    """
    get_res = client.get('/register')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    # Attacker injects 'role': 'Admin' in form payload
    client.post('/register', data={
        'csrf_token': token,
        'full_name': 'Attacker Eve',
        'username': 'attacker_eve',
        'email': 'eve@vault.io',
        'role': 'Admin',  # Attempted privilege escalation
        'password': 'StrongPassword2026!',
        'confirm_password': 'StrongPassword2026!'
    }, follow_redirects=True)

    user = User.query.filter_by(username='attacker_eve').first()
    assert user is not None
    assert user.role == 'User'  # Must remain 'User'
    assert user.is_admin is False
