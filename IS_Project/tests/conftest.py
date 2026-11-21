import re
import pytest
from app import create_app
from config import TestConfig
from extensions import db as _db
from authentication.models import User


def extract_csrf_token(response_text: str) -> str:
    """Helper to extract CSRF token from rendered HTML response."""
    match = re.search(r'name="csrf_token"\s+type="hidden"\s+value="([^"]+)"', response_text)
    if not match:
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response_text)
    if not match:
        match = re.search(r'value="([^"]+)"\s+name="csrf_token"', response_text)
    if not match:
        match = re.search(r'id="csrf_token"\s+name="csrf_token"\s+type="hidden"\s+value="([^"]+)"', response_text)
    return match.group(1) if match else ""


@pytest.fixture
def app():
    """Create and configure a fresh Flask app instance for tests."""
    app = create_app(TestConfig)
    
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def db(app):
    """Database instance."""
    return _db


@pytest.fixture
def regular_user(db):
    """Create a regular active user in test database."""
    user = User(
        full_name="Standard User",
        username="standard_user",
        email="standard@vault.io",
        role="User",
        is_active=True
    )
    user.set_password("SecurePass123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def admin_user(db):
    """Create an administrator in test database."""
    admin = User(
        full_name="System Admin",
        username="sysadmin",
        email="admin@vault.io",
        role="Admin",
        is_active=True
    )
    admin.set_password("AdminPass123!")
    db.session.add(admin)
    db.session.commit()
    return admin


@pytest.fixture
def authenticated_client(client, regular_user):
    """Client authenticated as regular_user."""
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))
    client.post('/login', data={
        'csrf_token': token,
        'email': regular_user.email,
        'password': 'SecurePass123!'
    }, follow_redirects=True)
    return client


@pytest.fixture
def authenticated_admin(client, admin_user):
    """Client authenticated as admin_user."""
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))
    client.post('/login', data={
        'csrf_token': token,
        'email': admin_user.email,
        'password': 'AdminPass123!'
    }, follow_redirects=True)
    return client
