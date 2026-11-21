import pytest
from tests.conftest import extract_csrf_token


def test_unauthorized_dashboard_access(client):
    """
    TEST 7: Unauthorized dashboard access.
    Expected: Anonymous users are redirected to login.
    """
    res = client.get('/dashboard')
    assert res.status_code == 302
    assert '/login' in res.headers['Location']


def test_normal_user_accessing_admin_page(client, regular_user):
    """
    TEST 8: Normal user accessing admin page.
    Expected: HTTP 403 Forbidden.
    """
    # Sign in as regular user
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    client.post('/login', data={
        'csrf_token': token,
        'email': regular_user.email,
        'password': 'SecurePass123!'
    }, follow_redirects=True)

    # Attempt to access restricted administrative endpoint
    admin_res = client.get('/admin/users')
    assert admin_res.status_code == 403
    assert "403 - Access Forbidden" in admin_res.get_data(as_text=True)


def test_administrator_accessing_admin_page(client, admin_user):
    """
    TEST 9: Administrator accessing admin page.
    Expected: Access granted (HTTP 200).
    """
    # Sign in as admin user
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    client.post('/login', data={
        'csrf_token': token,
        'email': admin_user.email,
        'password': 'AdminPass123!'
    }, follow_redirects=True)

    # Access administrative endpoint
    admin_res = client.get('/admin/users')
    assert admin_res.status_code == 200
    assert "User Accounts & Access Control" in admin_res.get_data(as_text=True)


def test_csrf_protection_rejection(client, regular_user):
    """
    TEST 15: CSRF protection.
    Expected: Invalid or missing CSRF token is rejected for protected state-changing requests.
    """
    # 1. Missing CSRF token on registration POST
    res_no_csrf = client.post('/register', data={
        'full_name': 'Malicious Hacker',
        'username': 'bad_actor',
        'email': 'bad@vault.io',
        'password': 'StrongPassword123!',
        'confirm_password': 'StrongPassword123!'
    })
    # Must fail CSRF verification (400 Bad Request)
    assert res_no_csrf.status_code == 400

    # 2. Invalid CSRF token
    res_fake_csrf = client.post('/register', data={
        'csrf_token': 'fake-invalid-tampered-token-12345',
        'full_name': 'Malicious Hacker',
        'username': 'bad_actor2',
        'email': 'bad2@vault.io',
        'password': 'StrongPassword123!',
        'confirm_password': 'StrongPassword123!'
    })
    assert res_fake_csrf.status_code == 400
