import pytest
from authentication.models import User
from tests.conftest import extract_csrf_token


def test_invalid_password_login(client, regular_user):
    """
    TEST 4: Invalid password login.
    Expected: Login denied and friendly error displayed.
    """
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    post_res = client.post('/login', data={
        'csrf_token': token,
        'email': regular_user.email,
        'password': 'WrongPassword123!'
    }, follow_redirects=True)

    assert post_res.status_code == 200
    assert "Invalid email or password." in post_res.get_data(as_text=True)

    # Verify protected dashboard remains inaccessible
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 302
    assert '/login' in dash_res.headers['Location']


def test_successful_login(client, regular_user):
    """
    TEST 5: Successful login.
    Expected: Authenticated session created, redirected to dashboard.
    """
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    post_res = client.post('/login', data={
        'csrf_token': token,
        'email': regular_user.email,
        'password': 'SecurePass123!'
    }, follow_redirects=True)

    assert post_res.status_code == 200
    content = post_res.get_data(as_text=True)
    assert f"Good morning, {regular_user.full_name}" in content

    # Verify dashboard is accessible in this authenticated session
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 200


def test_inactive_user_login(client, db):
    """
    TEST 10: Inactive user login.
    Expected: Login denied due to deactivated account status.
    """
    inactive_user = User(
        full_name="Inactive User",
        username="inactive_usr",
        email="inactive@vault.io",
        role="User",
        is_active=False
    )
    inactive_user.set_password("SecurePass123!")
    db.session.add(inactive_user)
    db.session.commit()

    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    post_res = client.post('/login', data={
        'csrf_token': token,
        'email': inactive_user.email,
        'password': 'SecurePass123!'
    }, follow_redirects=True)

    assert post_res.status_code == 200
    assert "Your account has been deactivated." in post_res.get_data(as_text=True)

    # Dashboard must remain inaccessible
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 302


def test_logout(client, regular_user):
    """
    TEST 11: Logout.
    Expected: Session destroyed and protected pages inaccessible.
    """
    # 1. Sign in
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    client.post('/login', data={
        'csrf_token': token,
        'email': regular_user.email,
        'password': 'SecurePass123!'
    }, follow_redirects=True)

    # Verify authenticated
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 200
    dash_token = extract_csrf_token(dash_res.get_data(as_text=True))

    # 2. Sign out via POST with CSRF
    logout_res = client.post('/logout', data={
        'csrf_token': dash_token
    }, follow_redirects=True)

    assert logout_res.status_code == 200
    assert "You have been signed out successfully." in logout_res.get_data(as_text=True)

    # 3. Verify protected pages are no longer accessible
    dash_after = client.get('/dashboard')
    assert dash_after.status_code == 302
    assert '/login' in dash_after.headers['Location']


def test_account_deactivation(client, db, regular_user):
    """
    TEST 13: Account deactivation.
    Expected: Once an account is deactivated, it can no longer authenticate.
    """
    # Deactivate the user
    regular_user.is_active = False
    db.session.commit()

    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    post_res = client.post('/login', data={
        'csrf_token': token,
        'email': regular_user.email,
        'password': 'SecurePass123!'
    }, follow_redirects=True)

    assert "Your account has been deactivated." in post_res.get_data(as_text=True)
