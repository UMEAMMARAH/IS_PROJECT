import pytest
from authentication.models import User
from tests.conftest import extract_csrf_token


def test_last_administrator_protection(client, db, admin_user):
    """
    TEST 14: Last administrator protection.
    Expected: System prevents deactivation or demotion of the last active administrator.
    """
    # 1. Sign in as admin
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    client.post('/login', data={
        'csrf_token': token,
        'email': admin_user.email,
        'password': 'AdminPass123!'
    }, follow_redirects=True)

    # Obtain CSRF token from admin users page
    admin_page = client.get('/admin/users')
    assert admin_page.status_code == 200
    admin_token = extract_csrf_token(admin_page.get_data(as_text=True))

    # 2. Attempt self-deactivation: Must be blocked
    self_deact_res = client.post(f'/admin/users/{admin_user.id}/toggle-status', data={
        'csrf_token': admin_token
    }, follow_redirects=True)
    assert "You cannot deactivate your own administrative account." in self_deact_res.get_data(as_text=True)

    # Verify status unchanged
    admin_check = db.session.get(User, admin_user.id)
    assert admin_check.is_active is True

    # 3. Create a second admin to test demotion/deactivation of the last active admin
    second_admin = User(
        full_name="Second Admin",
        username="admin2",
        email="admin2@vault.io",
        role="Admin",
        is_active=True
    )
    second_admin.set_password("AdminPass123!")
    db.session.add(second_admin)
    db.session.commit()

    # Fetch admin page to get token
    page2 = client.get('/admin/users')
    token2 = extract_csrf_token(page2.get_data(as_text=True))

    # Deactivating second_admin is permitted because first admin is still active
    client.post(f'/admin/users/{second_admin.id}/toggle-status', data={
        'csrf_token': token2
    }, follow_redirects=True)
    
    db.session.refresh(second_admin)
    assert second_admin.is_active is False

    # Now second_admin is inactive, leaving admin_user as the ONLY active admin.
    # Attempting to demote admin_user to 'User' must be blocked!
    page3 = client.get('/admin/users')
    token3 = extract_csrf_token(page3.get_data(as_text=True))

    demote_res = client.post(f'/admin/users/{admin_user.id}/change-role', data={
        'csrf_token': token3,
        'role': 'User'
    }, follow_redirects=True)

    assert "Cannot remove administrative privileges from the last active administrator." in demote_res.get_data(as_text=True)
    db.session.refresh(admin_user)
    assert admin_user.role == 'Admin'


def test_admin_user_search_and_toggle(client, db, admin_user, regular_user):
    """
    Test admin search functionality and status toggling for regular users.
    """
    # Sign in as admin
    get_res = client.get('/login')
    token = extract_csrf_token(get_res.get_data(as_text=True))

    client.post('/login', data={
        'csrf_token': token,
        'email': admin_user.email,
        'password': 'AdminPass123!'
    }, follow_redirects=True)

    # Search for regular user
    search_res = client.get(f'/admin/users?q={regular_user.username}')
    assert search_res.status_code == 200
    assert regular_user.username in search_res.get_data(as_text=True)

    # Deactivate regular user
    admin_token = extract_csrf_token(search_res.get_data(as_text=True))
    toggle_res = client.post(f'/admin/users/{regular_user.id}/toggle-status', data={
        'csrf_token': admin_token
    }, follow_redirects=True)

    assert f"User &#39;{regular_user.username}&#39; has been successfully deactivated." in toggle_res.get_data(as_text=True) or \
           f"User '{regular_user.username}' has been successfully deactivated." in toggle_res.get_data(as_text=True)

    db.session.refresh(regular_user)
    assert regular_user.is_active is False
