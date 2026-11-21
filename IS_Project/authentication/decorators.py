from functools import wraps
from flask import abort, redirect, url_for, flash, request
from flask_login import current_user, login_required

# Re-export login_required for seamless import by other modules
__all__ = ['login_required', 'admin_required']


def admin_required(f):
    """
    RBAC Decorator: Ensures the requesting user is authenticated, active,
    and has the 'Admin' system role.
    
    Returns HTTP 403 Forbidden if a regular User attempts access.
    Redirects unauthenticated visitors to login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for('auth.login', next=request.url))
        
        if not current_user.is_active:
            flash("Your account is deactivated. Please contact an administrator.", "error")
            return redirect(url_for('auth.login'))

        if not current_user.is_admin:
            # Strictly return HTTP 403 Forbidden for unauthorized role access
            abort(403)

        return f(*args, **kwargs)
    return decorated_function
