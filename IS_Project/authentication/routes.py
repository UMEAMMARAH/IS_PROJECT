from urllib.parse import urlparse, urljoin
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, current_user, login_required
from sqlalchemy import func
from extensions import db, limiter
from authentication.models import User
from authentication.forms import RegistrationForm, LoginForm, ProfileUpdateForm, PasswordChangeForm
from services.audit_service import record_audit_event

auth_bp = Blueprint('auth', __name__)


def is_safe_url(target: str) -> bool:
    """
    Prevent Open Redirect vulnerabilities.
    Verifies that the target redirect URL is internal to the application host.
    """
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Public registration endpoint.
    All new registrations are strictly assigned role='User'.
    No client input can influence administrative privilege assignment.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            full_name=form.full_name.data.strip(),
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role='User',  # Enforced User role
            is_active=True
        )
        user.set_password(form.password.data)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Record audit event
            record_audit_event(
                user.id,
                "Successful registration",
                {"username": user.username, "email": user.email, "role": user.role},
                request.remote_addr
            )
            login_user(user)
            session.permanent = True

            flash(f"Welcome, {user.full_name}! Your account is ready.", "success")
            return redirect(url_for('main.dashboard')) 
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during account creation. Please try again.", "error")

    return render_template('login.html', form=form, active_tab='register')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    """
    Authentication endpoint with rate limiting, password verification,
    and session fixation protection.
    """
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.users'))
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    reg_form = RegistrationForm()
    active_tab = request.args.get('tab', 'login')

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        remember = form.remember_me.data

        user = User.query.filter(func.lower(User.email) == email).first()

        # Check credentials
        if not user or not user.check_password(password):
            record_audit_event(
                None,
                "Failed login",
                {"attempted_email": email, "reason": "Invalid credentials"},
                request.remote_addr
            )
            flash("Invalid email or password.", "error")
            return render_template('login.html', form=form, reg_form=reg_form, active_tab='login'), 200

        # Check if account is active
        if not user.is_active:
            record_audit_event(
                user.id,
                "Failed login",
                {"attempted_email": email, "reason": "Deactivated account"},
                request.remote_addr
            )
            flash("Your account has been deactivated. Please contact an administrator.", "error")
            return render_template('login.html', form=form, reg_form=reg_form, active_tab='login'), 200

        # Protect against Session Fixation: Clear previous session state while regenerating CSRF token
        old_csrf = session.get('csrf_token')
        session.clear()
        if old_csrf:
            session['csrf_token'] = old_csrf
        else:
            import hashlib, os
            session['csrf_token'] = hashlib.sha1(os.urandom(64)).hexdigest()

        # Establish Flask-Login session
        login_user(user, remember=remember)
        session.permanent = True

        record_audit_event(
            user.id,
            "Successful login",
            {"email": user.email, "role": user.role},
            request.remote_addr
        )

        flash(f"Welcome back, {user.full_name}!", "success")

        # Handle safe post-login redirection
        next_page = request.args.get('next')
        if next_page and is_safe_url(next_page):
            return redirect(next_page)

        if user.is_admin:
            return redirect(url_for('admin.users'))
        return redirect(url_for('main.dashboard'))

    return render_template('login.html', form=form, reg_form=reg_form, active_tab=active_tab)


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    Logout endpoint.
    Strictly accepts POST requests to prevent CSRF logout exploits.
    Destroys the authenticated session and redirects to login.
    """
    user_id = current_user.id if current_user.is_authenticated else None
    record_audit_event(user_id, "Logout", ip_address=request.remote_addr)

    logout_user()
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """
    User Profile and Password Management.
    Enables viewing account information, updating display name,
    and securely rotating passwords with current password verification.
    """
    profile_form = ProfileUpdateForm(prefix='profile')
    password_form = PasswordChangeForm(prefix='pwd')

    # Pre-populate profile form on GET
    if request.method == 'GET':
        profile_form.full_name.data = current_user.full_name

    # Handle display name update
    if profile_form.submit.data and profile_form.validate_on_submit():
        current_user.full_name = profile_form.full_name.data.strip()
        db.session.commit()
        record_audit_event(
            current_user.id,
            "Profile update",
            {"new_full_name": current_user.full_name},
            request.remote_addr
        )
        flash("Profile information updated successfully.", "success")
        return redirect(url_for('auth.profile'))

    # Handle password change
    if password_form.submit.data and password_form.validate_on_submit():
        if not current_user.check_password(password_form.current_password.data):
            record_audit_event(
                current_user.id,
                "Password change failed",
                {"reason": "Incorrect current password"},
                request.remote_addr
            )
            flash("Current password is incorrect.", "error")
        else:
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            record_audit_event(
                current_user.id,
                "Password change",
                {"status": "Success"},
                request.remote_addr
            )
            flash("Password updated successfully. Please use your new password next time you sign in.", "success")
            return redirect(url_for('auth.profile'))

    return render_template(
        'profile.html',
        profile_form=profile_form,
        password_form=password_form,
        user=current_user
    )
