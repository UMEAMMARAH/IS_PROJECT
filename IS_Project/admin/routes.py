from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import current_user
from sqlalchemy import or_, func
from extensions import db
from authentication.models import User
from authentication.decorators import login_required, admin_required
from services.audit_service import record_audit_event

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.before_request
@login_required
@admin_required
def enforce_admin_access():
    """
    Strictly enforce administrative RBAC on every admin endpoint.
    Non-admin users attempting access are blocked with HTTP 403 Forbidden.
    """
    pass


@admin_bp.route('/users', methods=['GET'])
def users():
    """
    Admin User Management Dashboard.
    Supports filtering/searching by name, username, or email.
    Displays user metadata, account status, and role management controls.
    """
    query = request.args.get('q', '').strip()
    
    users_query = User.query
    if query:
        search_filter = or_(
            User.username.ilike(f"%{query}%"),
            User.email.ilike(f"%{query}%"),
            User.full_name.ilike(f"%{query}%")
        )
        users_query = users_query.filter(search_filter)

    user_list = users_query.order_by(User.created_at.desc()).all()

    # Aggregate metric statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    inactive_users = User.query.filter_by(is_active=False).count()
    admin_count = User.query.filter(func.lower(User.role) == 'admin').count()

    return render_template(
        'admin_users.html',
        users=user_list,
        search_query=query,
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        admin_count=admin_count,
        current_admin=current_user
    )


@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
def toggle_user_status(user_id: int):
    """
    Activate or deactivate a user account.
    
    CRITICAL SECURITY SAFEGUARDS:
      1. An administrator CANNOT deactivate their own account.
      2. The system CANNOT deactivate the last active administrator.
      3. State changes are protected against CSRF.
    """
    target_user = db.get_or_404(User, user_id)

    # Safeguard 1: Prevent self-deactivation
    if target_user.id == current_user.id:
        flash("Security Policy: You cannot deactivate your own administrative account.", "error")
        return redirect(url_for('admin.users'))

    # Safeguard 2: Prevent deactivating the last active administrator
    if target_user.is_admin and target_user.is_active:
        active_admin_count = User.query.filter(
            func.lower(User.role) == 'admin',
            User.is_active == True
        ).count()
        if active_admin_count <= 1:
            flash("Security Policy Violation: Cannot deactivate the last active administrator.", "error")
            return redirect(url_for('admin.users'))

    # Toggle account status
    target_user.is_active = not target_user.is_active
    db.session.commit()

    action_label = "Account activation" if target_user.is_active else "Account deactivation"
    record_audit_event(
        current_user.id,
        action_label,
        {
            "target_user_id": target_user.id,
            "target_username": target_user.username,
            "new_status": "Active" if target_user.is_active else "Inactive"
        },
        request.remote_addr
    )

    status_str = "activated" if target_user.is_active else "deactivated"
    flash(f"User '{target_user.username}' has been successfully {status_str}.", "success")
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/change-role', methods=['POST'])
def change_user_role(user_id: int):
    """
    Promote or demote a user's role (Admin <-> User).
    
    CRITICAL SECURITY SAFEGUARDS:
      1. Protect against removing administrative privileges from the last active admin.
      2. Validates role value strictly against allowed system roles.
      3. Protected against CSRF.
    """
    target_user = db.get_or_404(User, user_id)
    new_role = request.form.get('role', '').strip()

    if new_role not in ['Admin', 'User']:
        flash("Invalid role specified. Permitted roles: 'Admin' or 'User'.", "error")
        return redirect(url_for('admin.users'))

    # Safeguard: Prevent demoting the last active administrator
    if target_user.is_admin and new_role != 'Admin' and target_user.is_active:
        active_admin_count = User.query.filter(
            func.lower(User.role) == 'admin',
            User.is_active == True
        ).count()
        if active_admin_count <= 1:
            flash("Security Policy Violation: Cannot remove administrative privileges from the last active administrator.", "error")
            return redirect(url_for('admin.users'))

    old_role = target_user.role
    target_user.role = new_role
    db.session.commit()

    record_audit_event(
        current_user.id,
        "Role modification",
        {
            "target_user_id": target_user.id,
            "target_username": target_user.username,
            "old_role": old_role,
            "new_role": new_role
        },
        request.remote_addr
    )

    flash(f"Role for user '{target_user.username}' successfully changed to {new_role}.", "success")
    return redirect(url_for('admin.users'))
