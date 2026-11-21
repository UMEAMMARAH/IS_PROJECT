"""
SecureVault - Audit Logging Integration Interface
Member 1 <-> Member 3 Integration Bridge

Member 3 is responsible for the full enterprise audit logging module,
tamper-evident log verification, and export capabilities.

This module provides the standard integration hook `record_audit_event`
so authentication, RBAC, and admin actions can trigger audit events safely
without coupling directly to Member 3's underlying storage architecture.

CRITICAL SECURITY RULE:
Never pass plaintext passwords, password hashes, secret keys, or raw session
tokens into the `details` dictionary.
"""

import logging
import os
from datetime import datetime, timezone

# Configure a dedicated audit logger
audit_logger = logging.getLogger("SecureVaultAudit")
if not audit_logger.handlers:
    audit_logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[SECUREVAULT-AUDIT] %(asctime)s | User: %(user_id)s | Action: %(action)s | IP: %(ip)s | Details: %(details)s"
    )
    console_handler.setFormatter(formatter)
    audit_logger.addHandler(console_handler)

    # Optionally log to a secure audit log file if desired
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database")
    os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.FileHandler(os.path.join(log_dir, "audit_events.log"), encoding="utf-8")
    file_handler.setFormatter(formatter)
    audit_logger.addHandler(file_handler)


def record_audit_event(user_id, action, details=None, ip_address="N/A"):
    """
    Standard interface to record security-sensitive events.

    :param user_id: ID or username of the actor performing the action (or None for unauthenticated actions)
    :param action: High-level event identifier (e.g., 'Successful login', 'Failed login', 'Password change')
    :param details: Dictionary or string containing contextual metadata (NO PASSWORDS/HASHES!)
    :param ip_address: Remote client IP address
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    actor = str(user_id) if user_id is not None else "ANONYMOUS"

    # Sanitization check: Ensure no sensitive keys exist in details dict
    clean_details = {}
    if isinstance(details, dict):
        forbidden_keys = {"password", "password_hash", "confirm_password", "token", "secret", "csrf_token"}
        for k, v in details.items():
            if any(forbidden in k.lower() for forbidden in forbidden_keys):
                clean_details[k] = "[REDACTED]"
            else:
                clean_details[k] = v
    elif details is not None:
        clean_details = str(details)
    else:
        clean_details = "None"

    # Log to audit stream
    extra = {
        "user_id": actor,
        "action": action,
        "ip": ip_address,
        "details": str(clean_details)
    }
    audit_logger.info("", extra=extra)

    # Integration Hook: Persist in SQLite audit_logs table when in application context
    try:
        from flask import has_app_context
        if has_app_context():
            from extensions import db
            from authentication.models import AuditLog
            uid = int(user_id) if (user_id is not None and str(user_id).isdigit()) else None
            entry = AuditLog(
                user_id=uid,
                action=action,
                details=str(clean_details),
                ip_address=ip_address
            )
            db.session.add(entry)
            db.session.commit()
    except Exception as e:
        # Gracefully handle logging without interrupting main transaction
        pass

    return {
        "timestamp": timestamp,
        "user_id": actor,
        "action": action,
        "ip_address": ip_address,
        "details": clean_details,
        "status": "RECORDED"
    }


def get_recent_audit_events(limit=10, user_id=None):
    """
    Retrieve live audit log entries from SQLite for dashboard feed and admin views.
    """
    try:
        from flask import has_app_context
        if not has_app_context():
            return []
        from authentication.models import AuditLog
        query = AuditLog.query
        if user_id is not None:
            query = query.filter((AuditLog.user_id == user_id) | (AuditLog.user_id == None))
        return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    except Exception:
        return []


def get_audit_count(user_id=None):
    """
    Retrieve real count of audit events.
    """
    try:
        from flask import has_app_context
        if not has_app_context():
            return 0
        from authentication.models import AuditLog
        query = AuditLog.query
        if user_id is not None:
            query = query.filter((AuditLog.user_id == user_id) | (AuditLog.user_id == None))
        return query.count()
    except Exception:
        return 0
