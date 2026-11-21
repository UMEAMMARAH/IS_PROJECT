import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from sqlalchemy import func
from authentication.models import User


def validate_password_strength(form, field):
    """
    Validate that password meets enterprise security criteria:
      - Minimum 8 characters
      - At least one uppercase letter (A-Z)
      - At least one lowercase letter (a-z)
      - At least one digit (0-9)
      - At least one special symbol (!@#$%^&*...)
    """
    password = field.data or ""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters in length.")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain at least one numeric digit.")
    if not re.search(r"[\W_]", password):
        raise ValidationError("Password must contain at least one special character.")


class RegistrationForm(FlaskForm):
    """
    User registration form with strict input validation.
    CRITICAL: Does NOT contain a role selection field.
    All public registrations automatically receive 'User' role in the backend.
    """
    full_name = StringField(
        'Full Name',
        validators=[
            DataRequired(message="Full name is required."),
            Length(min=2, max=100, message="Full name must be between 2 and 100 characters.")
        ]
    )
    username = StringField(
        'Username',
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
            Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username may only contain letters, numbers, underscores, periods, and hyphens.")
        ]
    )
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message="Email address is required."),
            Email(message="Please enter a valid email address."),
            Length(max=120)
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters."),
            validate_password_strength
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo('password', message="Passwords do not match.")
        ]
    )
    submit = SubmitField('Create Secure Account')

    def validate_username(self, field):
        """Ensure username is unique (case-insensitive)."""
        existing = User.query.filter(func.lower(User.username) == func.lower(field.data.strip())).first()
        if existing:
            raise ValidationError("This username is already taken. Please choose another.")

    def validate_email(self, field):
        """Ensure email is unique (case-insensitive)."""
        existing = User.query.filter(func.lower(User.email) == func.lower(field.data.strip())).first()
        if existing:
            raise ValidationError("An account with this email address already exists.")


class LoginForm(FlaskForm):
    """
    User authentication form.
    Includes CSRF protection, email validation, and Remember Me support.
    """
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Please enter a valid email address.")
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required.")
        ]
    )
    remember_me = BooleanField('Keep me signed in for 7 days')
    submit = SubmitField('Sign In')


class ProfileUpdateForm(FlaskForm):
    """
    User profile update form.
    Allows changing display name.
    Does NOT allow tampering with role or email/username here.
    """
    full_name = StringField(
        'Full Name',
        validators=[
            DataRequired(message="Full name is required."),
            Length(min=2, max=100, message="Full name must be between 2 and 100 characters.")
        ]
    )
    submit = SubmitField('Update Profile')


class PasswordChangeForm(FlaskForm):
    """
    Password change form requiring current password verification.
    """
    current_password = PasswordField(
        'Current Password',
        validators=[
            DataRequired(message="Current password is required.")
        ]
    )
    new_password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message="New password is required."),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters."),
            validate_password_strength
        ]
    )
    confirm_new_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message="Please confirm your new password."),
            EqualTo('new_password', message="New passwords do not match.")
        ]
    )
    submit = SubmitField('Change Password')
