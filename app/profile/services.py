from __future__ import annotations

from flask_security.utils import verify_password

from app.extensions import db
from app.models import DoorAccessLog, User


class ProfileService:
    """Service for user profile management.

    Handles profile statistics, email changes, and username updates.
    """

    @staticmethod
    def get_profile_stats(user: User) -> dict:
        """Get statistics for user profile.

        Args:
            user: User to get stats for

        Returns:
            Dictionary with passkey_count and access_count
        """
        passkey_count = len(user.webauthn_credentials)
        access_count = DoorAccessLog.query.filter_by(user_id=user.id).count()

        return {"passkey_count": passkey_count, "access_count": access_count}

    @staticmethod
    def change_email(user: User, new_email: str, password: str) -> tuple[bool, str]:
        """Change user's email address with password verification.

        Args:
            user: User to update
            new_email: New email address
            password: Current password for verification

        Returns:
            Tuple of (success: bool, message: str)
        """
        if not new_email or not password:
            return False, "E-Mail und Passwort erforderlich"

        if not verify_password(password, user.password):
            return False, "Falsches Passwort"

        existing = User.query.filter_by(email=new_email).first()
        if existing and existing.id != user.id:
            return False, "E-Mail-Adresse bereits vergeben"

        user.email = new_email
        db.session.commit()

        return True, "E-Mail-Adresse erfolgreich geändert"

    @staticmethod
    def change_username(user: User, new_username: str | None) -> tuple[bool, str]:
        """Change user's username.

        Args:
            user: User to update
            new_username: New username or None to remove

        Returns:
            Tuple of (success: bool, message: str)
        """
        if new_username:
            existing = User.query.filter_by(username=new_username).first()
            if existing and existing.id != user.id:
                return False, "Username bereits vergeben"

        user.username = new_username
        db.session.commit()

        return True, "Username erfolgreich geändert"
