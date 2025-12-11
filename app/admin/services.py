from __future__ import annotations

from secrets import token_urlsafe
from typing import Optional

from flask import current_app, url_for
from flask_mail import Message
from flask_security.utils import hash_password

from app.extensions import db, mail
from app.models import Role, User


class UserService:
    """Service for user management operations.

    Handles user creation, deletion, role management, and email notifications.
    """

    @staticmethod
    def get_datastore():
        security_ext = current_app.extensions["security"]
        return security_ext.datastore

    @staticmethod
    def create_user(
        email: str, username: Optional[str] = None, is_admin: bool = False
    ) -> tuple[User, str]:
        """Create a new user with generated password.

        Args:
            email: User's email address
            username: Optional username
            is_admin: Whether to assign admin role

        Returns:
            Tuple of (User object, plaintext password)

        Raises:
            ValueError: If user with email already exists
        """
        ds = UserService.get_datastore()

        if ds.find_user(email=email):
            raise ValueError(f"User mit E-Mail {email} existiert bereits")

        password_plain = token_urlsafe(12)

        roles = []
        if is_admin:
            admin_role = ds.find_or_create_role(name="admin", description="Space Admin")
            roles.append(admin_role)

        user = ds.create_user(
            email=email,
            username=username,
            password=hash_password(password_plain),
            roles=roles,
        )
        db.session.commit()

        return user, password_plain

    @staticmethod
    def send_welcome_email(email: str, password: str) -> bool:
        """Send welcome email with login credentials.

        Args:
            email: Recipient email address
            password: Generated plaintext password

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            login_url = url_for("security.login", _external=True)
            msg = Message(
                subject="Dein Nerdlock-Zugang",
                recipients=[email],
                body=(
                    "Hallo,\n\n"
                    "für Nerdlock wurde ein Account für dich angelegt.\n\n"
                    f"Login-URL: {login_url}\n"
                    f"E-Mail/Username: {email}\n"
                    f"Passwort: {password}\n\n"
                    "Bitte melde dich an und ändere dein Passwort.\n"
                ),
            )
            mail.send(msg)
            return True
        except Exception:
            current_app.logger.exception("Mailversand fehlgeschlagen")
            return False

    @staticmethod
    def delete_user(user_id: int, current_user_id: int) -> tuple[bool, str]:
        """Delete a user with safety checks.

        Prevents deletion of self and last admin.

        Args:
            user_id: ID of user to delete
            current_user_id: ID of user performing the deletion

        Returns:
            Tuple of (success: bool, message: str)
        """
        ds = UserService.get_datastore()
        user = ds.find_user(id=user_id)

        if not user:
            return False, "User nicht gefunden"

        if user.id == current_user_id:
            return False, "Du kannst deinen eigenen Account nicht löschen"

        if any(r.name == "admin" for r in user.roles):
            admin_role = ds.find_role("admin")
            admins_left = (
                User.query.filter(User.roles.any(id=admin_role.id))
                .filter(User.id != user.id)
                .count()
            )
            if admins_left == 0:
                return False, "Letzten Admin kannst du nicht löschen"

        db.session.delete(user)
        db.session.commit()
        return True, "User gelöscht"

    @staticmethod
    def update_user_roles(
        user_id: int, selected_roles: list[str], current_user_id: int
    ) -> tuple[bool, str]:
        """Update user's roles with safety checks.

        Prevents removing admin role from self and last admin.

        Args:
            user_id: ID of user to update
            selected_roles: List of role names to assign
            current_user_id: ID of user performing the update

        Returns:
            Tuple of (success: bool, message: str)
        """
        ds = UserService.get_datastore()
        all_roles = {r.name: r for r in Role.query.all()}

        user = db.session.get(User, user_id)
        if not user:
            return False, "User nicht gefunden"

        current_role_names = {r.name for r in user.roles}

        if user_id == current_user_id and "admin" in current_role_names:
            selected_roles = list(set(selected_roles) | {"admin"})

        for role_name in selected_roles:
            role = all_roles.get(role_name)
            if not role:
                role = ds.find_or_create_role(name=role_name)
                all_roles[role_name] = role
            if role not in user.roles:
                user.roles.append(role)

        for role in list(user.roles):
            if role.name not in selected_roles:
                if role.name == "admin":
                    admins_left = (
                        User.query.filter(User.roles.any(id=role.id))
                        .filter(User.id != user_id)
                        .count()
                    )
                    if admins_left == 0:
                        continue
                    if user_id == current_user_id:
                        continue
                user.roles.remove(role)

        db.session.commit()
        return True, "Rollen aktualisiert"


class RoleService:
    """Service for role management operations.

    Handles creation and deletion of custom roles.
    """

    @staticmethod
    def get_datastore():
        security_ext = current_app.extensions["security"]
        return security_ext.datastore

    @staticmethod
    def create_role(role_name: str) -> tuple[bool, str]:
        """Create a new role.

        Args:
            role_name: Name of the role to create

        Returns:
            Tuple of (success: bool, message: str)
        """
        if not role_name:
            return False, "Rollenname darf nicht leer sein"

        ds = RoleService.get_datastore()
        if ds.find_role(role_name):
            return False, f"Rolle '{role_name}' existiert bereits"

        ds.create_role(name=role_name)
        db.session.commit()
        return True, f"Rolle '{role_name}' angelegt"

    @staticmethod
    def delete_role(role_name: str) -> tuple[bool, str]:
        """Delete a role and remove it from all users.

        Prevents deletion of admin role.

        Args:
            role_name: Name of the role to delete

        Returns:
            Tuple of (success: bool, message: str)
        """
        if not role_name:
            return False, "Rollenname fehlt"

        if role_name == "admin":
            return False, "Systemrolle 'admin' kann nicht gelöscht werden"

        ds = RoleService.get_datastore()
        role = ds.find_role(role_name)
        if not role:
            return False, "Rolle nicht gefunden"

        for u in User.query.filter(User.roles.any(id=role.id)).all():
            u.roles.remove(role)

        db.session.delete(role)
        db.session.commit()
        return True, f"Rolle '{role_name}' gelöscht"
