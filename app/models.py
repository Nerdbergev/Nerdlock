from datetime import datetime

from flask_security import RoleMixin, UserMixin

from .extensions import db

roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)


class Role(db.Model, RoleMixin):
    """Represents a user role for authorization.

    Roles are used to control access to different parts of the application
    and different door actions.
    """

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    """Represents a user in the system.

    Users can authenticate via password or WebAuthn credentials.
    Access permissions are controlled through roles.
    """

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean(), default=True)
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False)
    confirmed_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(64))
    current_login_ip = db.Column(db.String(64))
    login_count = db.Column(db.Integer, default=0)

    # Rollen
    roles = db.relationship(
        "Role",
        secondary=roles_users,
        backref=db.backref("users", lazy="dynamic"),
    )

    def __repr__(self) -> str:
        """Return string representation of user."""
        return f"<User {self.email or self.username}>"


class WebAuthnCredential(db.Model):
    """Stores WebAuthn/Passkey credentials for passwordless authentication.

    Each credential is associated with a user and contains the public key
    and metadata needed for WebAuthn authentication.
    """

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    credential_id = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    transports = db.Column(db.String(80))
    name = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref="webauthn_credentials")


class DoorAccessLog(db.Model):
    """Log aller Tür-Zugriffe"""

    __tablename__ = "door_access_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    door_location = db.Column(db.String(50), nullable=False, index=True)
    door_name = db.Column(db.String(100), nullable=False)

    action = db.Column(db.String(20), nullable=False)
    success = db.Column(db.Boolean, nullable=False, index=True)
    message = db.Column(db.String(500))

    user_roles = db.Column(db.String(255))

    ip_address = db.Column(db.String(64))

    user = db.relationship("User", backref=db.backref("door_access_logs", lazy="dynamic"))

    def __repr__(self) -> str:
        """Return string representation of log entry."""
        return f"""<DoorAccessLog {self.timestamp} {self.user.username}
            {self.action} {self.door_location}>"""

    @classmethod
    def log_access(
        cls,
        user,
        door_location: str,
        door_name: str,
        action: str,
        success: bool,
        message: str,
        ip_address: str = None,
    ):
        """Create a new door access log entry.

        Args:
            user: User who performed the action
            door_location: Location identifier of the door
            door_name: Display name of the door
            action: Action performed (unlock, lock, unlatch)
            success: Whether the action succeeded
            message: Result message or error description
            ip_address: Optional IP address of the request

        Returns:
            The created DoorAccessLog instance
        """
        user_roles_str = ",".join([r.name for r in user.roles]) if user.roles else ""

        log_entry = cls(
            user_id=user.id,
            door_location=door_location,
            door_name=door_name,
            action=action,
            success=success,
            message=message,
            user_roles=user_roles_str,
            ip_address=ip_address,
        )
        db.session.add(log_entry)
        db.session.commit()
        return log_entry
