"""Application configuration.

Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
print(BASE_DIR)


class Config:
    """Base configuration class.

    All settings are loaded from environment variables.
    Includes database, security, mail, and Nuki device configuration.
    """

    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'nerdlock.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT", "dev-salt")
    SECURITY_REGISTERABLE = False
    SECURITY_SEND_REGISTER_EMAIL = False
    SECURITY_RECOVERABLE = False
    SECURITY_TRACKABLE = True
    SECURITY_CONFIRMABLE = False
    SECURITY_CHANGEABLE = True
    SECURITY_USERNAME_ENABLE = True
    SECURITY_TWO_FACTOR = False
    SECURITY_UNIFIED_SIGNIN = False

    WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Nerdlock Hackspace")
    WEBAUTHN_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:5000")

    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = bool(int(os.environ.get("MAIL_USE_TLS", "1")))
    MAIL_USE_SSL = bool(int(os.environ.get("MAIL_USE_SSL", "0")))
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "")

    NUKI_BUILDING_ENABLED = bool(int(os.environ.get("NUKI_BUILDING_ENABLED", "0")))
    NUKI_BUILDING_MAC = os.environ.get("NUKI_BUILDING_MAC", "")
    NUKI_BUILDING_UNLATCH = bool(int(os.environ.get("NUKI_BUILDING_UNLATCH", "1")))

    NUKI_HACKSPACE_ENABLED = bool(int(os.environ.get("NUKI_HACKSPACE_ENABLED", "0")))
    NUKI_HACKSPACE_MAC = os.environ.get("NUKI_HACKSPACE_MAC", "")
    NUKI_HACKSPACE_UNLATCH = bool(int(os.environ.get("NUKI_HACKSPACE_UNLATCH", "1")))

    NUKI_APP_ID = int(os.environ.get("NUKI_APP_ID", "355740770"))
    NUKI_NAME = os.environ.get("NUKI_NAME", "Nerdlock")
    NUKI_CHECK_INTERVAL = int(os.environ.get("NUKI_CHECK_INTERVAL", "900"))

    def __init__(self):
        if not self.SECRET_KEY:
            print("Warning: SECRET_KEY is not set! Using default insecure key.")
            self.SECRET_KEY = "insecure-default-key"

        pass


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "testing-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SESSION_PROTECTION = None
    WTF_CSRF_ENABLED = False
    LOGIN_DISABLED = False
