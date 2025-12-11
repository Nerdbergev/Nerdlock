"""Pytest fixtures for testing.

Provides fixtures for app, database, test clients, and test users.
"""

import os
import sys

import pytest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app  # noqa: E402
from app.config import TestingConfig  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import Role, User  # noqa: E402


@pytest.fixture()
def app():
    """Create and configure a test application instance.

    Sets up test database with basic roles.

    Yields:
        Flask application configured for testing
    """
    app = create_app(TestingConfig)

    with app.app_context():
        db.create_all()

        admin_role = Role(name="admin", description="Administrator")

        db.session.add(admin_role)
        db.session.commit()

        yield app

        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    """Standard test client without authentication.

    Returns:
        Flask test client
    """
    return app.test_client()


@pytest.fixture()
def authenticated_client(app, admin_user):
    """Test client with admin user pre-authenticated.

    Uses login form to authenticate.

    Yields:
        Flask test client with active session
    """
    client = app.test_client()
    with client:
        # Login via POST to /login
        client.post(
            "/login",
            data={"email": "admin@test.com", "password": "adminpass"},
            follow_redirects=True,
        )
        yield client


@pytest.fixture()
def admin_user(app):
    """Create a test admin user.

    Returns user_id instead of User object to avoid DetachedInstanceError.
    Load user in tests with: db.session.get(User, admin_user)

    Returns:
        User ID (int)
    """
    import uuid

    from flask_security.utils import hash_password

    with app.app_context():
        admin_role = Role.query.filter_by(name="admin").first()
        user = User(
            email="admin@test.com",
            username="admin",
            password=hash_password("adminpass"),
            active=True,
            fs_uniquifier=str(uuid.uuid4()),
            roles=[admin_role],
        )
        db.session.add(user)
        db.session.commit()
        # IMPORTANT: Return the user_id, not the user object
        # to avoid DetachedInstanceError
        user_id = user.id

    # Return a function that fetches the user within an app_context
    return user_id
