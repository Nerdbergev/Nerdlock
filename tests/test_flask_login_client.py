from flask_login import FlaskLoginClient

from app.extensions import db
from app.models import User


def test_flask_login_client_with_user(app, admin_user):
    app.test_client_class = FlaskLoginClient

    with app.app_context():
        user = db.session.get(User, admin_user)

        with app.test_client(user=user) as client:
            response = client.get("/doors/")
            assert response.status_code == 200

            response = client.get("/profile/")
            assert response.status_code == 200


def test_flask_login_client_admin_access(app, admin_user):
    app.test_client_class = FlaskLoginClient

    with app.app_context():
        user = db.session.get(User, admin_user)

        with app.test_client(user=user) as client:
            response = client.get("/admin/")
            assert response.status_code == 200


def test_flask_login_client_fresh_login(app, admin_user):
    app.test_client_class = FlaskLoginClient

    with app.app_context():
        user = db.session.get(User, admin_user)

        with app.test_client(user=user, fresh_login=True) as client:
            response = client.get("/profile/")
            assert response.status_code == 200


def test_flask_login_client_non_fresh_login(app, admin_user):
    app.test_client_class = FlaskLoginClient

    with app.app_context():
        user = db.session.get(User, admin_user)

        with app.test_client(user=user, fresh_login=False) as client:
            response = client.get("/doors/")
            assert response.status_code == 200


def test_flask_login_client_multiple_users(app, admin_user):
    app.test_client_class = FlaskLoginClient

    with app.app_context():
        admin = db.session.get(User, admin_user)

        with app.test_client(user=admin) as admin_client:
            response = admin_client.get("/admin/")
            assert response.status_code == 200

        with app.test_client(user=admin) as second_client:
            response = second_client.get("/doors/")
            assert response.status_code == 200
