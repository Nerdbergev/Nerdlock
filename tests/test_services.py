import pytest

from app.admin.services import RoleService, UserService
from app.models import Role, User


def test_create_user_without_admin(app):
    with app.app_context():
        user, password = UserService.create_user("test@example.com", "testuser", is_admin=False)

        assert user is not None
        assert user.email == "test@example.com"
        assert user.username == "testuser"
        assert len(password) > 0
        assert not any(role.name == "admin" for role in user.roles)


def test_create_user_with_admin(app):
    with app.app_context():
        user, password = UserService.create_user("admin2@example.com", "admin2", is_admin=True)

        assert user is not None
        assert any(role.name == "admin" for role in user.roles)


def test_create_duplicate_user(app):
    with app.app_context():
        UserService.create_user("duplicate@example.com", "dup1", is_admin=False)

        with pytest.raises(ValueError):
            UserService.create_user("duplicate@example.com", "dup2", is_admin=False)


def test_delete_user(app, member_user, admin_user):
    with app.app_context():
        member = User.query.filter_by(email="member@test.com").first()
        admin = User.query.filter_by(email="admin@test.com").first()

        success, message = UserService.delete_user(member.id, admin.id)

        assert success is True
        assert User.query.filter_by(id=member.id).first() is None


def test_cannot_delete_self(app, admin_user):
    with app.app_context():
        admin = User.query.filter_by(email="admin@test.com").first()

        success, message = UserService.delete_user(admin.id, admin.id)

        assert success is False


def test_update_user_roles(app, member_user):
    with app.app_context():
        member = User.query.filter_by(email="member@test.com").first()

        success, message = UserService.update_user_roles(
            member.id, ["member", "door_admin"], member.id
        )

        assert success is True
        role_names = [r.name for r in member.roles]
        assert "member" in role_names
        assert "door_admin" in role_names


def test_create_role(app):
    with app.app_context():
        success, message = RoleService.create_role("new_role")

        assert success is True
        role = Role.query.filter_by(name="new_role").first()
        assert role is not None


def test_create_duplicate_role(app):
    with app.app_context():
        RoleService.create_role("test_role")
        success, message = RoleService.create_role("test_role")

        assert success is False


def test_delete_role(app):
    with app.app_context():
        RoleService.create_role("deletable_role")
        success, message = RoleService.delete_role("deletable_role")

        assert success is True
        role = Role.query.filter_by(name="deletable_role").first()
        assert role is None


def test_cannot_delete_admin_role(app):
    with app.app_context():
        success, message = RoleService.delete_role("admin")

        assert success is False
