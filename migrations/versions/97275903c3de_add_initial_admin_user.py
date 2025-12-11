"""Add initial admin user

Revision ID: 97275903c3de
Revises: a22ad05257ce
Create Date: 2025-12-11 16:14:01.095332

"""

import uuid
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from flask_security.utils import hash_password

# revision identifiers, used by Alembic.
revision = "97275903c3de"
down_revision = "a22ad05257ce"
branch_labels = None
depends_on = None


def upgrade():
    # Create tables references
    role_table = sa.table(
        "role",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
    )

    user_table = sa.table(
        "user",
        sa.column("id", sa.Integer),
        sa.column("email", sa.String),
        sa.column("username", sa.String),
        sa.column("password", sa.String),
        sa.column("active", sa.Boolean),
        sa.column("fs_uniquifier", sa.String),
        sa.column("confirmed_at", sa.DateTime),
    )

    roles_users_table = sa.table(
        "roles_users", sa.column("user_id", sa.Integer), sa.column("role_id", sa.Integer)
    )

    # Create admin role
    op.bulk_insert(
        role_table, [{"id": 1, "name": "admin", "description": "Administrator with full access"}]
    )

    # Create admin user with password 'changeme'
    password_hash = hash_password("changeme")
    fs_uniquifier = str(uuid.uuid4())

    op.bulk_insert(
        user_table,
        [
            {
                "id": 1,
                "email": "admin@nerdberg.de",
                "username": "admin",
                "password": password_hash,
                "active": True,
                "fs_uniquifier": fs_uniquifier,
                "confirmed_at": datetime.utcnow(),
            }
        ],
    )

    # Assign admin role to admin user
    op.bulk_insert(roles_users_table, [{"user_id": 1, "role_id": 1}])


def downgrade():
    # Remove role assignments
    op.execute("DELETE FROM roles_users WHERE user_id = 1 AND role_id = 1")

    # Remove admin user
    op.execute("DELETE FROM user WHERE id = 1")

    # Remove admin role
    op.execute("DELETE FROM role WHERE id = 1")
