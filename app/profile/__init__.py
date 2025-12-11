# app/profile/__init__.py
from flask import Blueprint

profile_bp = Blueprint("profile", __name__)

from . import routes  # noqa: F401,E402
