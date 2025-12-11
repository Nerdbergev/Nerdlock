# app/doors/__init__.py
from flask import Blueprint

doors_bp = Blueprint("doors", __name__)

from . import routes  # noqa: F401,E402
