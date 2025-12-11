"""WSGI entry point for production deployment.

Used by gunicorn or other WSGI servers.
"""

from app import create_app

app = create_app()
