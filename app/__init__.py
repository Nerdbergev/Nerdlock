"""Nerdlock application factory and initialization.

This module creates and configures the Flask application with all
extensions, blueprints, and Nuki integration.
"""

import logging

from flask import Flask

from .admin import admin_bp
from .auth import auth_bp
from .config import Config
from .doors import doors_bp
from .extensions import SQLAlchemyUserDatastore, db, login_manager, mail, security
from .main import main_bp
from .models import Role, User
from .profile import profile_bp

logger = logging.getLogger(__name__)


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application.

    Initializes database, authentication, blueprints, and Nuki devices.

    Args:
        config_class: Configuration class to use

    Returns:
        Configured Flask application instance
    """

    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    global user_datastore
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security.init_app(app, user_datastore)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(doors_bp, url_prefix="/doors")
    app.register_blueprint(profile_bp, url_prefix="/profile")

    from .nuki_updater import init_nuki_updater

    with app.app_context():
        from .door_control import DoorLocation, set_nuki_door

        if app.config.get("NUKI_BUILDING_ENABLED"):
            mac = app.config.get("NUKI_BUILDING_MAC")
            allow_unlatch = app.config.get("NUKI_BUILDING_UNLATCH", True)
            if mac:
                set_nuki_door(DoorLocation.BUILDING, mac, allow_unlatch)
                logger.info(f"Nuki enabled for BUILDING (MAC: {mac}, unlatch: {allow_unlatch})")
            else:
                logger.error("NUKI_BUILDING_ENABLED but no MAC configured")

        if app.config.get("NUKI_HACKSPACE_ENABLED"):
            mac = app.config.get("NUKI_HACKSPACE_MAC")
            allow_unlatch = app.config.get("NUKI_HACKSPACE_UNLATCH", True)
            if mac:
                set_nuki_door(DoorLocation.HACKSPACE, mac, allow_unlatch)
                logger.info(f"Nuki enabled for HACKSPACE (MAC: {mac}, unlatch: {allow_unlatch})")
            else:
                logger.error("NUKI_HACKSPACE_ENABLED but no MAC configured")

        init_nuki_updater(app)

    return app
