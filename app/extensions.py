"""Flask extensions initialization.

Extensions are initialized here and then configured in create_app().
"""

from flask_login import LoginManager
from flask_mail import Mail
from flask_security import Security, SQLAlchemyUserDatastore
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
login_manager = LoginManager()

security = Security()
user_datastore: SQLAlchemyUserDatastore | None = None

mail = Mail()
