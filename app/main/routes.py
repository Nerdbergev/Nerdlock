from flask import redirect, url_for
from flask_security import auth_required

from . import main_bp


@main_bp.route("/")
@auth_required()
def index():
    """Main entry point.

    Redirects authenticated users to door control dashboard.

    Returns:
        Redirect to doors.index
    """
    return redirect(url_for("doors.index"))
