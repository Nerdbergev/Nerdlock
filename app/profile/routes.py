from flask import flash, redirect, render_template, request, url_for
from flask_security import auth_required, current_user

from . import profile_bp
from .services import ProfileService


@profile_bp.route("/")
@auth_required()
def index():
    """User profile dashboard.

    Shows profile statistics including passkey and access counts.

    Returns:
        Rendered profile/index.html template
    """
    stats = ProfileService.get_profile_stats(current_user)

    return render_template(
        "profile/index.html",
        passkey_count=stats["passkey_count"],
        access_count=stats["access_count"],
    )


@profile_bp.route("/change-email", methods=["POST"])
@auth_required()
def change_email():
    """Change user's email address.

    Requires password verification.

    Returns:
        Redirect to profile index
    """
    new_email = request.form.get("new_email", "").strip()
    password = request.form.get("password", "")

    success, message = ProfileService.change_email(current_user, new_email, password)
    flash(message, "success" if success else "error")
    return redirect(url_for("profile.index"))


@profile_bp.route("/change-username", methods=["POST"])
@auth_required()
def change_username():
    """Change user's username.

    Returns:
        Redirect to profile index
    """
    new_username = request.form.get("new_username", "").strip() or None

    success, message = ProfileService.change_username(current_user, new_username)
    flash(message, "success" if success else "error")
    return redirect(url_for("profile.index"))
