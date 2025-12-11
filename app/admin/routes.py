from __future__ import annotations

from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_security import current_user, roles_required

from app.models import Role, User

from . import admin_bp
from .services import UserService


@admin_bp.route("/")
@roles_required("admin")
def admin_index():
    """Admin dashboard showing users, roles, and Nuki battery status.

    Returns:
        Rendered admin.html template
    """
    users = User.query.order_by(User.id).all()
    all_roles = Role.query.order_by(Role.name).all()

    nuki_batteries = []
    try:
        from pathlib import Path

        from flask import current_app

        from app.door_control import DOORS
        from app.nuki_control import get_nuki_device

        config_dir = Path(current_app.instance_path)
        nuki = get_nuki_device(config_dir)

        for door_info in DOORS.values():
            if door_info.use_nuki and door_info.nuki_mac:
                battery_state = nuki.get_battery_state(door_info.nuki_mac)

                if battery_state.get("timestamp"):
                    from datetime import datetime

                    ts = datetime.fromisoformat(battery_state["timestamp"])
                    battery_state["timestamp"] = ts.strftime("%d.%m.%Y %H:%M:%S")

                nuki_batteries.append(
                    {
                        "name": door_info.name,
                        "mac": door_info.nuki_mac,
                        "battery": battery_state,
                        "unlatch_allowed": door_info.nuki_allow_unlatch,
                    }
                )
    except Exception:
        pass

    return render_template(
        "admin.html", users=users, all_roles=all_roles, nuki_batteries=nuki_batteries
    )


@admin_bp.route("/users/create", methods=["POST"])
@roles_required("admin")
def create_user():
    """Create a new user with generated password.

    Sends welcome email with credentials.

    Returns:
        Redirect to admin index
    """
    email = request.form.get("email", "").strip()
    username = request.form.get("username", "").strip() or None
    is_admin = bool(request.form.get("is_admin"))

    if not email:
        abort(400, "E-Mail erforderlich")

    try:
        user, password_plain = UserService.create_user(email, username, is_admin)

        if UserService.send_welcome_email(email, password_plain):
            flash(f"User {email} angelegt, Passwort per Mail verschickt.")
        else:
            flash(
                f"User {email} angelegt, aber Mailversand fehlgeschlagen. "
                f"Passwort (nur einmal anzeigen!): {password_plain}"
            )
    except ValueError as e:
        flash(str(e))

    return redirect(url_for("admin.admin_index"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@roles_required("admin")
def delete_user(user_id: int):
    """Delete a user.

    Args:
        user_id: ID of user to delete

    Returns:
        Redirect to admin index
    """
    success, message = UserService.delete_user(user_id, current_user.id)
    flash(message)
    return redirect(url_for("admin.admin_index"))


@admin_bp.route("/users/roles/update", methods=["POST"])
@roles_required("admin")
def update_user_roles():
    """Update roles for all users.

    Processes role assignments for all users in the form.

    Returns:
        Redirect to admin index
    """
    users = User.query.all()
    for u in users:
        field_name = f"roles_{u.id}"
        selected = request.form.getlist(field_name)
        UserService.update_user_roles(u.id, selected, current_user.id)

    flash("Rollen aktualisiert.")
    return redirect(url_for("admin.admin_index"))
