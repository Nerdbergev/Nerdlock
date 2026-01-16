import threading

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_security import auth_required, current_user

from app.door_control import (
    DoorAction,
    DoorLocation,
    door_controller,
    get_all_doors,
    warmup_nuki_devices,
)
from app.models import DoorAccessLog

from . import doors_bp
from .services import DoorLogService, DoorService


@doors_bp.route("/")
@auth_required()
def index():
    """Door control dashboard.

    Shows all doors with their status and recent activity.

    Returns:
        Rendered doors/index.html template
    """
    from pathlib import Path

    from flask import current_app

    from app.nuki_control import get_nuki_device

    doors = get_all_doors()

    door_statuses = {}
    for location, info in doors.items():
        status_dict = {
            "info": info,
            "status": door_controller.get_status(location).value,
        }

        # Add battery info if Nuki is enabled
        if info.use_nuki and info.nuki_mac:
            try:
                config_dir = Path(current_app.instance_path)
                nuki = get_nuki_device(config_dir)
                battery = nuki.get_battery_state(info.nuki_mac)
                status_dict["battery"] = battery
            except Exception as e:
                current_app.logger.debug(f"Could not get battery for {location.value}: {e}")
                status_dict["battery"] = {"critical": False, "percentage": None, "timestamp": None}
        else:
            status_dict["battery"] = {"critical": False, "percentage": None, "timestamp": None}

        door_statuses[location.value] = status_dict

    recent_logs = (
        DoorAccessLog.query.filter_by(user_id=current_user.id)
        .order_by(DoorAccessLog.timestamp.desc())
        .limit(10)
        .all()
    )

    # Start Nuki warmup in background thread
    warmup_thread = threading.Thread(target=warmup_nuki_devices, daemon=True)
    warmup_thread.start()

    return render_template("doors/index.html", door_statuses=door_statuses, recent_logs=recent_logs)


@doors_bp.route("/action", methods=["POST"])
@auth_required()
def perform_action():
    """Execute a door action.

    Supports both single door and bulk (all doors) actions.
    Accepts JSON or form data.

    Returns:
        JSON response or redirect depending on request format
    """
    data = request.get_json() if request.is_json else request.form

    door_str = data.get("door")
    action_str = data.get("action")

    if door_str == "all":
        try:
            action = DoorAction(action_str)
        except ValueError:
            return (
                jsonify({"success": False, "message": "Ungültige Aktion"}),
                400,
            )

        success, message, results = DoorService.perform_bulk_action(current_user, action)

        return jsonify({"success": success, "message": message, "results": results})

    if not door_str or not action_str:
        return jsonify({"success": False, "message": "Fehlende Parameter"}), 400

    try:
        door = DoorLocation(door_str)
        action = DoorAction(action_str)
    except ValueError:
        return (
            jsonify({"success": False, "message": "Ungültige Tür oder Aktion"}),
            400,
        )

    success, message, status = DoorService.perform_door_action(current_user, door, action)

    if request.is_json:
        return jsonify({"success": success, "message": message, "status": status})
    else:
        flash(message, "success" if success else "error")
        return redirect(url_for("doors.index"))


@doors_bp.route("/logs")
@auth_required()
def logs():
    """View door access logs.

    Supports filtering by door and action type.

    Returns:
        Rendered doors/logs.html template with paginated logs
    """
    page = request.args.get("page", 1, type=int)
    per_page = 50

    door_filter = request.args.get("door")
    action_filter = request.args.get("action")

    logs_paginated = DoorLogService.get_logs(
        current_user, page, per_page, door_filter, action_filter
    )

    return render_template(
        "doors/logs.html",
        logs=logs_paginated.items,
        pagination=logs_paginated,
        door_filter=door_filter,
        action_filter=action_filter,
    )


@doors_bp.route("/status/<door_location>")
@auth_required()
def door_status(door_location: str):
    """Get current status of a specific door.

    Args:
        door_location: Door location identifier

    Returns:
        JSON response with door status
    """
    try:
        door = DoorLocation(door_location)
        result = DoorService.get_door_status(door)
        return jsonify(result)
    except ValueError:
        return jsonify({"success": False, "message": "Ungültige Tür"}), 404
