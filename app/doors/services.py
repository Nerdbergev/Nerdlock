from __future__ import annotations

from flask import request

from app.door_control import (
    DoorAction,
    DoorLocation,
    door_controller,
    execute_door_action,
    get_door_info,
)
from app.models import DoorAccessLog, User


class DoorService:
    """Service for door control operations.

    Handles door actions (unlock, lock, unlatch) with permission checks
    and logging.
    """

    @staticmethod
    def perform_door_action(
        user: User, door: DoorLocation, action: DoorAction
    ) -> tuple[bool, str, str]:
        """Perform a door action and log it.

        Args:
            user: User performing the action
            door: Door location
            action: Action to perform

        Returns:
            Tuple of (success: bool, message: str, door_status: str)
        """
        success, message = execute_door_action(user.roles, door, action)

        door_info = get_door_info(door)
        DoorAccessLog.log_access(
            user=user,
            door_location=door.value,
            door_name=door_info.name,
            action=action.value,
            success=success,
            message=message,
            ip_address=request.remote_addr,
        )

        status = door_controller.get_status(door).value
        return success, message, status

    @staticmethod
    def perform_bulk_action(user: User, action: DoorAction) -> tuple[bool, str, list[dict]]:
        """Perform action on all doors simultaneously.

        Only unlock and lock actions are allowed for bulk operations.

        Args:
            user: User performing the actions
            action: Action to perform (only UNLOCK or LOCK)

        Returns:
            Tuple of (overall_success: bool, summary_message: str, results: list[dict])
        """
        if action not in [DoorAction.UNLOCK, DoorAction.LOCK]:
            return False, "Nur unlock/lock für alle Türen möglich", []

        results = []
        overall_success = True

        for door_location in DoorLocation:
            success, message = execute_door_action(user.roles, door_location, action)

            door_info = get_door_info(door_location)
            DoorAccessLog.log_access(
                user=user,
                door_location=door_location.value,
                door_name=door_info.name,
                action=action.value,
                success=success,
                message=message,
                ip_address=request.remote_addr,
            )

            results.append({"door": door_info.name, "success": success, "message": message})
            if not success:
                overall_success = False

        summary = "Alle Türen " + (
            "aufgeschlossen" if action == DoorAction.UNLOCK else "abgeschlossen"
        )
        return (
            overall_success,
            summary if overall_success else "Einige Türen konnten nicht gesteuert werden",
            results,
        )

    @staticmethod
    def get_door_status(door: DoorLocation) -> dict:
        """Get current status of a door.

        Args:
            door: Door location

        Returns:
            Dictionary with door status information
        """
        status = door_controller.get_status(door)
        door_info = get_door_info(door)

        return {
            "success": True,
            "door": door.value,
            "name": door_info.name,
            "status": status.value,
        }


class DoorLogService:
    """Service for retrieving door access logs.

    Provides filtered and paginated access to door activity history.
    Admins see all logs, regular users see only their own.
    """

    @staticmethod
    def get_logs(
        user: User,
        page: int,
        per_page: int,
        door_filter: str | None = None,
        action_filter: str | None = None,
    ):
        """Get paginated door access logs with optional filters.

        Admins and vorstand can see all logs, others only their own.

        Args:
            user: User requesting logs
            page: Page number (1-indexed)
            per_page: Items per page
            door_filter: Optional door location filter
            action_filter: Optional action type filter

        Returns:
            Pagination object with filtered logs
        """
        if user.has_role("admin") or user.has_role("vorstand"):
            query = DoorAccessLog.query
        else:
            query = DoorAccessLog.query.filter_by(user_id=user.id)

        if door_filter:
            query = query.filter_by(door_location=door_filter)

        if action_filter:
            query = query.filter_by(action=action_filter)

        logs_paginated = query.order_by(DoorAccessLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return logs_paginated
