from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class DoorAction(Enum):
    """Available door actions."""

    UNLOCK = "unlock"
    LOCK = "lock"
    UNLATCH = "unlatch"


class DoorStatus(Enum):
    """Current status of a door."""

    LOCKED = "locked"
    UNLOCKED = "unlocked"
    OPEN = "open"
    ERROR = "error"


class DoorLocation(Enum):
    """Physical door locations."""

    BUILDING = "building"
    HACKSPACE = "hackspace"


@dataclass
class DoorInfo:
    """Configuration and metadata for a door.

    Attributes:
        location: Physical location identifier
        name: Display name of the door
        description: Human-readable description
        unlock_roles: Roles allowed to unlock
        lock_roles: Roles allowed to lock
        unlatch_roles: Roles allowed to unlatch (open without key)
        use_nuki: Whether this door uses Nuki smart lock
        nuki_mac: MAC address of Nuki device
        nuki_allow_unlatch: Whether unlatch is allowed via Nuki
    """

    location: DoorLocation
    name: str
    description: str
    unlock_roles: list[str]
    lock_roles: list[str]
    unlatch_roles: list[str]
    use_nuki: bool = False
    nuki_mac: str = ""
    nuki_allow_unlatch: bool = True


DOORS = {
    DoorLocation.BUILDING: DoorInfo(
        location=DoorLocation.BUILDING,
        name="Gebäudeeingang",
        description="Haupteingang des Gebäudes",
        unlock_roles=["admin"],
        lock_roles=["admin"],
        unlatch_roles=["admin"],
        use_nuki=False,
    ),
    DoorLocation.HACKSPACE: DoorInfo(
        location=DoorLocation.HACKSPACE,
        name="Hackspace-Eingang",
        description="Eingang zum Hackspace",
        unlock_roles=["admin"],
        lock_roles=["admin"],
        unlatch_roles=["admin"],
        use_nuki=False,
    ),
}


def set_nuki_door(location: DoorLocation, mac_address: str, allow_unlatch: bool = True):
    """Configure a door to use Nuki smart lock.

    Args:
        location: Door location to configure
        mac_address: Bluetooth MAC address of Nuki device
        allow_unlatch: Whether to allow unlatch action via Nuki
    """
    DOORS[location].use_nuki = True
    DOORS[location].nuki_mac = mac_address
    DOORS[location].nuki_allow_unlatch = allow_unlatch


class DoorControlMock:
    """Mock door controller for testing and simulation.

    Simulates door state and actions without physical hardware.
    Used when Nuki devices are not configured.
    """

    def __init__(self):
        self._status = {
            DoorLocation.BUILDING: DoorStatus.LOCKED,
            DoorLocation.HACKSPACE: DoorStatus.LOCKED,
        }
        self._delays = {
            DoorAction.UNLOCK: 0.5,
            DoorAction.LOCK: 0.5,
            DoorAction.UNLATCH: 1.0,
        }

    def get_status(self, door: DoorLocation) -> DoorStatus:
        """Get current status of a door.

        Args:
            door: Door location

        Returns:
            Current DoorStatus
        """
        door_info = DOORS.get(door)

        # If using Nuki, get real status
        if door_info and door_info.use_nuki and door_info.nuki_mac:
            try:
                from app.nuki_control import nuki_instance

                if nuki_instance is None:
                    logger.warning(f"Door {door.value}: nuki_instance not initialized yet")
                    return self._status[door]

                nuki_state = nuki_instance.get_lock_state(door_info.nuki_mac)
                logger.info(f"Door {door.value}: Nuki state = {nuki_state}, will map to DoorStatus")

                # Map Nuki state to DoorStatus
                if nuki_state == "LOCKED":
                    logger.info(f"Door {door.value}: Returning LOCKED")
                    return DoorStatus.LOCKED
                elif nuki_state in ("UNLOCKED", "UNLATCHED"):
                    logger.info(f"Door {door.value}: Returning UNLOCKED")
                    return DoorStatus.UNLOCKED
                elif nuki_state == "UNCALIBRATED":
                    logger.warning(f"Door {door.value} is UNCALIBRATED")
                    return DoorStatus.ERROR
                else:
                    logger.warning(f"Unknown Nuki state: {nuki_state}, using cached status")
                    return self._status[door]
            except Exception as e:
                logger.warning(
                    f"Failed to get Nuki status for {door.value}: {e}, using cached status"
                )
                # Fall back to cached status

        logger.info(f"Door {door.value}: Using cached status = {self._status[door]}")
        return self._status[door]

    def execute_action(self, door: DoorLocation, action: DoorAction) -> tuple[bool, str]:
        """Execute an action on a door.

        Args:
            door: Door location
            action: Action to perform

        Returns:
            Tuple of (success: bool, message: str)
        """
        delay = self._delays.get(action, 0.5)
        time.sleep(delay)

        current_status = self._status[door]

        if action == DoorAction.UNLOCK:
            if current_status == DoorStatus.UNLOCKED:
                return False, "Tür ist bereits aufgeschlossen"
            self._status[door] = DoorStatus.UNLOCKED
            return True, "Tür erfolgreich aufgeschlossen"

        elif action == DoorAction.LOCK:
            if current_status == DoorStatus.LOCKED:
                return False, "Tür ist bereits abgeschlossen"
            if current_status == DoorStatus.OPEN:
                return False, "Tür ist noch offen, kann nicht abgeschlossen werden"
            self._status[door] = DoorStatus.LOCKED
            return True, "Tür erfolgreich abgeschlossen"

        elif action == DoorAction.UNLATCH:
            if current_status == DoorStatus.LOCKED:
                return False, "Tür muss zuerst aufgeschlossen werden"
            self._status[door] = DoorStatus.UNLOCKED
            return True, "Falle gezogen"

        return False, "Unbekannte Aktion"

    def reset_door(self, door: DoorLocation):
        """Reset door status if it was left open.

        Args:
            door: Door location to reset
        """
        if self._status[door] == DoorStatus.OPEN:
            self._status[door] = DoorStatus.UNLOCKED


door_controller = DoorControlMock()


def get_door_info(location: DoorLocation) -> DoorInfo:
    """Get configuration info for a door.

    Args:
        location: Door location

    Returns:
        DoorInfo configuration object
    """
    return DOORS[location]


def get_all_doors() -> dict[DoorLocation, DoorInfo]:
    """Get configuration for all doors.

    Returns:
        Dictionary mapping door locations to their configuration
    """
    return DOORS


def check_permission(
    user_roles: list[str], door: DoorLocation, action: DoorAction
) -> tuple[bool, Optional[str]]:
    """Check if user has permission for a door action.

    Args:
        user_roles: List of user's role names
        door: Door location
        action: Requested action

    Returns:
        Tuple of (has_permission: bool, error_message: Optional[str])
    """
    door_info = DOORS[door]

    if action == DoorAction.UNLOCK:
        required_roles = door_info.unlock_roles
    elif action == DoorAction.LOCK:
        required_roles = door_info.lock_roles
    elif action == DoorAction.UNLATCH:
        required_roles = door_info.unlatch_roles
    else:
        return False, "Unbekannte Aktion"

    user_role_names = [role.name if hasattr(role, "name") else str(role) for role in user_roles]
    has_permission = any(role in required_roles for role in user_role_names)

    if not has_permission:
        return False, f"Fehlende Berechtigung. Benötigt: {', '.join(required_roles)}"

    return True, None


def execute_door_action(
    user_roles: list[str], door: DoorLocation, action: DoorAction
) -> tuple[bool, str]:
    """Execute a door action with permission check.

    Handles both Nuki smart locks and mock controller.

    Args:
        user_roles: List of user's role names
        door: Door location
        action: Action to perform

    Returns:
        Tuple of (success: bool, message: str)
    """
    has_perm, error = check_permission(user_roles, door, action)
    if not has_perm:
        return False, error or "Keine Berechtigung"

    door_info = DOORS[door]
    if door_info.use_nuki:
        if action == DoorAction.UNLATCH and not door_info.nuki_allow_unlatch:
            return False, "Unlatch nicht erlaubt für dieses Nuki"

        try:
            from flask import current_app

            from .nuki_control import get_nuki_device

            config_dir = Path(current_app.instance_path)
            nuki = get_nuki_device(config_dir)

            mac_address = door_info.nuki_mac
            app_id = current_app.config["NUKI_APP_ID"]
            name = current_app.config["NUKI_NAME"]

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, message = loop.run_until_complete(
                    nuki.execute_action(mac_address, app_id, name, action.value)
                )

                if success:
                    new_state = nuki.get_lock_state(mac_address)

                    if new_state == "LOCKED":
                        door_controller._status[door] = DoorStatus.LOCKED
                    elif new_state == "UNLOCKED":
                        door_controller._status[door] = DoorStatus.UNLOCKED
                    elif new_state == "UNCALIBRATED":
                        logger.warning(f"Lock {mac_address} is UNCALIBRATED - needs calibration!")
                        door_controller._status[door] = DoorStatus.UNLOCKED
                    else:
                        logger.warning(f"Unknown lock state: {new_state}")

                return success, message
            except Exception as e:
                logger.error(f"Nuki action failed: {e}")
                raise
            finally:
                loop.close()
        except Exception as e:
            return False, f"Nuki-Fehler: {e}"

    return door_controller.execute_action(door, action)
