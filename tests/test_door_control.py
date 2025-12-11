from app.door_control import (
    DoorAction,
    DoorLocation,
    DoorStatus,
    check_permission,
    door_controller,
)
from app.models import Role


def test_check_permission_admin_unlock():
    roles = [Role(name="admin")]
    has_perm, error = check_permission(roles, DoorLocation.BUILDING, DoorAction.UNLOCK)
    assert has_perm is True
    assert error is None


def test_check_permission_no_role_unlock():
    roles = []
    has_perm, error = check_permission(roles, DoorLocation.BUILDING, DoorAction.UNLOCK)
    assert has_perm is False


def test_check_permission_admin_unlatch():
    roles = [Role(name="admin")]
    has_perm, error = check_permission(roles, DoorLocation.BUILDING, DoorAction.UNLATCH)
    assert has_perm is True


def test_door_controller_unlock():
    door_controller._status[DoorLocation.BUILDING] = DoorStatus.LOCKED
    success, message = door_controller.execute_action(DoorLocation.BUILDING, DoorAction.UNLOCK)
    assert success is True
    assert door_controller._status[DoorLocation.BUILDING] == DoorStatus.UNLOCKED


def test_door_controller_lock():
    door_controller._status[DoorLocation.BUILDING] = DoorStatus.UNLOCKED
    success, message = door_controller.execute_action(DoorLocation.BUILDING, DoorAction.LOCK)
    assert success is True
    assert door_controller._status[DoorLocation.BUILDING] == DoorStatus.LOCKED


def test_door_controller_unlatch():
    door_controller._status[DoorLocation.BUILDING] = DoorStatus.UNLOCKED
    success, message = door_controller.execute_action(DoorLocation.BUILDING, DoorAction.UNLATCH)
    assert success is True
    assert door_controller._status[DoorLocation.BUILDING] == DoorStatus.UNLOCKED


def test_door_controller_cannot_unlock_twice():
    door_controller._status[DoorLocation.BUILDING] = DoorStatus.UNLOCKED
    success, message = door_controller.execute_action(DoorLocation.BUILDING, DoorAction.UNLOCK)
    assert success is False


def test_door_controller_cannot_lock_twice():
    door_controller._status[DoorLocation.BUILDING] = DoorStatus.LOCKED
    success, message = door_controller.execute_action(DoorLocation.BUILDING, DoorAction.LOCK)
    assert success is False


def test_door_controller_get_status():
    door_controller._status[DoorLocation.BUILDING] = DoorStatus.LOCKED
    status = door_controller.get_status(DoorLocation.BUILDING)
    assert status == DoorStatus.LOCKED
