from app.door_control import (
    DoorAction,
    DoorLocation,
    DoorStatus,
    door_controller,
)


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
