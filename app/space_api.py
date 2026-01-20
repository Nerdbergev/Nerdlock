"""Space API integration for sending door status updates.

Sends door status changes to a configured external Space API endpoint.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import requests
from flask import current_app

from app.door_control import DoorLocation, DoorStatus

logger = logging.getLogger(__name__)


def _map_door_status_to_space_status(status: DoorStatus) -> str:
    """Map internal DoorStatus to Space API status format.

    Args:
        status: Internal door status

    Returns:
        Space API status string ("open" or "close")
    """
    if status in (DoorStatus.UNLOCKED, DoorStatus.OPEN):
        return "open"
    else:
        return "close"


def send_door_status_to_space_api(
    door: DoorLocation, status: DoorStatus, timestamp: Optional[datetime] = None
) -> bool:
    """Send door status update to Space API.

    Posts the current door status to the configured Space API endpoint
    in Django REST Framework format.

    Args:
        door: Door location
        status: Current door status
        timestamp: Optional timestamp, defaults to now

    Returns:
        True if successful, False otherwise
    """
    try:
        # Check if Space API is enabled
        if not current_app.config.get("SPACE_API_ENABLED"):
            logger.debug("Space API is disabled, skipping status update")
            return False

        api_url = current_app.config.get("SPACE_API_URL")
        api_token = current_app.config.get("SPACE_API_TOKEN")

        if not api_url or not api_token:
            logger.warning("Space API URL or token not configured")
            return False

        # Prepare timestamp
        if timestamp is None:
            timestamp = datetime.now()

        # Map status
        space_status = _map_door_status_to_space_status(status)

        # Prepare payload
        payload = {"date": timestamp.isoformat(), "status": space_status}

        # Prepare headers
        headers = {"Authorization": f"Token {api_token}", "Content-Type": "application/json"}

        # Ensure URL ends with /doorstatus/ (Django requires trailing slash for POST)
        if not api_url.endswith("/doorstatus/"):
            if api_url.endswith("/doorstatus"):
                api_url = f"{api_url}/"
            elif api_url.endswith("/"):
                api_url = f"{api_url}doorstatus/"
            else:
                api_url = f"{api_url}/doorstatus/"

        # Send POST request
        logger.info(
            f"Sending status update to Space API: door={door.value}, "
            f"status={space_status}, timestamp={timestamp.isoformat()}"
        )

        response = requests.post(api_url, json=payload, headers=headers, timeout=10)

        response.raise_for_status()

        logger.info(
            f"Successfully sent status to Space API: {response.status_code} - "
            f"{response.text[:100]}"
        )
        return True

    except requests.exceptions.Timeout:
        logger.error("Space API request timed out")
        return False
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Space API connection error: {e}")
        return False
    except requests.exceptions.HTTPError as e:
        logger.error(f"Space API HTTP error: {e.response.status_code} - {e.response.text}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending to Space API: {e}")
        return False


def notify_door_status_change(door: DoorLocation, new_status: DoorStatus) -> None:
    """Notify Space API of a door status change.

    This is a convenience function that handles the status update
    in a non-blocking manner (logs errors but doesn't raise exceptions).
    Only sends updates for the configured door (SPACE_API_DOOR).

    Args:
        door: Door location
        new_status: New door status
    """
    try:
        # Check if this door should send updates to Space API
        configured_door = current_app.config.get("SPACE_API_DOOR", "building")
        if door.value != configured_door:
            logger.debug(
                f"Skipping Space API update for {door.value} "
                f"(configured door: {configured_door})"
            )
            return
        onlinestatus = check_online_status()
        if onlinestatus == new_status:
            logger.debug(f"Door status unchanged for Space API ({new_status}), skipping update")
            return
        logger.debug(f"Notifying Space API of door status change: {onlinestatus} -> {new_status}")
        send_door_status_to_space_api(door, new_status)
    except Exception as e:
        logger.error(f"Failed to notify Space API: {e}")


def check_online_status() -> DoorStatus:
    """Check online status from Space API.

    Returns:
        DoorStatus based on Space API response
    """
    try:
        api_url = current_app.config.get("SPACE_API_URL") + "doorstatus/"
        if not api_url:
            logger.warning("Space API URL not configured")
            return DoorStatus.ERROR

        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        # We get a json array and have to return first status field of array

        json_data = response.json()
        if isinstance(json_data["results"], list) and len(json_data["results"]) > 0:
            status = json_data["results"][0].get("status", "unknown")
            if status == "open":
                return DoorStatus.UNLOCKED
            elif status == "close":
                return DoorStatus.LOCKED
        return DoorStatus.ERROR

    except requests.exceptions.RequestException as e:
        logger.error(f"Space API request error: {e}")
        return DoorStatus.ERROR
