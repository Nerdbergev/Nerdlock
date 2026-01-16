"""Background service for periodic Nuki device status updates.

Runs in a separate thread to keep battery and lock state information current.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path

from flask import Flask

logger = logging.getLogger(__name__)


class NukiStatusUpdater:
    """Background service for updating Nuki device status.

    Periodically polls configured Nuki devices to update battery
    and lock state information.
    """

    def __init__(self, app: Flask):
        self.app = app
        self.running = False
        self.thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self):
        """Start the background updater thread.

        Only starts if Nuki devices are configured.
        """
        if self.running:
            logger.warning("NukiStatusUpdater already running")
            return

        from app.door_control import DOORS

        has_nuki = any(door.use_nuki for door in DOORS.values())

        if not has_nuki:
            logger.info("No Nuki devices enabled")
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_background, daemon=True)
        self.thread.start()
        logger.info("NukiStatusUpdater started")

    def stop(self):
        """Stop the background updater thread gracefully."""
        if not self.running:
            return

        self.running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

        if self.thread:
            self.thread.join(timeout=5)
        logger.info("NukiStatusUpdater stopped")

    def _run_background(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._update_loop())
        except Exception as e:
            logger.error(f"NukiStatusUpdater crashed: {e}")
        finally:
            self._loop.close()

    async def _update_loop(self):
        from app.door_control import DOORS
        from app.nuki_control import get_nuki_device

        config_dir = Path(self.app.instance_path)
        nuki = get_nuki_device(config_dir)

        app_id = self.app.config["NUKI_APP_ID"]
        name = self.app.config["NUKI_NAME"]
        interval = self.app.config["NUKI_CHECK_INTERVAL"]

        nuki_doors = []
        for door_info in DOORS.values():
            if door_info.use_nuki and door_info.nuki_mac:
                if not nuki.is_paired(door_info.nuki_mac):
                    logger.error(f"Nuki {door_info.nuki_mac} not paired - run pairing script first")
                else:
                    nuki_doors.append(
                        {
                            "location": door_info.location.value,
                            "mac": door_info.nuki_mac,
                            "name": door_info.name,
                        }
                    )

        if not nuki_doors:
            logger.warning("No Nuki doors configured or paired")
            return

        logger.info(f"Starting Nuki status updates every {interval}s for {len(nuki_doors)} door(s)")

        while self.running:
            for door_info in nuki_doors:
                if not self.running:
                    break

                try:
                    logger.debug(
                        f"[UPDATER DEBUG] Starting update for {door_info['name']} "
                        f"({door_info['mac']})"
                    )
                    await nuki.update_status(door_info["mac"], app_id, name)
                    lock_state = nuki.get_lock_state(door_info["mac"])
                    battery = nuki.get_battery_state(door_info["mac"])

                    if battery and battery.get("percentage") is not None:
                        battery_info = f"{battery['percentage']}%"
                        if battery.get("critical"):
                            battery_info += " (CRITICAL!)"
                    elif battery and battery.get("critical"):
                        battery_info = "CRITICAL"
                    else:
                        battery_info = "OK"

                    logger.info(
                        f"Nuki {door_info['name']} ({door_info['mac']}): {lock_state}, "
                        f"Battery: {battery_info}"
                    )
                except Exception as e:
                    logger.error(f"Failed to update Nuki {door_info['name']}: {e}")
                    logger.error(
                        f"[UPDATER DEBUG] Exception type: {type(e).__name__}, details: {e}",
                        exc_info=True,
                    )

            for _ in range(interval):
                if not self.running:
                    break
                await asyncio.sleep(1)

        logger.info("Nuki update loop ended")


_updater: NukiStatusUpdater | None = None


def init_nuki_updater(app: Flask):
    """Initialize and start the Nuki status updater.

    Called during application startup.

    Args:
        app: Flask application instance
    """
    global _updater
    if _updater is None:
        _updater = NukiStatusUpdater(app)
        _updater.start()


def get_nuki_updater() -> NukiStatusUpdater | None:
    """Get the active Nuki updater instance.

    Returns:
        NukiStatusUpdater instance or None if not initialized
    """
    return _updater
