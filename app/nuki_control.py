from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import pyNukiBT
from bleak import BleakScanner
from nacl.public import PrivateKey

logger = logging.getLogger(__name__)


class NukiDevice:
    """Interface for controlling Nuki Smart Locks via Bluetooth.

    Handles pairing, action execution, and status monitoring for Nuki devices.
    Pairing data is persisted to JSON files for reuse.
    """

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.pairing_dir = config_dir / "nuki_pairings"
        self.pairing_dir.mkdir(parents=True, exist_ok=True)
        self.devices: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    def _get_pairing_file(self, mac_address: str) -> Path:
        """Get path to pairing data file for a device.

        Args:
            mac_address: Bluetooth MAC address

        Returns:
            Path to JSON file containing pairing data
        """
        safe_mac = mac_address.replace(":", "_")
        return self.pairing_dir / f"nuki_{safe_mac}.json"

    def load_pairing(
        self, mac_address: str
    ) -> tuple[bytes | None, bytes | None, bytes | None, bytes | None]:
        """Load pairing data for a Nuki device.

        Args:
            mac_address: Bluetooth MAC address

        Returns:
            Tuple of (auth_id, nuki_public_key, bridge_public_key, bridge_private_key)
            or (None, None, None, None) if not paired
        """
        pairing_file = self._get_pairing_file(mac_address)
        if pairing_file.exists():
            try:
                with open(pairing_file, "r") as f:
                    data = json.load(f)
                    return (
                        bytes.fromhex(data["auth_id"]),
                        bytes.fromhex(data["nuki_public_key"]),
                        bytes.fromhex(data["bridge_public_key"]),
                        bytes.fromhex(data["bridge_private_key"]),
                    )
            except Exception as e:
                logger.error(f"Failed to load pairing data for {mac_address}: {e}")
        return None, None, None, None

    def save_pairing(
        self,
        mac_address: str,
        auth_id: bytes,
        nuki_public_key: bytes,
        bridge_public_key: bytes,
        bridge_private_key: bytes,
    ):
        """Save pairing data to persistent storage.

        Args:
            mac_address: Bluetooth MAC address
            auth_id: Authentication ID from pairing
            nuki_public_key: Nuki's public key
            bridge_public_key: Bridge's public key
            bridge_private_key: Bridge's private key
        """
        pairing_file = self._get_pairing_file(mac_address)
        data = {
            "mac_address": mac_address,
            "auth_id": auth_id.hex(),
            "nuki_public_key": nuki_public_key.hex(),
            "bridge_public_key": bridge_public_key.hex(),
            "bridge_private_key": bridge_private_key.hex(),
        }
        with open(pairing_file, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Pairing data saved to {pairing_file}")

    def is_paired(self, mac_address: str) -> bool:
        """Check if device is already paired.

        Args:
            mac_address: Bluetooth MAC address

        Returns:
            True if pairing data exists
        """
        auth_id, _, _, _ = self.load_pairing(mac_address)
        return auth_id is not None

    async def pair(self, mac_address: str, pin: int, app_id: int, name: str) -> bool:
        """Pair with a Nuki device.

        Args:
            mac_address: Bluetooth MAC address of Nuki
            pin: 6-digit PIN from Nuki device
            app_id: Unique app identifier
            name: Name for this bridge connection

        Returns:
            True if pairing successful
        """
        keypair = PrivateKey.generate()
        bridge_public_key = bytes(keypair.public_key)
        bridge_private_key = bytes(keypair)

        n = pyNukiBT.NukiDevice(
            mac_address,
            None,
            None,
            bridge_public_key,
            bridge_private_key,
            app_id,
            name,
        )

        device = await BleakScanner.find_device_by_address(mac_address, timeout=10.0)
        if not device:
            logger.error(f"Device {mac_address} not found")
            return False

        n.set_ble_device(device)
        await n.connect()
        logger.info(f"Connected to Nuki at {mac_address}")

        try:
            await n.pair(pin)
            self.save_pairing(
                mac_address,
                n._auth_id,
                n._nuki_public_key,
                n._bridge_public_key,
                n._bridge_private_key,
            )
            await n.disconnect()
            logger.info("Pairing successful")
            return True
        except pyNukiBT.NukiErrorException as e:
            logger.error(f"Pairing failed: {e}")
            await n.disconnect()
            return False

    async def _get_device(self, mac_address: str, app_id: int, name: str) -> pyNukiBT.NukiDevice:
        """Get connected Nuki device instance.

        Args:
            mac_address: Bluetooth MAC address
            app_id: App identifier
            name: Bridge name

        Returns:
            Connected NukiDevice instance

        Raises:
            ValueError: If not paired with device
            ConnectionError: If device not found
        """
        auth_id, nuki_public_key, bridge_public_key, bridge_private_key = self.load_pairing(
            mac_address
        )
        if not auth_id:
            raise ValueError(f"Not paired with {mac_address} - run pairing first")

        n = pyNukiBT.NukiDevice(
            mac_address,
            auth_id,
            nuki_public_key,
            bridge_public_key,
            bridge_private_key,
            app_id,
            name,
        )

        device = await BleakScanner.find_device_by_address(mac_address, timeout=10.0)
        if not device:
            raise ConnectionError(f"Device {mac_address} not found")

        n.set_ble_device(device)
        await n.connect()
        return n

    async def execute_action(
        self, mac_address: str, app_id: int, name: str, action: str
    ) -> tuple[bool, str]:
        """Execute action on Nuki device.

        Args:
            mac_address: Bluetooth MAC address
            app_id: App identifier
            name: Bridge name
            action: Action to perform (lock, unlock, unlatch)

        Returns:
            Tuple of (success: bool, message: str)
        """
        async with self._lock:
            try:
                n = await self._get_device(mac_address, app_id, name)

                if action == "lock":
                    await n.lock()
                    message = "Verriegelt"
                elif action == "unlock":
                    await n.unlock()
                    message = "Entriegelt"
                elif action == "unlatch":
                    await n.unlatch()
                    message = "Tür geöffnet"
                else:
                    await n.disconnect()
                    return False, f"Unknown action: {action}"

                await asyncio.sleep(1)
                await n.update_state()
                self.last_state = n.last_state or {}
                await n.disconnect()

                logger.info(f"Action {action} executed successfully")
                return True, message

            except Exception as e:
                logger.error(f"Failed to execute action {action}: {e}")
                return False, str(e)

    async def update_status(self, mac_address: str, app_id: int, name: str) -> dict:
        """Update and retrieve current status of Nuki device.

        Args:
            mac_address: Bluetooth MAC address
            app_id: App identifier
            name: Bridge name

        Returns:
            Dictionary with device state including battery info
        """
        async with self._lock:
            try:
                n = await self._get_device(mac_address, app_id, name)
                await n.update_state()
                last_state = n.last_state or {}

                battery_critical = last_state.get("critical_battery_state", False)

                if mac_address not in self.devices:
                    self.devices[mac_address] = {}

                self.devices[mac_address]["last_state"] = last_state
                self.devices[mac_address]["battery"] = {
                    "critical": battery_critical,
                    "timestamp": datetime.utcnow().isoformat(),
                }

                await n.disconnect()
                logger.debug(f"Status updated for {mac_address}: {last_state}")
                return last_state

            except Exception as e:
                logger.error(f"Failed to update status for {mac_address}: {e}")
                return {}

    def get_lock_state(self, mac_address: str) -> str:
        """Get current lock state of device.

        Args:
            mac_address: Bluetooth MAC address

        Returns:
            Lock state string (LOCKED, UNLOCKED, or UNKNOWN)
        """
        device_data = self.devices.get(mac_address, {})
        last_state = device_data.get("last_state", {})

        if not last_state:
            return "UNKNOWN"

        lock_state = last_state.get("lock_state", "unknown")
        state_map = {
            "locked": "LOCKED",
            "unlocked": "UNLOCKED",
            "unlatched": "UNLOCKED",
            "unlocking": "UNLOCKED",
            "locking": "LOCKED",
        }
        return state_map.get(str(lock_state).lower(), "UNKNOWN")

    def get_battery_state(self, mac_address: str) -> dict:
        """Get battery state of device.

        Args:
            mac_address: Bluetooth MAC address

        Returns:
            Dictionary with critical flag and timestamp
        """
        device_data = self.devices.get(mac_address, {})
        battery = device_data.get("battery")

        if not battery:
            return {"critical": False, "timestamp": None}
        return battery

    def get_all_batteries(self) -> dict[str, dict]:
        """Get battery states for all known devices.

        Returns:
            Dictionary mapping MAC addresses to battery info
        """
        result = {}
        for mac, data in self.devices.items():
            battery = data.get("battery")
            if battery:
                result[mac] = battery
        return result


nuki_instance: Optional[NukiDevice] = None


def get_nuki_device(config_dir: Path) -> NukiDevice:
    """Get or create singleton NukiDevice instance.

    Args:
        config_dir: Directory for storing pairing data

    Returns:
        Shared NukiDevice instance
    """
    global nuki_instance
    if nuki_instance is None:
        nuki_instance = NukiDevice(config_dir)
    return nuki_instance
