from __future__ import annotations

import asyncio
import builtins
import contextlib
import io
import json
import logging
import sys
import threading
import traceback
import warnings
from datetime import datetime
from pathlib import Path
from typing import Optional

import pyNukiBT
from bleak import BleakScanner
from nacl.public import PrivateKey

logger = logging.getLogger(__name__)

# Configure logging for pyNukiBT
logging.getLogger("pyNukiBT").setLevel(logging.WARNING)
warnings.filterwarnings("ignore", module="pyNukiBT")


# Monkey-patch traceback.print_exc to suppress pyNukiBT disconnect errors
_original_print_exc = traceback.print_exc


def _filtered_print_exc(limit=None, file=None, chain=True):
    """Suppress known harmless pyNukiBT errors from traceback output."""
    if file is None:
        file = sys.stderr

    # Capture the traceback
    import io as _io

    buffer = _io.StringIO()
    _original_print_exc(limit=limit, file=buffer, chain=chain)
    output = buffer.getvalue()

    # Filter out harmless disconnect errors
    if "pyNukiBT/nuki.py" in output and "disconnect" in output and "EOFError" in output:
        logger.debug("[SUPPRESSED] pyNukiBT disconnect error (harmless)")
        return

    # Write to original file if not suppressed
    file.write(output)


traceback.print_exc = _filtered_print_exc


# Monkey-patch print to filter pyNukiBT error messages
_original_print = print


def _filtered_print(*args, **kwargs):
    """Suppress known pyNukiBT warning messages."""
    if args:
        text = " ".join(str(arg) for arg in args)
        if "Got unexpected message length for command CONFIG" in text:
            logger.debug(f"[SUPPRESSED] {text}")
            return
        if "Error while disconnecting" in text:
            logger.debug("[SUPPRESSED] pyNukiBT disconnect error message")
            return
        if "Timeout while waiting for response KEYTURNER_STATES" in text:
            logger.warning(f"[NUKI] {text}")
            return
    _original_print(*args, **kwargs)


# Apply the patch
builtins.print = _filtered_print


def _suppress_stderr():
    """Context manager to suppress stderr output (for noisy library errors)."""
    return contextlib.redirect_stderr(io.StringIO())


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
        self._locks: dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}
        self._lock_creation_lock = threading.Lock()

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the asyncio lock for the current event loop.

        This ensures the lock is always created in the correct event loop,
        which is important when the class is used from different threads.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No event loop running, create one
            loop = asyncio.get_event_loop()

        with self._lock_creation_lock:
            if loop not in self._locks:
                self._locks[loop] = asyncio.Lock()
            return self._locks[loop]

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
            try:
                with _suppress_stderr():
                    await n.disconnect()
            except Exception as e:
                logger.debug(f"Disconnect error (can be ignored): {e}")
            logger.info("Pairing successful")
            return True
        except pyNukiBT.NukiErrorException as e:
            logger.error(f"Pairing failed: {e}")
            try:
                with _suppress_stderr():
                    await n.disconnect()
            except Exception:
                pass  # Ignore disconnect errors after failure
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
        logger.debug(f"[DEBUG] _get_device: Loading pairing data for {mac_address}")
        auth_id, nuki_public_key, bridge_public_key, bridge_private_key = self.load_pairing(
            mac_address
        )
        if not auth_id:
            raise ValueError(f"Not paired with {mac_address} - run pairing first")

        logger.debug(f"[DEBUG] _get_device: Creating NukiDevice instance for {mac_address}")
        logger.debug(
            f"[DEBUG] _get_device: auth_id length: {len(auth_id)}, app_id: {app_id}, name: {name}"
        )

        n = pyNukiBT.NukiDevice(
            mac_address,
            auth_id,
            nuki_public_key,
            bridge_public_key,
            bridge_private_key,
            app_id,
            name,
        )

        logger.debug(f"[DEBUG] _get_device: Scanning for device {mac_address}...")
        device = await BleakScanner.find_device_by_address(mac_address, timeout=10.0)
        if not device:
            raise ConnectionError(f"Device {mac_address} not found")

        logger.debug("[DEBUG] _get_device: Device found, setting BLE device")
        n.set_ble_device(device)

        logger.debug(f"[DEBUG] _get_device: Connecting to {mac_address}...")
        await n.connect()
        logger.debug(f"[DEBUG] _get_device: Connected successfully to {mac_address}")
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
        async with self._get_lock():
            n = None
            try:
                logger.info(f"[DEBUG] execute_action: Starting action '{action}' for {mac_address}")
                n = await self._get_device(mac_address, app_id, name)

                # Update state first to populate last_state before action
                logger.debug(
                    f"[DEBUG] execute_action: Updating state before action for {mac_address}"
                )
                await n.update_state()

                if action == "lock":
                    logger.debug(f"[DEBUG] execute_action: Sending lock command to {mac_address}")
                    await n.lock()
                    message = "Verriegelt"
                elif action == "unlock":
                    logger.debug(f"[DEBUG] execute_action: Sending unlock command to {mac_address}")
                    await n.unlock()
                    message = "Entriegelt"
                elif action == "unlatch":
                    logger.debug(
                        f"[DEBUG] execute_action: Sending unlatch command to {mac_address}"
                    )
                    await n.unlatch()
                    message = "Tür geöffnet"
                else:
                    await n.disconnect()
                    return False, f"Unknown action: {action}"

                logger.debug(f"[DEBUG] execute_action: Action '{action}' sent, waiting 1s...")
                await asyncio.sleep(1)
                logger.debug(
                    f"[DEBUG] execute_action: Updating state after action for {mac_address}"
                )
                await n.update_state()
                logger.debug(f"[DEBUG] execute_action: State updated, last_state: {n.last_state}")
                logger.debug(f"[DEBUG] execute_action: self.devices type: {type(self.devices)}")

                # Store state in devices dict instead of instance variable
                if self.devices is None:
                    logger.error("[ERROR] self.devices is None! Reinitializing...")
                    self.devices = {}

                if mac_address not in self.devices:
                    self.devices[mac_address] = {}

                last_state = n.last_state if n.last_state is not None else {}
                logger.debug(f"[DEBUG] execute_action: Storing last_state: {type(last_state)}")
                self.devices[mac_address]["last_state"] = last_state

                logger.debug(f"[DEBUG] execute_action: Disconnecting from {mac_address}...")
                try:
                    with _suppress_stderr():
                        await n.disconnect()
                    logger.debug(
                        f"[DEBUG] execute_action: Disconnected successfully from {mac_address}"
                    )
                except Exception as e:
                    logger.debug(f"[DEBUG] execute_action: Disconnect error (can be ignored): {e}")

                logger.info(f"Action {action} executed successfully")
                return True, message

            except Exception as e:
                logger.error(f"[ERROR] Failed to execute action {action}: {e}")
                logger.error(f"[ERROR] Exception type: {type(e).__name__}")
                if n is not None:
                    logger.debug(
                        "[DEBUG] execute_action: Attempting cleanup disconnect after error..."
                    )
                    try:
                        with _suppress_stderr():
                            await n.disconnect()
                        logger.debug("[DEBUG] execute_action: Cleanup disconnect completed")
                    except Exception as de:
                        logger.debug(f"[DEBUG] execute_action: Cleanup disconnect error: {de}")
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
        async with self._get_lock():
            n = None
            try:
                logger.debug(f"[DEBUG] update_status: Starting status update for {mac_address}")
                n = await self._get_device(mac_address, app_id, name)
                logger.debug(f"[DEBUG] update_status: Requesting state update from {mac_address}")

                # Try update_state with retry on CryptoError
                last_state = None
                for attempt in range(2):
                    try:
                        await n.update_state()
                        last_state = n.last_state or {}
                        break
                    except Exception as state_err:
                        if "CryptoError" in str(type(state_err)) or "Decryption failed" in str(
                            state_err
                        ):
                            logger.warning(
                                f"Decryption failed on attempt {attempt + 1}, retrying..."
                            )
                            if attempt < 1:  # Only retry once
                                try:
                                    await n.disconnect()
                                    await asyncio.sleep(0.5)
                                    device = await BleakScanner.find_device_by_address(
                                        mac_address, timeout=10.0
                                    )
                                    if device:
                                        n.set_ble_device(device)
                                        await n.connect()
                                except Exception:
                                    pass
                        else:
                            raise

                if last_state is None:
                    logger.error(f"Failed to get state for {mac_address} after retries")
                    last_state = {}

                logger.debug(f"[DEBUG] update_status: Received state: {last_state}")

                battery_critical = last_state.get("critical_battery_state", False)

                # Note: critical_battery_state contains battery percentage (0-100)
                # Values below 20% are considered critical
                # Cap at 100% as some devices report values > 100
                if isinstance(battery_critical, int):
                    battery_percentage = min(battery_critical, 100)
                    battery_critical = battery_percentage < 20
                else:
                    battery_percentage = None

                if mac_address not in self.devices:
                    self.devices[mac_address] = {}

                self.devices[mac_address]["last_state"] = last_state
                self.devices[mac_address]["battery"] = {
                    "critical": battery_critical,
                    "percentage": battery_percentage,
                    "timestamp": datetime.utcnow().isoformat(),
                }

                logger.debug(f"[DEBUG] update_status: Disconnecting from {mac_address}...")
                try:
                    with _suppress_stderr():
                        await n.disconnect()
                    logger.debug(
                        f"[DEBUG] update_status: Disconnected successfully from {mac_address}"
                    )
                except Exception as e:
                    logger.debug(f"[DEBUG] update_status: Disconnect error (can be ignored): {e}")

                logger.debug(f"Status updated for {mac_address}: {last_state}")
                return last_state

            except Exception as e:
                logger.error(f"[ERROR] Failed to update status for {mac_address}: {e}")
                logger.error(f"[ERROR] Exception type: {type(e).__name__}")
                if n is not None:
                    logger.debug(
                        "[DEBUG] update_status: Attempting cleanup disconnect after error..."
                    )
                    try:
                        with _suppress_stderr():
                            await n.disconnect()
                        logger.debug("[DEBUG] update_status: Cleanup disconnect completed")
                    except Exception as de:
                        logger.debug(f"[DEBUG] update_status: Cleanup disconnect error: {de}")
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
            logger.debug(f"[DEBUG] get_lock_state: No last_state for {mac_address}")
            return "UNKNOWN"

        lock_state = last_state.get("lock_state", "unknown")
        logger.debug(
            f"[DEBUG] get_lock_state: {mac_address} raw lock_state={lock_state} "
            f"(type: {type(lock_state)})"
        )

        # Convert enum to string if needed
        if hasattr(lock_state, "name"):
            lock_state_str = lock_state.name
        else:
            lock_state_str = str(lock_state)

        state_map = {
            "locked": "LOCKED",
            "unlocked": "UNLOCKED",
            "unlatched": "UNLOCKED",
            "unlocking": "UNLOCKED",
            "locking": "LOCKED",
            "uncalibrated": "UNCALIBRATED",
            "motor_blocked": "ERROR",
        }
        result = state_map.get(lock_state_str.lower(), "UNKNOWN")
        logger.debug(
            f"[DEBUG] get_lock_state: {mac_address} lock_state_str={lock_state_str} -> {result}"
        )
        return result

    def get_battery_state(self, mac_address: str) -> dict:
        """Get battery state of device.

        Args:
            mac_address: Bluetooth MAC address

        Returns:
            Dictionary with critical flag, percentage, and timestamp
        """
        device_data = self.devices.get(mac_address, {})
        battery = device_data.get("battery")

        if not battery:
            return {"critical": False, "percentage": None, "timestamp": None}
        return battery
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
