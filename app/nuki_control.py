from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import pyNukiBT
from bleak import BleakScanner
from bleak.exc import BleakDBusError, BleakError
from nacl.public import PrivateKey

logger = logging.getLogger(__name__)

# Make pyNukiBT quiet (it logs disconnect EOFErrors at ERROR level)
logging.getLogger("pyNukiBT").setLevel(logging.CRITICAL)
logging.getLogger("pyNukiBT.nuki").setLevel(logging.CRITICAL)


class BluetoothResetManager:
    """Manages automatic Bluetooth adapter resets on repeated connection failures.

    Uses rate limiting to avoid too frequent resets.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._last_reset_time = 0.0
        self._min_reset_interval = 300.0  # 5 minutes minimum between resets
        self._consecutive_failures = 0
        self._failure_threshold = 3  # Reset after 3 consecutive failures
        self._last_failure_time = 0.0
        self._failure_timeout = 60.0  # Reset counter if no failures for 60s

    def record_failure(self) -> bool:
        """Record a connection failure and potentially trigger reset.

        Returns:
            True if reset was triggered, False otherwise
        """
        with self._lock:
            now = time.time()

            # Reset failure counter if too much time passed
            if now - self._last_failure_time > self._failure_timeout:
                self._consecutive_failures = 0

            self._consecutive_failures += 1
            self._last_failure_time = now

            logger.warning(
                f"BLE connection failure recorded"
                f" ({self._consecutive_failures}/{self._failure_threshold})"
            )

            # Check if we should trigger reset
            if self._consecutive_failures >= self._failure_threshold:
                time_since_last_reset = now - self._last_reset_time

                if time_since_last_reset >= self._min_reset_interval:
                    logger.warning(
                        f"Triggering automatic Bluetooth reset after {self._consecutive_failures} "
                        f"consecutive failures (last reset was {time_since_last_reset:.0f}s ago)"
                    )

                    if self._perform_reset():
                        self._last_reset_time = now
                        self._consecutive_failures = 0
                        return True
                    else:
                        logger.error("Automatic Bluetooth reset failed")
                else:
                    logger.info(
                        f"Skipping Bluetooth reset - too soon after last reset "
                        f"({time_since_last_reset:.0f}s < {self._min_reset_interval:.0f}s)"
                    )

            return False

    def record_success(self):
        """Record a successful connection - resets failure counter."""
        with self._lock:
            if self._consecutive_failures > 0:
                logger.info(
                    f"BLE connection successful, "
                    f"resetting failure counter (was {self._consecutive_failures})"
                )
                self._consecutive_failures = 0

    def _perform_reset(self) -> bool:
        """Perform the actual Bluetooth reset.

        Returns:
            True if reset successful, False otherwise
        """
        try:
            script_locations = [
                Path("/opt/Nerdlock/scripts/reset_bluetooth.sh"),
                Path(__file__).parent.parent / "scripts" / "reset_bluetooth.sh",
            ]

            script_path = None
            for path in script_locations:
                if path.exists():
                    script_path = path
                    break

            if not script_path:
                logger.error("Bluetooth reset script not found")
                return False

            logger.info(f"Executing Bluetooth reset: {script_path}")

            result = subprocess.run(
                ["sudo", str(script_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                logger.info(f"Bluetooth reset successful: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"Bluetooth reset failed (exit {result.returncode}): {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Bluetooth reset timed out")
            return False
        except Exception as e:
            logger.error(f"Bluetooth reset error: {e}", exc_info=True)
            return False


@dataclass(frozen=True)
class _BleCacheEntry:
    device: object  # bleak.backends.device.BLEDevice
    ts: float


class _BleWorker:
    """Single dedicated BLE event-loop thread (one DBus connection, one loop)."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="nuki-ble-worker", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            try:
                pending = asyncio.all_tasks(loop=self._loop)  # type: ignore[arg-type]
                for t in pending:
                    t.cancel()
                if pending:
                    self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            self._loop.close()

    async def run(self, coro):
        """Run coroutine on worker loop; safe to call from any thread/loop."""
        if self._loop is None:
            raise RuntimeError("BLE worker not started")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if running is self._loop:
            return await coro

        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return await asyncio.wrap_future(fut)


class NukiDevice:
    """
    Same public API as before, plus:
      - async warmup(macs, app_id, name) -> None

    Key changes:
      - Per-MAC session reuse (keep connection open for idle_ttl seconds)
      - Per-MAC lock enforced in BLE worker loop
      - BLEDevice cache to reduce scanning
      - Disconnect is best-effort and EOFError ignored
    """

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.pairing_dir = config_dir / "nuki_pairings"
        self.pairing_dir.mkdir(parents=True, exist_ok=True)

        # Public state storage (read by sync getters)
        self.devices: dict[str, dict] = {}
        self._state_lock = threading.Lock()

        # BLE worker
        self._worker = _BleWorker()
        self._worker.start()

        # Bluetooth reset manager
        self._bt_reset_manager = BluetoothResetManager()

        # BLE-loop-only fields
        self._mac_locks: dict[str, asyncio.Lock] = {}
        self._ble_cache: dict[str, _BleCacheEntry] = {}
        self._sessions: dict[str, tuple[pyNukiBT.NukiDevice, float, int, str]] = {}
        #                          mac -> (device, last_used_ts, app_id, name)

        self._gc_task_started = False

        # Tuning (adjust to taste)
        self._ble_cache_ttl_s = 600.0  # scan result cache (10 min)
        self._scan_timeout_s = 3.0  # short scan; we try to avoid scanning most times
        self._idle_ttl_s = 60.0  # keep BLE connection warm for 60s of inactivity
        self._post_action_settle_s = 0.4  # wait after lock/unlock before reading state

        self._scan_lock: asyncio.Lock | None = None
        self._failed_scan_count = 0  # Track consecutive scan failures

    # ---------- pairing persistence ----------

    def _get_pairing_file(self, mac_address: str) -> Path:
        safe_mac = mac_address.replace(":", "_")
        return self.pairing_dir / f"nuki_{safe_mac}.json"

    def load_pairing(
        self, mac_address: str
    ) -> tuple[bytes | None, bytes | None, bytes | None, bytes | None]:
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
                logger.error("Failed to load pairing data for %s: %s", mac_address, e)
        return None, None, None, None

    def save_pairing(
        self,
        mac_address: str,
        auth_id: bytes,
        nuki_public_key: bytes,
        bridge_public_key: bytes,
        bridge_private_key: bytes,
    ) -> None:
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
        logger.info("Pairing data saved to %s", pairing_file)

    def is_paired(self, mac_address: str) -> bool:
        auth_id, _, _, _ = self.load_pairing(mac_address)
        return auth_id is not None

    # ---------- internal helpers (BLE loop only) ----------

    def _ensure_gc_started__ble(self) -> None:
        if self._gc_task_started:
            return
        self._gc_task_started = True
        asyncio.create_task(self._session_gc__ble())

    def _get_scan_lock__ble(self) -> asyncio.Lock:
        if self._scan_lock is None:
            self._scan_lock = asyncio.Lock()
        return self._scan_lock

    def _get_mac_lock__ble(self, mac: str) -> asyncio.Lock:
        lock = self._mac_locks.get(mac)
        if lock is None:
            lock = asyncio.Lock()
            self._mac_locks[mac] = lock
        return lock

    async def _find_ble_device__ble(self, mac: str):
        now = time.time()
        entry = self._ble_cache.get(mac)
        if entry and (now - entry.ts) < self._ble_cache_ttl_s:
            return entry.device

        scan_lock = self._get_scan_lock__ble()

        async with scan_lock:
            # Cache might have been filled while we waited
            now = time.time()
            entry = self._ble_cache.get(mac)
            if entry and (now - entry.ts) < self._ble_cache_ttl_s:
                return entry.device

            # Use longer timeout if we've had recent failures
            scan_timeout = self._scan_timeout_s
            if self._failed_scan_count > 0:
                scan_timeout = min(15.0, self._scan_timeout_s * (1 + self._failed_scan_count))
                logger.warning(
                    "Using extended scan timeout %.1fs for %s after %d consecutive failures",
                    scan_timeout,
                    mac,
                    self._failed_scan_count,
                )

            last_exc: Exception | None = None
            for attempt in range(4):
                try:
                    dev = await BleakScanner.find_device_by_address(mac, timeout=scan_timeout)
                    if dev:
                        self._ble_cache[mac] = _BleCacheEntry(device=dev, ts=time.time())
                        self._failed_scan_count = 0  # Reset on success
                        logger.debug("Successfully scanned and cached device %s", mac)
                    return dev
                except BleakDBusError as e:
                    # BlueZ: another discovery/scan is already in progress
                    if "org.bluez.Error.InProgress" in str(e):
                        last_exc = e
                        await asyncio.sleep(0.25 * (attempt + 1))
                        continue
                    raise
                except Exception as e:
                    last_exc = e
                    break

            if last_exc:
                logger.warning("Scan for %s failed after retries: %s", mac, last_exc)
                self._failed_scan_count += 1
            return None

    async def _disconnect_best_effort__ble(self, n: pyNukiBT.NukiDevice) -> None:
        try:
            await n.disconnect()
        except EOFError:
            # dbus_fast sometimes throws EOF if the bus drops during disconnect
            return
        except Exception:
            return

    def _is_device_not_found(self, e: Exception) -> bool:
        return isinstance(e, BleakError) and "not found" in str(e)

    async def _force_rescan__ble(self, mac: str):
        logger.info("Forcing rescan for device %s (clearing cache)", mac)
        self._ble_cache.pop(mac, None)
        scan_lock = self._get_scan_lock__ble()

        async with scan_lock:
            last_exc: Exception | None = None
            # Try with progressively longer timeouts
            timeouts = [10.0, 15.0, 20.0, 30.0]
            for attempt, timeout in enumerate(timeouts):
                try:
                    logger.info(
                        "Rescan attempt %d/%d for %s with timeout %.1fs",
                        attempt + 1,
                        len(timeouts),
                        mac,
                        timeout,
                    )
                    dev = await BleakScanner.find_device_by_address(mac, timeout=timeout)
                    if dev:
                        self._ble_cache[mac] = _BleCacheEntry(device=dev, ts=time.time())
                        self._failed_scan_count = 0  # Reset on success
                        logger.info("Successfully rescanned device %s", mac)
                        return dev
                    else:
                        logger.warning("Rescan attempt %d: Device %s not found", attempt + 1, mac)
                except BleakDBusError as e:
                    if "org.bluez.Error.InProgress" in str(e):
                        last_exc = e
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    raise
                except Exception as e:
                    logger.warning("Rescan attempt %d failed: %s", attempt + 1, e)
                    last_exc = e
                    await asyncio.sleep(1.0 * (attempt + 1))
                    continue

            if last_exc:
                logger.error("Force rescan for %s failed after all retries: %s", mac, last_exc)
                self._failed_scan_count += 1
            return None

    async def _connect_new_session__ble(
        self, mac: str, app_id: int, name: str
    ) -> pyNukiBT.NukiDevice:
        auth_id, nuki_public_key, bridge_public_key, bridge_private_key = self.load_pairing(mac)
        if not auth_id:
            raise ValueError(f"Not paired with {mac} - run pairing first")

        async def _make_and_connect(dev):
            n = pyNukiBT.NukiDevice(
                mac,
                auth_id,
                nuki_public_key,
                bridge_public_key,
                bridge_private_key,
                app_id,
                name,
            )
            n.set_ble_device(dev)
            await n.connect()
            return n

        # 1) First try: cached device (fast path)
        dev = await self._find_ble_device__ble(mac)
        if not dev:
            logger.warning("Device %s not found in initial scan", mac)
            raise ConnectionError(f"Device {mac} not found")

        try:
            return await _make_and_connect(dev)
        except BleakError as e:
            msg = str(e)
            if "not found" not in msg:
                raise

            # 2) Stale device path: drop cache and do a real scan, then retry
            logger.warning(
                "Bleak device-path stale for %s, rescanning and retrying connect: %s", mac, e
            )
            self._ble_cache.pop(mac, None)

            # Use longer timeout for rescan
            rescan_timeout = 15.0 if self._failed_scan_count == 0 else 30.0
            logger.info("Attempting rescan with timeout %.1fs", rescan_timeout)
            dev2 = await BleakScanner.find_device_by_address(mac, timeout=rescan_timeout)
            if not dev2:
                logger.error(
                    "Device %s not found after rescan (timeout: %.1fs)", mac, rescan_timeout
                )
                self._failed_scan_count += 1
                raise ConnectionError(f"Device {mac} not found (after rescan)")

            # refresh cache too
            self._ble_cache[mac] = _BleCacheEntry(device=dev2, ts=time.time())
            self._failed_scan_count = 0
            logger.info("Successfully found device %s after rescan", mac)
            return await _make_and_connect(dev2)

    async def _get_session__ble(self, mac: str, app_id: int, name: str) -> pyNukiBT.NukiDevice:
        """Reuse a warm session if possible; otherwise connect and store."""
        self._ensure_gc_started__ble()

        sess = self._sessions.get(mac)
        if sess:
            n, _, sess_app_id, sess_name = sess
            # If app_id/name changed, rebuild session
            if sess_app_id == app_id and sess_name == name:
                self._sessions[mac] = (n, time.time(), sess_app_id, sess_name)
                return n
            # else drop old session
            await self._disconnect_best_effort__ble(n)
            self._sessions.pop(mac, None)

        n = await self._connect_new_session__ble(mac, app_id, name)
        self._sessions[mac] = (n, time.time(), app_id, name)
        return n

    async def _drop_session__ble(self, mac: str) -> None:
        sess = self._sessions.pop(mac, None)
        if not sess:
            return
        n, _, _, _ = sess
        await self._disconnect_best_effort__ble(n)

    async def _session_gc__ble(self) -> None:
        """Disconnect idle sessions."""
        while True:
            now = time.time()
            for mac, (n, last_used, _app_id, _name) in list(self._sessions.items()):
                if now - last_used > self._idle_ttl_s:
                    self._sessions.pop(mac, None)
                    await self._disconnect_best_effort__ble(n)
            await asyncio.sleep(2.0)

    @staticmethod
    def _parse_battery(last_state: dict) -> tuple[bool, Optional[int]]:
        # Critical flag (NOTE: Nuki reports False when battery is critical!)
        crit = last_state.get("critical_battery_state", True)
        if isinstance(crit, bool):
            battery_critical = not crit  # Invert: False = critical, True = OK
        elif isinstance(crit, int):
            battery_critical = crit == 0  # Invert: 0 = critical, >0 = OK
        else:
            battery_critical = False

        # Percentage (best-effort; depends on device/pyNukiBT version)
        # Note: Many Nuki devices don't provide battery percentage, only critical state
        pct = None
        for k in ("battery_percentage", "batteryLevel", "battery_level", "battery"):
            v = last_state.get(k)
            if isinstance(v, int):
                pct = max(0, min(v, 100))
                logger.debug(f"Found battery percentage in key '{k}': {pct}%")
                break

        if pct is None:
            logger.debug(
                f"No battery percentage available,"
                f" critical_battery_state={crit} (inverted to critical={battery_critical})"
            )

        return battery_critical, pct

    def _store_state(self, mac: str, last_state: dict) -> None:
        with self._state_lock:
            self.devices.setdefault(mac, {})
            self.devices[mac]["last_state"] = last_state

    def _store_battery(self, mac: str, critical: bool, percentage: Optional[int]) -> None:
        with self._state_lock:
            self.devices.setdefault(mac, {})
            self.devices[mac]["battery"] = {
                "critical": bool(critical),
                "percentage": percentage,
                "timestamp": datetime.utcnow().isoformat(),
            }
        logger.debug(f"Stored battery for {mac}: critical={critical}, percentage={percentage}")

    # ---------- new public method (optional) ----------

    async def warmup(self, mac_addresses: list[str], app_id: int, name: str) -> None:
        """Connect to devices and fetch state so actions are fast afterwards."""

        async def _do__ble() -> None:
            for mac in mac_addresses:
                lock = self._get_mac_lock__ble(mac)
                async with lock:
                    try:
                        n = await self._get_session__ble(mac, app_id, name)
                        await n.update_state()
                        last_state = n.last_state or {}
                        self._store_state(mac, last_state)
                        crit, pct = self._parse_battery(last_state)
                        self._store_battery(mac, crit, pct)
                    except Exception as e:
                        logger.debug("Warmup failed for %s: %s", mac, e)
                        await self._drop_session__ble(mac)

        return await self._worker.run(_do__ble())

    # ---------- public async API (same signatures) ----------

    async def pair(self, mac_address: str, pin: int, app_id: int, name: str) -> bool:
        async def _do_pair__ble() -> bool:
            lock = self._get_mac_lock__ble(mac_address)
            async with lock:
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

                dev = await self._find_ble_device__ble(mac_address)
                if not dev:
                    logger.error("Device %s not found", mac_address)
                    return False

                n.set_ble_device(dev)
                await n.connect()
                try:
                    await n.pair(pin)
                    self.save_pairing(
                        mac_address,
                        n._auth_id,
                        n._nuki_public_key,
                        n._bridge_public_key,
                        n._bridge_private_key,
                    )
                    return True
                except pyNukiBT.NukiErrorException as e:
                    logger.error("Pairing failed: %s", e)
                    return False
                finally:
                    await self._disconnect_best_effort__ble(n)

        return await self._worker.run(_do_pair__ble())

    async def execute_action(
        self, mac_address: str, app_id: int, name: str, action: str
    ) -> tuple[bool, str]:
        async def _do_action__ble() -> tuple[bool, str]:
            lock = self._get_mac_lock__ble(mac_address)
            async with lock:
                for attempt in (1, 2):
                    try:
                        n = await self._get_session__ble(mac_address, app_id, name)
                        if getattr(n, "last_state", None) is None:
                            try:
                                await n.update_state()
                            except Exception:
                                # fallback: prevent pyNukiBT from crashing on assignment
                                n.last_state = {}
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
                            return False, f"Unknown action: {action}"

                        await asyncio.sleep(self._post_action_settle_s)

                        # optional refresh
                        await n.update_state()
                        last_state = n.last_state or {}
                        self._store_state(mac_address, last_state)
                        crit, pct = self._parse_battery(last_state)
                        self._store_battery(mac_address, crit, pct)

                        # Record success for auto-reset manager
                        self._bt_reset_manager.record_success()

                        return True, message

                    except Exception as e:
                        if attempt == 1 and self._is_device_not_found(e):
                            logger.warning(
                                "BLE device-path lost for %s, "
                                "forcing rescan + reconnect and retrying action",
                                mac_address,
                            )
                            await self._drop_session__ble(mac_address)
                            # Clear entire cache to force fresh discovery
                            self._ble_cache.clear()
                            logger.info("Cleared entire BLE cache to force fresh discovery")
                            await self._force_rescan__ble(mac_address)
                            # loop continues to attempt 2
                            continue

                        logger.error(
                            "Failed to execute action %s for"
                            "%s after retries: %s (failed_scan_count=%d)",
                            action,
                            mac_address,
                            e,
                            self._failed_scan_count,
                            exc_info=True,
                        )
                        await self._drop_session__ble(mac_address)
                        # Clear cache on final failure to avoid stale data
                        self._ble_cache.pop(mac_address, None)

                        # Trigger automatic Bluetooth reset if too many failures
                        if self._bt_reset_manager.record_failure():
                            logger.info(
                                "Automatic Bluetooth reset triggered, please retry in 10 seconds"
                            )

                        return False, str(e)

        return await self._worker.run(_do_action__ble())

    async def update_status(self, mac_address: str, app_id: int, name: str) -> dict:
        async def _do_status__ble() -> dict:
            lock = self._get_mac_lock__ble(mac_address)
            async with lock:
                try:
                    n = await self._get_session__ble(mac_address, app_id, name)

                    # Retry once on decrypt-ish issues; if it persists drop session.
                    last_state: dict = {}
                    for attempt in range(2):
                        try:
                            await n.update_state()
                            last_state = n.last_state or {}
                            break
                        except Exception as e:
                            if attempt == 0:
                                logger.debug(
                                    "State update failed for %s (%s), retrying once", mac_address, e
                                )
                                await self._drop_session__ble(mac_address)
                                n = await self._get_session__ble(mac_address, app_id, name)
                                continue
                            raise

                    self._store_state(mac_address, last_state)
                    crit, pct = self._parse_battery(last_state)
                    self._store_battery(mac_address, crit, pct)
                    return last_state

                except Exception as e:
                    logger.error(
                        "Failed to update status for %s: %s", mac_address, e, exc_info=True
                    )
                    await self._drop_session__ble(mac_address)

                    # Trigger automatic Bluetooth reset if too many failures
                    if "not found" in str(e).lower() or isinstance(e, ConnectionError):
                        if self._bt_reset_manager.record_failure():
                            logger.info("Automatic Bluetooth reset triggered during status update")

                    raise

        return await self._worker.run(_do_status__ble())

    # ---------- public sync getters ----------

    def get_lock_state(self, mac_address: str) -> str:
        with self._state_lock:
            last_state = (self.devices.get(mac_address, {}) or {}).get("last_state", {}) or {}

        if not last_state:
            return "UNKNOWN"

        lock_state = last_state.get("lock_state", "unknown")
        lock_state_str = lock_state.name if hasattr(lock_state, "name") else str(lock_state)

        state_map = {
            "locked": "LOCKED",
            "unlocked": "UNLOCKED",
            "unlatched": "UNLOCKED",
            "unlocking": "UNLOCKED",
            "locking": "LOCKED",
            "uncalibrated": "UNCALIBRATED",
            "motor_blocked": "ERROR",
        }
        return state_map.get(lock_state_str.lower(), "UNKNOWN")

    def get_battery_state(self, mac_address: str) -> dict:
        with self._state_lock:
            battery = (self.devices.get(mac_address, {}) or {}).get("battery")
        if not battery:
            return {"critical": False, "percentage": None, "timestamp": None}
        return battery

    def get_all_batteries(self) -> dict[str, dict]:
        with self._state_lock:
            return {
                mac: data["battery"] for mac, data in self.devices.items() if data.get("battery")
            }


# ---- singleton factory (same external access) ----

nuki_instance: Optional[NukiDevice] = None


def get_nuki_device(config_dir: Path) -> NukiDevice:
    global nuki_instance
    if nuki_instance is None:
        nuki_instance = NukiDevice(config_dir)
    return nuki_instance
