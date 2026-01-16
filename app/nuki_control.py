from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import pyNukiBT
from bleak import BleakScanner
from bleak.exc import BleakError
from nacl.public import PrivateKey

logger = logging.getLogger(__name__)

# Make pyNukiBT quiet (it logs disconnect EOFErrors at ERROR level)
logging.getLogger("pyNukiBT").setLevel(logging.CRITICAL)
logging.getLogger("pyNukiBT.nuki").setLevel(logging.CRITICAL)


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

        dev = await BleakScanner.find_device_by_address(mac, timeout=self._scan_timeout_s)
        if dev:
            self._ble_cache[mac] = _BleCacheEntry(device=dev, ts=now)
        return dev

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
        self._ble_cache.pop(mac, None)
        dev = await BleakScanner.find_device_by_address(mac, timeout=10.0)
        if dev:
            self._ble_cache[mac] = _BleCacheEntry(device=dev, ts=time.time())
        return dev

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
            raise ConnectionError(f"Device {mac} not found")

        try:
            return await _make_and_connect(dev)
        except BleakError as e:
            msg = str(e)
            if "not found" not in msg:
                raise

            # 2) Stale device path: drop cache and do a real scan, then retry
            logger.debug(
                "Bleak device-path stale for %s, rescanning and retrying connect: %s", mac, e
            )
            self._ble_cache.pop(mac, None)

            dev2 = await BleakScanner.find_device_by_address(mac, timeout=10.0)
            if not dev2:
                raise ConnectionError(f"Device {mac} not found (after rescan)")

            # refresh cache too
            self._ble_cache[mac] = _BleCacheEntry(device=dev2, ts=time.time())
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
        # Critical flag
        crit = last_state.get("critical_battery_state", False)
        if isinstance(crit, bool):
            battery_critical = crit
        elif isinstance(crit, int):
            battery_critical = crit > 0
        else:
            battery_critical = False

        # Percentage (best-effort; depends on device/pyNukiBT version)
        pct = None
        for k in ("battery_percentage", "batteryLevel", "battery_level", "battery"):
            v = last_state.get(k)
            if isinstance(v, int):
                pct = max(0, min(v, 100))
                break

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

                        return True, message

                    except Exception as e:
                        if attempt == 1 and self._is_device_not_found(e):
                            logger.info(
                                "BLE device-path lost for %s, "
                                "forcing rescan + reconnect and retrying action",
                                mac_address,
                            )
                            await self._drop_session__ble(mac_address)
                            await self._force_rescan__ble(mac_address)
                            # loop continues to attempt 2
                            continue

                        logger.error(
                            "Failed to execute action %s for %s: %s",
                            action,
                            mac_address,
                            e,
                            exc_info=True,
                        )
                        await self._drop_session__ble(mac_address)
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
                    return {}

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
