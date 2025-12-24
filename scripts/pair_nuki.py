#!/usr/bin/env python3
"""Script for pairing Nuki smart locks via Bluetooth.

Scans for Nuki devices, prompts for PIN, and stores pairing data.
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from bleak import BleakScanner  # noqa: E402

from app.nuki_control import get_nuki_device  # noqa: E402


async def scan_for_nuki():
    print("Suche nach Nuki-Geräten...")
    print("=" * 60)

    devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
    nuki_devices = [(d, adv) for d, adv in devices.values() if d.name and "Nuki" in d.name]

    if not nuki_devices:
        print("Keine Nuki-Geräte gefunden.")
        return None

    print("Gefundene Nuki-Geräte:\n")
    for i, (device, adv) in enumerate(nuki_devices, 1):
        print(f"{i}. {device.name}")
        print(f"   MAC: {device.address}")
        print(f"   RSSI: {adv.rssi} dBm")
        print()

    if len(nuki_devices) == 1:
        return nuki_devices[0][0].address

    while True:
        choice = input(f"Wähle Gerät (1-{len(nuki_devices)}): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(nuki_devices):
            return nuki_devices[int(choice) - 1][0].address
        print("Ungültige Eingabe.")


async def main():
    config_dir = Path(__file__).parent.parent / "instance"
    nuki = get_nuki_device(config_dir)

    mac_address = await scan_for_nuki()
    if not mac_address:
        return

    if nuki.is_paired(mac_address):
        print(f"Es existieren bereits Pairing-Daten für {mac_address}!")
        pairing_file = nuki._get_pairing_file(mac_address)
        print(f"   Datei: {pairing_file}")
        overwrite = input("Neu pairen? (j/N): ").strip().lower()
        if overwrite != "j":
            print("Abgebrochen.")
            return

    pin = input("\nGib die 6-stellige PIN ein: ").strip()

    if len(pin) != 6 or not pin.isdigit():
        print("Fehler: PIN muss genau 6 Ziffern sein!")
        return

    app_id = 355740770
    name = "Nerdlock"

    print(f"\n🔗 Starte Pairing mit {mac_address}...")
    success = await nuki.pair(mac_address, int(pin), app_id, name)

    if success:
        print("\nPairing erfolgreich!")
        pairing_file = nuki._get_pairing_file(mac_address)
        print(f"   Daten gespeichert in: {pairing_file}")
        print("\nDu kannst jetzt Nerdlock verwenden.")
        print("\nSetze in der Umgebung:")
        print("  export NUKI_BUILDING_ENABLED=1")
        print(f'  export NUKI_BUILDING_MAC="{mac_address}"')
        print("  export NUKI_BUILDING_UNLATCH=1  # 0 um Unlatch zu verbieten")
    else:
        print("\nPairing fehlgeschlagen!")


if __name__ == "__main__":
    asyncio.run(main())
