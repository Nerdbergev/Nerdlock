# Nerdlock

Türsteuerung für den Schacht 2 des Nerdberges mit Nuki Smart Locks, Passkeys und Rollenverwaltung.

## Was ist das?

Nerdlock ist eine Webanwendung, die den Zugang zum Schacht 2 gibt. Mitglieder können per Webinterface Türen auf- und zusperren, Admins verwalten User und Rollen, Admins können nachträglich nachvollziehen, wer wann gesperrt hat.

Das Ganze läuft auf einem Raspberry Pi, der per Bluetooth mit euren Nuki-Schlössern spricht.

## Features

- **Türsteuerung**: Unlock, Lock, Unlatch per Webinterface
- **Passkeys**: Passwordless Login mit Fingerabdruck oder Face ID
- **Rollenverwaltung**: Admin, Member, Guest, Door-Admin - wer darf was
- **Zugriffslogs**: Wer hat wann welche Tür geöffnet
- **Nuki-Integration**: Batteriestatus und automatische Status-Updates
- **Mail-Benachrichtigungen**: Neue User bekommen ihre Zugangsdaten per Mail

## Hardware

- **Raspberry Pi 3/4/5** (getestet auf RPi 4)
- **Nuki Smart Lock** (mit Bluetooth-Modul)
- Optional: Domain mit HTTPS für Passkeys

## Installation auf Raspberry Pi

### 1. System vorbereiten

```bash
# System updaten
sudo apt update && sudo apt upgrade -y

# Python 3.13 installieren (wenn nicht vorhanden, mindestens 3.11)
sudo apt install python3.13 python3.13-venv python3.13-dev

# Bluetooth-Dependencies
sudo apt install bluetooth bluez libbluetooth-dev

# Git installieren
sudo apt install git
```

### 2. Projekt klonen

```bash
cd /home/pi
git clone https://github.com/Nerdbergev/Nerdlock.git
cd Nerdlock
```

### 3. Virtual Environment erstellen

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Umgebungsvariablen einrichten

Erstellt eine `.env` Datei:

```bash
nano .env
```

Inhalt (anpassen!):

```bash
# Flask
SECRET_KEY=hier-ein-langer-zufälliger-string-generieren
SECURITY_PASSWORD_SALT=noch-ein-zufälliger-salt

# Datenbank (SQLite ist ok für kleine Spaces)
DATABASE_URL=sqlite:///nerdlock.db

# Mail (für User-Einladungen)
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USE_TLS=1
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-mail-password
MAIL_DEFAULT_SENDER=nerdlock@example.com

# WebAuthn (für Passkeys)
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_NAME=Dein Hackspace
WEBAUTHN_ORIGIN=https://your-domain.com

# Nuki (später, nach Pairing)
NUKI_BUILDING_ENABLED=0
NUKI_BUILDING_MAC=
NUKI_BUILDING_UNLATCH=1

NUKI_HACKSPACE_ENABLED=0
NUKI_HACKSPACE_MAC=
NUKI_HACKSPACE_UNLATCH=1

NUKI_APP_ID=355740770
NUKI_NAME=Nerdlock
NUKI_CHECK_INTERVAL=900
```

Secrets generieren:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Datenbank initialisieren

```bash
source .venv/bin/activate
python3 << EOF
from app import create_app
from app.extensions import db
from app.models import User, Role
from flask_security.utils import hash_password
import uuid

app = create_app()
with app.app_context():
    db.create_all()

    # Admin-Rolle erstellen
    admin_role = Role(name="admin", description="Administrator")
    member_role = Role(name="member", description="Mitglied")
    db.session.add_all([admin_role, member_role])
    db.session.commit()

    # Ersten Admin erstellen
    admin = User(
        email="admin@example.com",  # ANPASSEN!
        username="admin",
        password=hash_password("change-me-now"),  # PASSWORT ÄNDERN!
        active=True,
        fs_uniquifier=str(uuid.uuid4()),
        roles=[admin_role]
    )
    db.session.add(admin)
    db.session.commit()
    print("Admin erstellt: admin@example.com / change-me-now")
EOF
```

### 6. Nuki pairen (optional)

Wenn ihr Nuki Smart Locks habt:

```bash
python3 scripts/pair_nuki.py
```

Das Script findet die Nukis, fragt nach der 6-stelligen PIN und speichert die Pairing-Daten. Danach zeigt es euch die ENV-Variablen, die ihr in die `.env` eintragen müsst.

### 7. App starten (Entwicklung)

```bash
source .venv/bin/activate
export FLASK_APP=wsgi:app
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
```

Jetzt auf `http://raspberry-ip:5000` zugreifen und mit dem Admin-Account einloggen.

### 8. Produktiv-Setup mit Gunicorn + systemd

Erstellt einen systemd-Service:

```bash
sudo nano /etc/systemd/system/nerdlock.service
```

Inhalt:

```ini
[Unit]
Description=Nerdlock Hackspace Access Control
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/Nerdlock
Environment="PATH=/home/pi/Nerdlock/.venv/bin"
EnvironmentFile=/home/pi/Nerdlock/.env
ExecStart=/home/pi/Nerdlock/.venv/bin/gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --timeout 60 \
    --access-logfile /home/pi/Nerdlock/logs/access.log \
    --error-logfile /home/pi/Nerdlock/logs/error.log \
    wsgi:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Gunicorn installieren und Service starten:

```bash
# Gunicorn installieren
source .venv/bin/activate
pip install gunicorn

# Log-Verzeichnis erstellen
mkdir -p logs

# Service aktivieren
sudo systemctl daemon-reload
sudo systemctl enable nerdlock
sudo systemctl start nerdlock

# Status checken
sudo systemctl status nerdlock
```

### 9. Nginx als Reverse Proxy (empfohlen)

Für HTTPS und bessere Performance:

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

Nginx-Config erstellen:

```bash
sudo nano /etc/nginx/sites-available/nerdlock
```

Inhalt:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Aktivieren:

```bash
sudo ln -s /etc/nginx/sites-available/nerdlock /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

HTTPS einrichten:

```bash
sudo certbot --nginx -d your-domain.com
```

## Verwendung

### User anlegen

Als Admin einloggen → Admin-Panel → "Neuen User anlegen"

User bekommt eine Mail mit Passwort. Danach kann er sich einloggen und ein Passkey einrichten.

### Rollen verwalten

- **admin**: Volle Kontrolle, User-Verwaltung

Rollen können pro User im Admin-Panel gesetzt werden.

### Türen steuern

Nach Login auf "Türen" → Gewünschte Tür auswählen → Unlock/Lock/Unlatch

Bulk-Actions: Alle Türen auf einmal steuern (nur Unlock/Lock).

### Logs anschauen

Unter "Logs" sieht jeder User seine eigenen Zugriffe. Admins sehen alle.

Filter nach Tür und Aktion möglich.

## Entwicklung

### Tests laufen lassen

```bash
source .venv/bin/activate
pytest tests/
```

### Pre-commit hooks installieren

```bash
source .venv/bin/activate
pip install pre-commit black isort flake8 commitizen
pre-commit install
pre-commit install --hook-type commit-msg
```

### Commit messages

Wir nutzen Conventional Commits:

```bash
cz commit
```

Oder manuell:

```bash
git commit -m "feat(doors): add bulk unlock action"
git commit -m "fix(auth): fix passkey registration for Firefox"
```

## Troubleshooting

### Bluetooth-Probleme

```bash
# Bluetooth-Status checken
sudo systemctl status bluetooth

# Bluetooth neustarten
sudo systemctl restart bluetooth

# Geräte scannen
sudo hcitool lescan
```

### Nuki findet sich nicht

- Nuki muss in Bluetooth-Reichweite sein (~10m)
- Pairing-Modus aktivieren (Taste am Nuki drücken)
- Pi-Bluetooth muss eingeschaltet sein
- Nur ein Gerät kann gleichzeitig pairen

### App startet nicht

```bash
# Logs checken
sudo journalctl -u nerdlock -f

# Oder direkt:
tail -f logs/error.log
```

### Passkeys funktionieren nicht

- HTTPS ist Pflicht (außer localhost)
- `WEBAUTHN_RP_ID` muss zur Domain passen
- `WEBAUTHN_ORIGIN` muss zum Browser-URL passen
- Browser muss Passkeys unterstützen (Chrome, Firefox, Safari)

## Lizenz

MIT - macht damit was ihr wollt, aber ohne Gewähr.

## Credits

Gebaut fürs Nerdberg e.V. Hackspace. Ihr dürft es gerne für euren Space verwenden!

Bei Fragen oder Problemen: Issue aufmachen oder Pull Request schicken.
