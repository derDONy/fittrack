# FitTrack — Dein persönlicher Fitness Tracker 💪

Ein Self-Hosted Fitness Tracker mit AI-Coach, optimiert für Synology NAS.

## Features

- **Geräte verwalten** — Trainingsgeräte anlegen (Latzug, Butterfly, Rudern etc.)
- **Training loggen** — Gewicht, Sätze, Wiederholungen, Notizen eintragen
- **Fortschrittsanalyse** — Trends, Volumenverlauf und persönliche Rekorde
- **Vernachlässigung erkennen** — Hinweis wenn Geräte >14 Tage nicht genutzt
- **AI Fitness Coach** — Trainingstipps via Anthropic Claude API
- **Docker-ready** — Ein Befehl, läuft auf deiner Synology NAS

## Schnellstart auf Synology NAS

### Voraussetzungen

- Synology NAS mit **Container Manager** (ehemals Docker)
- SSH-Zugang zur NAS (aktivierbar unter: Systemsteuerung → Terminal & SNMP)
- Optional: Anthropic API Key für AI-Coach (https://console.anthropic.com/)

### Schritt 1: Dateien auf die NAS kopieren

Kopiere den gesamten `fittrack/` Ordner auf deine NAS, z.B. nach `/volume1/docker/fittrack/`.

```bash
# Per SCP vom Computer:
scp -r fittrack/ dein-user@NAS-IP:/volume1/docker/fittrack/
```

### Schritt 2: Umgebungsvariablen setzen

```bash
cd /volume1/docker/fittrack
cp .env.example .env
nano .env  # API Key eintragen
```

### Schritt 3: Container starten

```bash
cd /volume1/docker/fittrack
sudo docker-compose up -d --build
```

### Schritt 4: Öffnen

Öffne im Browser: **http://NAS-IP:8484**

---

## Aus dem Internet erreichbar machen

### Option A: Synology Reverse Proxy (empfohlen)

1. **Systemsteuerung** → **Anmeldeportal** → **Erweitert** → **Reverse Proxy**
2. Neue Regel erstellen:
   - **Beschreibung:** FitTrack
   - **Quelle:**
     - Protokoll: HTTPS
     - Hostname: fittrack.deine-domain.de
     - Port: 443
   - **Ziel:**
     - Protokoll: HTTP
     - Hostname: localhost
     - Port: 8484
3. DDNS einrichten: **Systemsteuerung** → **Externer Zugriff** → **DDNS**
4. Let's Encrypt Zertifikat: **Systemsteuerung** → **Sicherheit** → **Zertifikat**

### Option B: Cloudflare Tunnel (kein Port-Forwarding nötig)

1. Cloudflare-Konto erstellen und Domain hinzufügen
2. `cloudflared` auf der NAS installieren
3. Tunnel konfigurieren:

```bash
cloudflared tunnel create fittrack
cloudflared tunnel route dns fittrack fittrack.deine-domain.de
```

4. Config erstellen (`~/.cloudflared/config.yml`):
```yaml
tunnel: <tunnel-id>
credentials-file: ~/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: fittrack.deine-domain.de
    service: http://localhost:8484
  - service: http_status:404
```

5. Starten: `cloudflared tunnel run fittrack`

### Option C: Tailscale / WireGuard VPN

Für privaten Zugriff ohne öffentliche Erreichbarkeit.

---

## Sicherheitshinweise

⚠️ **Wichtig wenn aus dem Internet erreichbar:**

- Immer HTTPS verwenden (Let's Encrypt)
- Starken SECRET_KEY in `.env` setzen
- Regelmäßig Updates einspielen
- Optional: Basic Auth über den Reverse Proxy konfigurieren

Für Basic Auth im Synology Reverse Proxy:
Nutze eine `.htpasswd` Datei und konfiguriere den Nginx im Reverse Proxy.

---

## Technische Details

| Komponente | Technologie |
|-----------|------------|
| Backend | Python 3.11, Flask |
| Datenbank | SQLite (persistent via Docker Volume) |
| Frontend | Vanilla HTML/CSS/JS |
| AI | Anthropic Claude API |
| Container | Docker + docker-compose |

### API Endpunkte

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| GET | `/api/machines` | Alle Geräte |
| POST | `/api/machines` | Gerät anlegen |
| PUT | `/api/machines/:id` | Gerät bearbeiten |
| DELETE | `/api/machines/:id` | Gerät archivieren |
| GET | `/api/workouts` | Trainings abrufen |
| POST | `/api/workouts` | Training eintragen |
| DELETE | `/api/workouts/:id` | Training löschen |
| GET | `/api/analytics/overview` | Dashboard-Statistiken |
| GET | `/api/analytics/machine/:id` | Geräte-Analyse |
| GET | `/api/analytics/history` | Volumen-Verlauf |
| POST | `/api/ai/tips` | AI Coach Tipps |

### Daten-Backup

Die Datenbank liegt im Docker Volume `fittrack_data`.

```bash
# Backup erstellen
docker cp fittrack:/app/data/fittrack.db ./fittrack_backup_$(date +%Y%m%d).db

# Backup wiederherstellen
docker cp ./fittrack_backup.db fittrack:/app/data/fittrack.db
docker restart fittrack
```

---

## Troubleshooting

**Container startet nicht:**
```bash
docker-compose logs fittrack
```

**Port belegt:**
Ändere in `docker-compose.yml` den Port z.B. auf `"9090:8484"`.

**AI Coach funktioniert nicht:**
Prüfe ob `ANTHROPIC_API_KEY` in der `.env` korrekt gesetzt ist.

**Datenbank zurücksetzen:**
```bash
docker-compose down
docker volume rm fittrack_fittrack_data
docker-compose up -d --build
```
