# FitTrack — Dein persönlicher Fitness Tracker 💪

Ein selbst gehosteter Fitness-Tracker mit AI-Coach, optimiert für die Synology NAS (oder jeden anderen Docker-Host). Deine Trainingsdaten bleiben auf deinem eigenen Server — keine Cloud, kein Tracking durch Dritte.

> ⚠️ **Wichtig:** FitTrack ist speziell für **Krafttraining an Geräten im Gym** gebaut (Dropsätze, Negativtraining, Sätze/Wiederholungen/Gewicht) plus eine einfache Laufband-Erfassung. Es ist **kein** allgemeiner Fitness-Tracker für Yoga, Mannschaftssport, Schwimmen, Radfahren o. ä. — dafür fehlen die passenden Datenfelder und Auswertungen.

🇬🇧 *[English version below](#fittrack--your-personal-fitness-tracker-)*

---

## 🇩🇪 Deutsch

### Features

- Training mit drei Methoden: Dropsatz, Negativtraining (auch einzeln links/rechts), Normal
- Trainingspläne, Geräteverwaltung, Verlauf, Dashboard mit Diagrammen
- Befinden-Tracking (Stimmung, Schlaf, Gelenke, Trinken)
- Optionaler AI-Coach über die Anthropic API
- Installierbar als PWA auf dem Smartphone
- API-Token-System für externen, lesenden Zugriff auf deine Daten

### Voraussetzungen

- Ein Server mit Docker und Docker Compose (z. B. Synology NAS, Raspberry Pi, beliebiger Linux-Host)
- Optional: ein Reverse Proxy / Tunnel (z. B. Cloudflare Tunnel), wenn die App von außerhalb deines Netzwerks erreichbar sein soll

### Installation

1. Repository klonen oder herunterladen
2. `.env` Datei im Projektordner anlegen (siehe unten) — **diese Datei niemals committen, sie ist bereits in `.gitignore` ausgeschlossen**
3. `docker compose up -d --build` ausführen
4. App unter `http://<server-ip>:8484` öffnen

### Was du in der `.env` Datei selbst setzen musst

Es gibt keine vorausgefüllte `.env` im Repository — du legst sie selbst an. Folgende Variablen werden von `docker-compose.yml` erwartet:

```env
# Pflicht für eigenen Login — beim ersten Start wird damit dein Account angelegt
FITTRACK_USER=dein_benutzername
FITTRACK_PASS=dein_start_passwort

# Pflicht für einen langen, zufälligen geheimen Schlüssel (mind. 32 Zeichen)
# z. B. erzeugen mit: openssl rand -hex 32
SECRET_KEY=ein-langer-zufaelliger-string

# Optional — nur nötig, wenn du den AI-Coach nutzen willst
ANTHROPIC_API_KEY=

# Optional — Rate-Limiting beim Login anpassen (Defaults siehe unten)
LOGIN_MAX_ATTEMPTS=10
LOGIN_WINDOW_MINUTES=10

# Optional — nur im Notfall setzen, um das Passwort zurückzusetzen,
# danach Zeile wieder entfernen und Container neu starten
FITTRACK_RESET_PASS=
```

**Wichtig:**
- `FITTRACK_USER` / `FITTRACK_PASS` werden **nur beim allerersten Start** verwendet, wenn die Datenbank noch leer ist. Danach läuft der Login über die in der App gespeicherten Zugangsdaten — ändere dein Passwort am besten direkt nach dem ersten Login in der App selbst (Tab „Mehr" → Passwort ändern).
- Ohne `SECRET_KEY` generiert die App bei jedem Neustart einen neuen zufälligen Schlüssel — das würde alle Sessions ungültig machen. Setze unbedingt einen festen Wert.
- Wenn du `ANTHROPIC_API_KEY` leer lässt, funktioniert die App ganz normal — nur der AI-Coach-Button zeigt dann einen Hinweis statt einer Antwort.

### Eigene Domain / Basis-URL anpassen

Im Frontend (`index.html`) gibt es im Tab „API" eine Beispiel-URL (`https://deine-domain.example.com`) als Anzeigehilfe für die API-Endpunkte. Das ist nur Anzeigetext — du musst dort nichts ändern, die App funktioniert unabhängig davon unter der Domain, die du selbst per Reverse Proxy einrichtest.

### Wichtige Hinweise für den Betrieb

- Wenn du die App hinter einem Reverse Proxy/Tunnel betreibst, der TLS extern terminiert (z. B. Cloudflare Tunnel), muss die interne Verbindung über `http://`, nicht `https://`, laufen — sonst kommt es zu 502-Fehlern.
- Das Docker-Volume (`fittrack_data`) enthält deine Datenbank. Lösche es nicht versehentlich, sonst sind alle Trainingsdaten weg.
- Beim Neu-Erstellen des Compose-Projekts sollte der Projektname identisch bleiben — sonst legt Docker ein neues, leeres Volume an.

### Lizenz

Dieses Projekt steht unter der [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.de) Lizenz (Namensnennung – Nicht-kommerziell – Weitergabe unter gleichen Bedingungen).

Kurz gesagt:
- ✅ Du darfst forken, verändern und für dich selbst (privat) nutzen
- ✅ Nenne dabei `derDONy` als ursprünglichen Autor
- ❌ Keine kommerzielle Nutzung
- ✅ Wenn du deine veränderte Version veröffentlichst, muss sie unter derselben Lizenz stehen

Vollständiger Lizenztext: siehe [`LICENSE`](LICENSE)

---

## 🇬🇧 English

A self-hosted fitness tracker with an AI coach, built for Synology NAS (or any other Docker host). Your training data stays on your own server — no cloud, no third-party tracking.

> ⚠️ **Note:** FitTrack is specifically built for **strength training on gym machines** (drop sets, negative training, sets/reps/weight) plus basic treadmill logging. It is **not** a general-purpose fitness tracker for yoga, team sports, swimming, cycling, etc. — the data fields and analytics simply don't cover those.

### Features

- Training with three methods: drop sets, negative training (including separate left/right), normal sets
- Training plans, machine management, history, dashboard with charts
- Wellbeing tracking (mood, sleep, joints, hydration)
- Optional AI coach via the Anthropic API
- Installable as a PWA on your phone
- API token system for read-only external access to your data

### Requirements

- A server with Docker and Docker Compose (e.g. Synology NAS, Raspberry Pi, any Linux host)
- Optional: a reverse proxy / tunnel (e.g. Cloudflare Tunnel) if you want the app reachable from outside your network

### Installation

1. Clone or download this repository
2. Create a `.env` file in the project folder (see below) — **never commit this file, it's already excluded via `.gitignore`**
3. Run `docker compose up -d --build`
4. Open the app at `http://<server-ip>:8484`

### What you need to set yourself in the `.env` file

There is no pre-filled `.env` in this repository — you create it yourself. `docker-compose.yml` expects the following variables:

```env
# Required for your own login — used to create your account on first start
FITTRACK_USER=your_username
FITTRACK_PASS=your_starting_password

# Required — a long, random secret key (at least 32 characters)
# e.g. generate one with: openssl rand -hex 32
SECRET_KEY=a-long-random-string

# Optional — only needed if you want to use the AI coach
ANTHROPIC_API_KEY=

# Optional — adjust login rate limiting (defaults shown below)
LOGIN_MAX_ATTEMPTS=10
LOGIN_WINDOW_MINUTES=10

# Optional — only set this in an emergency to reset your password,
# then remove the line again and restart the container
FITTRACK_RESET_PASS=
```

**Important:**
- `FITTRACK_USER` / `FITTRACK_PASS` are **only used on the very first start**, when the database is still empty. After that, login uses the credentials stored in the app — it's best to change your password right after the first login, inside the app itself (tab "More" → Change password).
- Without a fixed `SECRET_KEY`, the app generates a new random key on every restart, which would invalidate all sessions. Make sure to set a fixed value.
- If you leave `ANTHROPIC_API_KEY` empty, the app works completely normally — the AI coach button will just show a notice instead of a response.

### Customizing your own domain / base URL

In the frontend (`index.html`), the "API" tab shows an example URL (`https://deine-domain.example.com`) as a display hint for the API endpoints. This is just display text — you don't need to change anything there; the app works independently of it, under whatever domain you set up via your own reverse proxy.

### Operational notes

- If you run the app behind a reverse proxy/tunnel that terminates TLS externally (e.g. Cloudflare Tunnel), the internal connection must use `http://`, not `https://` — otherwise you'll get 502 errors.
- The Docker volume (`fittrack_data`) holds your database. Don't delete it accidentally, or you'll lose all your training data.
- When recreating the Compose project, keep the project name identical — otherwise Docker will create a new, empty volume.

### License

This project is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) (Attribution – NonCommercial – ShareAlike).

In short:
- ✅ You may fork, modify, and use it for yourself (privately)
- ✅ Credit `derDONy` as the original author
- ❌ No commercial use
- ✅ If you publish your modified version, it must be under the same license

Full license text: see [`LICENSE`](LICENSE)
