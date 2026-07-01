# FitTrack Backend — siehe APP_VERSION unten für aktuelle Versionsnummer
import os
import json
import sqlite3
import hashlib
import secrets
import functools
import time
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, session

APP_VERSION = "0.10.4"

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ── Session Security ────────────────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Hinweis: SESSION_COOKIE_SECURE ist absichtlich nicht gesetzt, da Cloudflare
# TLS extern terminiert und intern HTTP nutzt (sonst funktionieren Cookies nicht)

# ── Startup-Check: unsicherer Default-Key ───────────────────────────────────
_KNOWN_WEAK_KEYS = {'change-me-in-production', 'changeme', 'secret', 'password'}
if app.secret_key in _KNOWN_WEAK_KEYS:
    import sys
    print(
        "\n[FitTrack] ⚠️  WARNUNG: Standard SECRET_KEY wird verwendet!\n"
        "           Bitte in der .env Datei einen langen zufälligen Wert setzen.\n"
        "           Bis dahin können Session-Cookies gefälscht werden!\n",
        file=sys.stderr
    )

# ── Login Rate-Limiting ─────────────────────────────────────────────────────
# Konfigurierbar via .env: LOGIN_MAX_ATTEMPTS und LOGIN_WINDOW_MINUTES
_login_attempts: dict = defaultdict(list)
_LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', '10'))
_LOGIN_WINDOW_SECONDS = int(os.environ.get('LOGIN_WINDOW_MINUTES', '10')) * 60

def _check_login_rate_limit(ip: str):
    """Gibt (erlaubt, verbleibende_versuche, warte_sekunden) zurück."""
    now = time.time()
    attempts = _login_attempts[ip]
    attempts[:] = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        oldest = min(attempts) if attempts else now
        wait = max(1, int(_LOGIN_WINDOW_SECONDS - (now - oldest)) + 1)
        return False, 0, wait
    attempts.append(now)
    remaining = _LOGIN_MAX_ATTEMPTS - len(attempts)
    return True, remaining, 0

# ── HTTP Security Headers ───────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    # Verhindert MIME-Type Sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Verhindert Einbettung als iFrame (Clickjacking-Schutz)
    response.headers['X-Frame-Options'] = 'DENY'
    # Minimiert Referrer-Informationen
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Schränkt Browser-Berechtigungen ein
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Content Security Policy
    # unsafe-inline ist nötig, da das Frontend Inline-JS/CSS nutzt
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://api.anthropic.com; "
        "img-src 'self' data: blob:;"
    )
    return response

DB_PATH = os.environ.get('DB_PATH', '/app/data/fittrack.db')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')


# ── Database Setup ──────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200000)
    return salt + ':' + h.hex()


def verify_password(password, stored):
    salt = stored.split(':')[0]
    return hash_password(password, salt) == stored


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_number TEXT DEFAULT '',
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Sonstige',
            muscle_group TEXT NOT NULL DEFAULT '',
            seat_settings TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            tracking_type TEXT NOT NULL DEFAULT 'kraft',
            created_at TEXT DEFAULT (datetime('now')),
            archived INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS workouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id INTEGER NOT NULL,
            workout_date TEXT NOT NULL,
            sets INTEGER NOT NULL DEFAULT 1,
            reps INTEGER NOT NULL,
            weight REAL NOT NULL,
            duration_seconds INTEGER DEFAULT NULL,
            training_method TEXT DEFAULT 'normal',
            drop_set_num INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (machine_id) REFERENCES machines(id)
        );

        CREATE TABLE IF NOT EXISTS training_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            training_method TEXT DEFAULT 'dropsatz',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS plan_machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id INTEGER NOT NULL,
            machine_id INTEGER NOT NULL,
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY (plan_id) REFERENCES training_plans(id) ON DELETE CASCADE,
            FOREIGN KEY (machine_id) REFERENCES machines(id)
        );

        CREATE TABLE IF NOT EXISTS wellbeing_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_date TEXT NOT NULL,
            mood INTEGER NOT NULL DEFAULT 3,
            sleep INTEGER NOT NULL DEFAULT 3,
            hydration REAL DEFAULT NULL,
            joints INTEGER DEFAULT NULL,
            notes TEXT DEFAULT '',
            is_training_day INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            scopes TEXT NOT NULL DEFAULT 'read',
            created_at TEXT DEFAULT (datetime('now')),
            last_used TEXT DEFAULT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_workouts_machine ON workouts(machine_id);
        CREATE INDEX IF NOT EXISTS idx_workouts_date ON workouts(workout_date);
        CREATE INDEX IF NOT EXISTS idx_plan_machines ON plan_machines(plan_id);
        CREATE INDEX IF NOT EXISTS idx_wellbeing_date ON wellbeing_logs(log_date);
        CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
    """)

    # ── Migrate old databases: add missing columns ──
    def col_exists(table, col):
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        return col in cols

    if not col_exists('machines', 'machine_number'):
        conn.execute("ALTER TABLE machines ADD COLUMN machine_number TEXT DEFAULT ''")
    if not col_exists('machines', 'seat_settings'):
        conn.execute("ALTER TABLE machines ADD COLUMN seat_settings TEXT DEFAULT ''")
    if not col_exists('workouts', 'training_method'):
        conn.execute("ALTER TABLE workouts ADD COLUMN training_method TEXT DEFAULT 'normal'")
    if not col_exists('workouts', 'drop_set_num'):
        conn.execute("ALTER TABLE workouts ADD COLUMN drop_set_num INTEGER DEFAULT 0")
    if not col_exists('machines', 'tracking_type'):
        conn.execute("ALTER TABLE machines ADD COLUMN tracking_type TEXT NOT NULL DEFAULT 'kraft'")
        # Bestehende Cardio-Geräte (z.B. Laufband) auf den Cardio-Tracking-Typ setzen
        conn.execute("UPDATE machines SET tracking_type = 'cardio' WHERE category = 'Cardio'")
    conn.commit()

    # Create default user if no users exist
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        default_user = os.environ.get('FITTRACK_USER', 'admin')
        default_pass = os.environ.get('FITTRACK_PASS', 'changeme')
        pw_hash = hash_password(default_pass)
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (default_user, pw_hash)
        )
        print(f"[FitTrack] Default-User '{default_user}' erstellt.")

    # Seed default machines if empty
    count = conn.execute("SELECT COUNT(*) FROM machines").fetchone()[0]
    if count == 0:
        # (number, name, category, muscle_group, seat_settings)
        defaults = [
            ("01", "Brustpresse", "Drückübungen", "Brust, Trizeps", "h7"),
            ("02", "Butterfly", "Drückübungen", "Brust", "h7"),
            ("03", "Rudern sitzend", "Zugübungen", "Rücken, Bizeps", "h7"),
            ("", "Schrägbrustpresse", "Drückübungen", "Obere Brust, Trizeps", ""),
            ("05", "Latzug", "Zugübungen", "Rücken, Bizeps", "h9"),
            ("", "Latzug vertikal", "Zugübungen", "Latissimus, Bizeps", ""),
            ("", "Rudern oberer Rücken", "Zugübungen", "Oberer Rücken, Hintere Schulter", ""),
            ("06", "Schulterpresse", "Drückübungen", "Schultern, Trizeps", "h9"),
            ("21", "Seitheben", "Drückübungen", "Seitliche Schulter", "h8"),
            ("22", "Bizepsmaschine", "Arme", "Bizeps", "h6"),
            ("23", "Trizepsmaschine", "Arme", "Trizeps", "h6"),
            ("07", "Beinpresse", "Beine", "Oberschenkel, Gesäß", "bh2 sh4"),
            ("", "Beinstrecker", "Beine", "Quadrizeps", ""),
            ("", "Beinbeuger sitzend", "Beine", "Hinterer Oberschenkel", ""),
            ("09", "Adduktoren", "Beine", "Innenschenkel", ""),
            ("08", "Abduktoren", "Beine", "Außenschenkel, Gesäß", ""),
            ("", "Gluteusmaschine", "Beine", "Gesäß", ""),
            ("18", "Bauchmaschine", "Core", "Bauch", "2"),
            ("13", "Rückenstreckung", "Core", "Unterer Rücken", ""),
            ("120", "Rumpftorsion", "Core", "Seitlicher Bauch", ""),
            ("", "Dip's unten", "Drückübungen", "Brust, Trizeps", ""),
            ("", "Dip's Klimmzug", "Zugübungen", "Rücken, Bizeps", ""),
            ("", "Laufband", "Cardio", "Ausdauer", ""),
        ]
        conn.executemany(
            "INSERT INTO machines (machine_number, name, category, muscle_group, seat_settings) VALUES (?, ?, ?, ?, ?)",
            defaults
        )
        # Tracking-Typen für die Default-Geräte setzen (executemany oben nutzt den 'kraft'-Default)
        conn.execute("UPDATE machines SET tracking_type = 'cardio' WHERE name = 'Laufband'")
        conn.execute(
            "INSERT INTO machines (machine_number, name, category, muscle_group, seat_settings, tracking_type) "
            "VALUES ('', 'Planking', 'Eigengewicht', 'Core/Rumpf', '', 'halten')"
        )

    conn.commit()
    conn.close()


# ── Auth Middleware ──────────────────────────────────────────────────────────

def _verify_api_token(token: str):
    """Prüft einen API-Token und gibt (token_row | None) zurück."""
    if not token or not token.startswith('ft_'):
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM api_tokens WHERE token_hash = ?", (token_hash,)
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE api_tokens SET last_used = datetime('now') WHERE id = ?", (row['id'],)
        )
        conn.commit()
    conn.close()
    return row


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Session-Auth
        if session.get('user_id'):
            return f(*args, **kwargs)
        # Bearer-Token Auth
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            row = _verify_api_token(token)
            if row:
                return f(*args, **kwargs)
        return jsonify({"error": "Nicht eingeloggt"}), 401
    return decorated


def api_read_required(f):
    """Für API-Endpunkte: Session ODER gültiger Token mit read-Scope."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if session.get('user_id'):
            return f(*args, **kwargs)
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            row = _verify_api_token(token)
            if row:
                return f(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return decorated


# ── Serve Frontend ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')


# ── Auth API ────────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def login():
    ip = request.remote_addr or 'unknown'
    allowed, remaining, wait_secs = _check_login_rate_limit(ip)
    if not allowed:
        mins, secs = divmod(wait_secs, 60)
        wait_str = f"{mins}:{secs:02d}" if mins > 0 else f"{secs} Sek."
        return jsonify({
            "error": f"Zu viele Fehlversuche — noch {wait_str} warten.",
            "locked": True,
            "wait_seconds": wait_secs
        }), 429

    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({"error": "Benutzername und Passwort erforderlich"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user or not verify_password(password, user['password_hash']):
        # Warnung wenn nur noch wenige Versuche übrig
        if remaining <= 3:
            return jsonify({
                "error": f"Falscher Benutzername oder Passwort. Noch {remaining} Versuch{'e' if remaining != 1 else ''} übrig.",
                "remaining": remaining
            }), 401
        return jsonify({"error": "Falscher Benutzername oder Passwort"}), 401
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=30)
    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({"ok": True, "username": user['username']})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    if session.get('user_id'):
        return jsonify({"logged_in": True, "username": session['username'], "version": APP_VERSION})
    return jsonify({"logged_in": False}), 401


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json or {}
    current = data.get('current_password', '')
    new_pass = data.get('new_password', '')
    if not current or not new_pass:
        return jsonify({"error": "Beide Passwörter erforderlich"}), 400
    if len(new_pass) < 6:
        return jsonify({"error": "Neues Passwort muss mindestens 6 Zeichen haben"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    if not verify_password(current, user['password_hash']):
        conn.close()
        return jsonify({"error": "Aktuelles Passwort ist falsch"}), 401
    new_hash = hash_password(new_pass)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user['id']))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ── Machines API ────────────────────────────────────────────────────────────

@app.route('/api/machines', methods=['GET'])
@login_required
def get_machines():
    conn = get_db()
    rows = conn.execute("SELECT * FROM machines WHERE archived = 0 ORDER BY category, name").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/machines', methods=['POST'])
@login_required
def add_machine():
    data = request.json
    if not data or not data.get('name'):
        return jsonify({"error": "Name ist erforderlich"}), 400
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO machines (machine_number, name, category, muscle_group, seat_settings, notes, tracking_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (data.get('machine_number', ''), data['name'], data.get('category', 'Sonstige'),
         data.get('muscle_group', ''), data.get('seat_settings', ''), data.get('notes', ''),
         data.get('tracking_type', 'kraft'))
    )
    conn.commit()
    machine = conn.execute("SELECT * FROM machines WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return jsonify(dict(machine)), 201


@app.route('/api/machines/<int:machine_id>', methods=['PUT'])
@login_required
def update_machine(machine_id):
    data = request.json
    conn = get_db()
    conn.execute(
        "UPDATE machines SET machine_number=?, name=?, category=?, muscle_group=?, seat_settings=?, notes=?, tracking_type=? WHERE id=?",
        (data.get('machine_number', ''), data.get('name', ''), data.get('category', 'Sonstige'),
         data.get('muscle_group', ''), data.get('seat_settings', ''), data.get('notes', ''),
         data.get('tracking_type', 'kraft'), machine_id)
    )
    conn.commit()
    machine = conn.execute("SELECT * FROM machines WHERE id = ?", (machine_id,)).fetchone()
    conn.close()
    return jsonify(dict(machine))


@app.route('/api/machines/<int:machine_id>', methods=['DELETE'])
@login_required
def archive_machine(machine_id):
    conn = get_db()
    conn.execute("UPDATE machines SET archived = 1 WHERE id = ?", (machine_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ── Training Plans API ──────────────────────────────────────────────────────

@app.route('/api/plans', methods=['GET'])
@login_required
def get_plans():
    conn = get_db()
    plans = conn.execute("SELECT * FROM training_plans ORDER BY created_at DESC").fetchall()
    result = []
    for p in plans:
        machines = conn.execute("""
            SELECT pm.*, m.machine_number, m.name, m.category, m.muscle_group, m.seat_settings, m.tracking_type
            FROM plan_machines pm JOIN machines m ON pm.machine_id = m.id
            WHERE pm.plan_id = ?
            ORDER BY pm.sort_order
        """, (p['id'],)).fetchall()
        result.append({**dict(p), "machines": [dict(m) for m in machines]})
    conn.close()
    return jsonify(result)


@app.route('/api/plans', methods=['POST'])
@login_required
def create_plan():
    data = request.json
    if not data or not data.get('name'):
        return jsonify({"error": "Name erforderlich"}), 400
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO training_plans (name, training_method) VALUES (?, ?)",
        (data['name'], data.get('training_method', 'dropsatz'))
    )
    plan_id = cur.lastrowid
    for i, mid in enumerate(data.get('machine_ids', [])):
        conn.execute(
            "INSERT INTO plan_machines (plan_id, machine_id, sort_order) VALUES (?, ?, ?)",
            (plan_id, mid, i)
        )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": plan_id}), 201


@app.route('/api/plans/<int:plan_id>', methods=['PUT'])
@login_required
def update_plan(plan_id):
    data = request.json
    conn = get_db()
    conn.execute(
        "UPDATE training_plans SET name=?, training_method=? WHERE id=?",
        (data.get('name', ''), data.get('training_method', 'dropsatz'), plan_id)
    )
    conn.execute("DELETE FROM plan_machines WHERE plan_id = ?", (plan_id,))
    for i, mid in enumerate(data.get('machine_ids', [])):
        conn.execute(
            "INSERT INTO plan_machines (plan_id, machine_id, sort_order) VALUES (?, ?, ?)",
            (plan_id, mid, i)
        )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route('/api/plans/<int:plan_id>', methods=['DELETE'])
@login_required
def delete_plan(plan_id):
    conn = get_db()
    conn.execute("DELETE FROM training_plans WHERE id = ?", (plan_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ── Workouts API ────────────────────────────────────────────────────────────

@app.route('/api/workouts', methods=['GET'])
@login_required
def get_workouts():
    conn = get_db()
    machine_id = request.args.get('machine_id')
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    if machine_id:
        rows = conn.execute("""
            SELECT w.*, m.name as machine_name, m.category, m.muscle_group
            FROM workouts w JOIN machines m ON w.machine_id = m.id
            WHERE w.machine_id = ? ORDER BY w.workout_date DESC, w.created_at DESC, w.id DESC
            LIMIT ? OFFSET ?
        """, (machine_id, limit, offset)).fetchall()
    else:
        rows = conn.execute("""
            SELECT w.*, m.name as machine_name, m.category, m.muscle_group
            FROM workouts w JOIN machines m ON w.machine_id = m.id
            ORDER BY w.workout_date DESC, w.created_at DESC, w.id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/workouts', methods=['POST'])
@login_required
def add_workout():
    data = request.json
    if not data:
        return jsonify({"error": "Daten fehlen"}), 400

    required = ['machine_id', 'reps', 'weight']
    for field in required:
        if field not in data:
            return jsonify({"error": f"{field} ist erforderlich"}), 400

    conn = get_db()
    cur = conn.execute(
        """INSERT INTO workouts (machine_id, workout_date, sets, reps, weight,
           duration_seconds, training_method, drop_set_num, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (data['machine_id'],
         data.get('workout_date', datetime.now().strftime('%Y-%m-%d')),
         data.get('sets', 1),
         data['reps'],
         data['weight'],
         data.get('duration_seconds'),
         data.get('training_method', 'normal'),
         data.get('drop_set_num', 0),
         data.get('notes', ''))
    )
    conn.commit()
    workout = conn.execute("""
        SELECT w.*, m.name as machine_name FROM workouts w
        JOIN machines m ON w.machine_id = m.id WHERE w.id = ?
    """, (cur.lastrowid,)).fetchone()
    conn.close()
    return jsonify(dict(workout)), 201


@app.route('/api/workouts/batch', methods=['POST'])
@login_required
def batch_save_workouts():
    """Save multiple workouts at once (for quick training mode)"""
    data = request.json
    if not data or not data.get('entries'):
        return jsonify({"error": "Keine Einträge"}), 400

    workout_date = data.get('workout_date', datetime.now().strftime('%Y-%m-%d'))
    training_method = data.get('training_method', 'dropsatz')
    entries = data['entries']

    conn = get_db()
    saved = 0
    for entry in entries:
        machine_id = entry.get('machine_id')
        drops = entry.get('drops', [])
        duration = entry.get('duration_seconds')
        notes = entry.get('notes', '')
        entry_method = entry.get('training_method', training_method)

        # Halten (z.B. Plank): jeder Satz ist eine gehaltene Dauer, kein Gewicht/Wdh.
        # Muss VOR der weight>0/reps>0-Prüfung behandelt werden, sonst würde er verworfen.
        if entry.get('tracking_type') == 'halten':
            for i, drop in enumerate(drops):
                dur = drop.get('duration') or 0
                if dur and dur > 0:
                    conn.execute(
                        """INSERT INTO workouts
                           (machine_id, workout_date, sets, reps, weight,
                            duration_seconds, training_method, drop_set_num, notes)
                           VALUES (?, ?, 1, 1, 0, ?, ?, ?, ?)""",
                        (machine_id, workout_date, dur, entry_method, i, notes)
                    )
                    saved += 1
            continue

        for i, drop in enumerate(drops):
            weight = drop.get('weight', 0)
            reps = drop.get('reps', 0)
            if weight > 0 and reps > 0:
                conn.execute(
                    """INSERT INTO workouts
                       (machine_id, workout_date, sets, reps, weight,
                        duration_seconds, training_method, drop_set_num, notes)
                       VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)""",
                    (machine_id, workout_date, reps, weight,
                     duration if i == 0 else None,
                     entry_method, i, notes)
                )
                saved += 1

    conn.commit()
    conn.close()
    return jsonify({"ok": True, "saved": saved})


@app.route('/api/workouts/last-session', methods=['GET'])
@login_required
def last_session():
    """Get the most recent workout per machine (for 'vorher:' display) - max 3 drops.
    Optional: ?method=dropsatz to filter by training method."""
    conn = get_db()
    machine_ids = request.args.get('machine_ids', '')
    method_filter = request.args.get('method', '')  # optional: dropsatz, negativ, normal
    if not machine_ids:
        conn.close()
        return jsonify({})

    ids = [int(x) for x in machine_ids.split(',') if x.strip().isdigit()]
    result = {}

    for mid in ids:
        # Find the most recent workout_date for this machine (optionally filtered by method)
        if method_filter:
            last_date_row = conn.execute("""
                SELECT MAX(workout_date) as last_date FROM workouts
                WHERE machine_id = ? AND training_method = ?
            """, (mid, method_filter)).fetchone()
        else:
            last_date_row = conn.execute("""
                SELECT MAX(workout_date) as last_date FROM workouts WHERE machine_id = ?
            """, (mid,)).fetchone()
        last_date = last_date_row['last_date'] if last_date_row else None

        if last_date:
            # Get only the LATEST entry per drop_set_num (0, 1, 2) — max 3 drops
            if method_filter:
                drops = conn.execute("""
                    SELECT weight, reps, drop_set_num, duration_seconds, training_method
                    FROM workouts
                    WHERE machine_id = ? AND workout_date = ? AND drop_set_num IN (0, 1, 2)
                        AND training_method = ?
                    GROUP BY drop_set_num
                    HAVING created_at = MAX(created_at)
                    ORDER BY drop_set_num ASC
                """, (mid, last_date, method_filter)).fetchall()
            else:
                drops = conn.execute("""
                    SELECT weight, reps, drop_set_num, duration_seconds, training_method
                    FROM workouts
                    WHERE machine_id = ? AND workout_date = ? AND drop_set_num IN (0, 1, 2)
                    GROUP BY drop_set_num
                    HAVING created_at = MAX(created_at)
                    ORDER BY drop_set_num ASC
                """, (mid, last_date)).fetchall()
            result[str(mid)] = {
                "date": last_date,
                "drops": [{"weight": d['weight'], "reps": d['reps'], "duration": d['duration_seconds']} for d in drops],
                "method": drops[0]['training_method'] if drops else 'dropsatz'
            }

    conn.close()
    return jsonify(result)


@app.route('/api/workouts/sessions', methods=['GET'])
@login_required
def workout_sessions():
    """Verlauf gruppiert: pro Trainingstag die Geräte mit Methode und allen Sätzen."""
    limit = request.args.get('limit', 30, type=int)  # Anzahl Trainingstage
    conn = get_db()
    dates = conn.execute(
        "SELECT DISTINCT workout_date FROM workouts ORDER BY workout_date DESC LIMIT ?",
        (limit,)
    ).fetchall()
    result = []
    for d in dates:
        date = d['workout_date']
        rows = conn.execute("""
            SELECT w.*, m.name as machine_name, m.machine_number, m.category, m.seat_settings, m.tracking_type
            FROM workouts w JOIN machines m ON w.machine_id = m.id
            WHERE w.workout_date = ?
            ORDER BY w.created_at ASC, w.id ASC
        """, (date,)).fetchall()
        groups = {}
        order = []
        for r in rows:
            # Gruppieren nach Gerät + Methode + Notes (trennt Links/Rechts bei Negativ Einzeln)
            key = (r['machine_id'], r['training_method'] or 'normal', r['notes'] or '')
            if key not in groups:
                groups[key] = {
                    'machine_id': r['machine_id'], 'name': r['machine_name'],
                    'machine_number': r['machine_number'], 'category': r['category'],
                    'seat_settings': r['seat_settings'], 'tracking_type': r['tracking_type'],
                    'method': r['training_method'] or 'normal', 'notes': r['notes'] or '',
                    'sets': []
                }
                order.append(key)
            groups[key]['sets'].append({
                'id': r['id'], 'weight': r['weight'], 'reps': r['reps'],
                'drop_set_num': r['drop_set_num'], 'duration_seconds': r['duration_seconds']
            })
        # Anzahl unterschiedlicher Geräte (L/R zählt als ein Gerät)
        machine_ids = {k[0] for k in order}
        result.append({
            'date': date,
            'machine_count': len(machine_ids),
            'set_count': len(rows),
            'machines': [groups[k] for k in order]
        })
    conn.close()
    return jsonify(result)


@app.route('/api/workouts/<int:workout_id>', methods=['DELETE'])
@login_required
def delete_workout(workout_id):
    conn = get_db()
    conn.execute("DELETE FROM workouts WHERE id = ?", (workout_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ── Analytics API ───────────────────────────────────────────────────────────

@app.route('/api/analytics/overview', methods=['GET'])
@login_required
def analytics_overview():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM workouts").fetchone()[0]
    week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    this_week = conn.execute("SELECT COUNT(*) FROM workouts WHERE workout_date >= ?", (week_ago,)).fetchone()[0]
    month_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    this_month = conn.execute("SELECT COUNT(*) FROM workouts WHERE workout_date >= ?", (month_ago,)).fetchone()[0]
    active_days = conn.execute("SELECT COUNT(DISTINCT workout_date) FROM workouts WHERE workout_date >= ?", (month_ago,)).fetchone()[0]
    neglected = conn.execute("""
        SELECT m.id, m.name, m.muscle_group, MAX(w.workout_date) as last_used
        FROM machines m LEFT JOIN workouts w ON m.id = w.machine_id
        WHERE m.archived = 0
        GROUP BY m.id
        HAVING last_used IS NULL OR last_used < ?
        ORDER BY last_used ASC
    """, ((datetime.now() - timedelta(days=14)).strftime('%Y-%m-%d'),)).fetchall()
    conn.close()
    return jsonify({
        "total_workouts": total, "workouts_this_week": this_week,
        "workouts_this_month": this_month, "active_days_this_month": active_days,
        "neglected_machines": [dict(r) for r in neglected]
    })


@app.route('/api/analytics/machine/<int:machine_id>', methods=['GET'])
@login_required
def analytics_machine(machine_id):
    conn = get_db()
    machine = conn.execute("SELECT * FROM machines WHERE id = ?", (machine_id,)).fetchone()
    if not machine:
        conn.close()
        return jsonify({"error": "Gerät nicht gefunden"}), 404
    workouts = conn.execute("""
        SELECT * FROM workouts WHERE machine_id = ?
        ORDER BY workout_date ASC, created_at ASC
    """, (machine_id,)).fetchall()
    workouts_list = [dict(w) for w in workouts]
    progress = {"trend": "neutral"}
    if len(workouts_list) >= 2:
        recent = workouts_list[-5:]
        older = workouts_list[:5]
        avg_recent_vol = sum(w['weight'] * w['reps'] * w['sets'] for w in recent) / len(recent)
        avg_older_vol = sum(w['weight'] * w['reps'] * w['sets'] for w in older) / len(older)
        change_pct = ((avg_recent_vol - avg_older_vol) / avg_older_vol * 100) if avg_older_vol > 0 else 0
        progress["trend"] = "up" if change_pct > 5 else ("down" if change_pct < -5 else "neutral")
        progress["weight_change"] = round(sum(w['weight'] for w in recent)/len(recent) - sum(w['weight'] for w in older)/len(older), 1)
        progress["reps_change"] = round(sum(w['reps'] for w in recent)/len(recent) - sum(w['reps'] for w in older)/len(older), 1)
        progress["volume_change_pct"] = round(change_pct, 1)
    pr_weight = conn.execute("SELECT MAX(weight) FROM workouts WHERE machine_id = ?", (machine_id,)).fetchone()[0]
    pr_volume = conn.execute("SELECT MAX(weight * reps * sets) FROM workouts WHERE machine_id = ?", (machine_id,)).fetchone()[0]
    conn.close()
    return jsonify({
        "machine": dict(machine), "workouts": workouts_list, "progress": progress,
        "personal_records": {"max_weight": pr_weight, "max_volume": pr_volume}
    })


@app.route('/api/analytics/history', methods=['GET'])
@login_required
def analytics_history():
    conn = get_db()
    days = request.args.get('days', 90, type=int)
    start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    rows = conn.execute("""
        SELECT workout_date, COUNT(*) as count, SUM(weight * reps * sets) as total_volume
        FROM workouts WHERE workout_date >= ? GROUP BY workout_date ORDER BY workout_date ASC
    """, (start,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Wellbeing API ───────────────────────────────────────────────────────────

@app.route('/api/wellbeing', methods=['POST'])
@login_required
def save_wellbeing():
    data = request.json
    if not data:
        return jsonify({"error": "Daten fehlen"}), 400
    log_date = data.get('log_date', datetime.now().strftime('%Y-%m-%d'))
    # Upsert: replace if same date exists
    conn = get_db()
    existing = conn.execute("SELECT id FROM wellbeing_logs WHERE log_date = ?", (log_date,)).fetchone()
    if existing:
        conn.execute("""
            UPDATE wellbeing_logs SET mood=?, sleep=?, hydration=?, joints=?, notes=?, is_training_day=?
            WHERE id=?
        """, (data.get('mood', 3), data.get('sleep', 3), data.get('hydration'),
              data.get('joints'), data.get('notes', ''), data.get('is_training_day', 1), existing['id']))
    else:
        conn.execute("""
            INSERT INTO wellbeing_logs (log_date, mood, sleep, hydration, joints, notes, is_training_day)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (log_date, data.get('mood', 3), data.get('sleep', 3), data.get('hydration'),
              data.get('joints'), data.get('notes', ''), data.get('is_training_day', 1)))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route('/api/wellbeing', methods=['GET'])
@login_required
def get_wellbeing():
    conn = get_db()
    days = request.args.get('days', 90, type=int)
    start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    rows = conn.execute("""
        SELECT * FROM wellbeing_logs WHERE log_date >= ? ORDER BY log_date ASC
    """, (start,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/wellbeing/today', methods=['GET'])
@login_required
def get_wellbeing_today():
    conn = get_db()
    today = datetime.now().strftime('%Y-%m-%d')
    row = conn.execute("SELECT * FROM wellbeing_logs WHERE log_date = ?", (today,)).fetchone()
    conn.close()
    return jsonify(dict(row) if row else {})


# ── AI Coach API ────────────────────────────────────────────────────────────

@app.route('/api/ai/tips', methods=['POST'])
@login_required
def ai_tips():
    if not ANTHROPIC_API_KEY:
        return jsonify({"tip": "⚠️ Kein Anthropic API Key konfiguriert. Setze ANTHROPIC_API_KEY in deiner .env Datei."})
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        conn = get_db()
        overview = {}
        overview['total'] = conn.execute("SELECT COUNT(*) FROM workouts").fetchone()[0]
        week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        overview['this_week'] = conn.execute("SELECT COUNT(*) FROM workouts WHERE workout_date >= ?", (week_ago,)).fetchone()[0]
        recent = conn.execute("""
            SELECT w.workout_date, m.name, m.muscle_group, w.sets, w.reps, w.weight,
                   w.training_method, w.drop_set_num
            FROM workouts w JOIN machines m ON w.machine_id = m.id
            ORDER BY w.workout_date DESC LIMIT 30
        """).fetchall()
        recent_list = [dict(r) for r in recent]
        neglected = conn.execute("""
            SELECT m.name, m.muscle_group, MAX(w.workout_date) as last_used
            FROM machines m LEFT JOIN workouts w ON m.id = w.machine_id
            WHERE m.archived = 0 GROUP BY m.id
            HAVING last_used IS NULL OR last_used < ?
        """, ((datetime.now() - timedelta(days=14)).strftime('%Y-%m-%d'),)).fetchall()
        neglected_list = [dict(r) for r in neglected]
        progress = conn.execute("""
            SELECT m.name, COUNT(w.id) as total_workouts, MIN(w.weight) as min_weight,
                   MAX(w.weight) as max_weight, AVG(w.weight) as avg_weight
            FROM machines m JOIN workouts w ON m.id = w.machine_id
            WHERE m.archived = 0 GROUP BY m.id
        """).fetchall()
        progress_list = [dict(r) for r in progress]
        wellbeing = conn.execute("""
            SELECT log_date, mood, sleep, hydration, joints, is_training_day
            FROM wellbeing_logs ORDER BY log_date DESC LIMIT 14
        """).fetchall()
        wellbeing_list = [dict(r) for r in wellbeing]
        conn.close()
        user_query = request.json.get('query', '') if request.json else ''
        context = f"""Du bist ein erfahrener Fitness-Coach. Duze den Nutzer immer.

ÜBER DEN NUTZER:
- Trainiert bei FitX an Technogym Selection Geräten (wenn du Tipps zu Einstellungen oder Ausführung hast, nutze dein Wissen über diese Geräte)
- Fokus liegt auf OBERKÖRPER — Beine werden bewusst nicht an Maschinen trainiert, da das Laufband-Programm die Beinmuskulatur bereits ausreichend beansprucht
- Hat rheumatoide Arthritis — an manchen Tagen sind die Gelenke steif oder schmerzhaft, dann schafft er weniger als geplant. Das ist kein Motivationsproblem, sondern die Erkrankung. Sei verständnisvoll, aber nicht bemitleidend.
- Trainiert aktuell Dropsätze (hohes Gewicht bis Muskelversagen → -10kg → Versagen → -10kg). Wechselt bald zu Negativtraining.

LAUFBAND-ROUTINE (Technogym Laufband):
- 5 km pro Session, kein Spaziergang
- Erste 4 km: Steigung 1-2, Geschwindigkeit 10,4
- Letzter Kilometer variiert: meist 2-3 Intervalle à 1 Min bei Geschwindigkeit 9 / Steigung 15 (Maximum)
- Letzte 100-300m: Steigung 2, Geschwindigkeit 15 (Sprint-Finish)
- Das ist ein ernsthaftes Cardio- und Beintraining — berücksichtige das bei Empfehlungen

TRAININGSDATEN:
Gesamt: {overview['total']} Einträge, {overview['this_week']} diese Woche

Letzte Trainings:
{json.dumps(recent_list, ensure_ascii=False, indent=2)}

Vernachlässigt (>14 Tage):
{json.dumps(neglected_list, ensure_ascii=False, indent=2)}

Fortschritt:
{json.dumps(progress_list, ensure_ascii=False, indent=2)}

BEFINDEN (letzte 14 Einträge, mood/sleep/joints: 1=super 2=gut 3=mäßig 4=schlecht, hydration in Liter):
{json.dumps(wellbeing_list, ensure_ascii=False, indent=2)}

ANTWORT-REGELN:
- Kurz und knackig, max 200 Wörter
- Deutsch, motivierend aber ehrlich
- Duzen!
- Keine Bein-Maschinen empfehlen (Laufband reicht)
- Bei schwachen Tagen: könnte die Arthritis sein, nicht gleich Übertraining vermuten
- Beziehe die Befinden-Daten ein: Schlaf, Gelenke, Stimmung korrelieren mit Trainingsleistung
- Emojis sparsam (max 2-3)"""
        if user_query:
            context += f"\n\nSpezifische Frage: {user_query}"
        response = client.messages.create(
            model="claude-haiku-4-5-20251001", max_tokens=512,
            messages=[{"role": "user", "content": context}]
        )
        return jsonify({"tip": response.content[0].text})
    except Exception as e:
        app.logger.error(f"[FitTrack] AI-Fehler: {e}")
        return jsonify({"tip": "Fehler bei der AI-Analyse. Bitte später erneut versuchen."}), 500


# ── API Token Management ────────────────────────────────────────────────────

@app.route('/api/tokens', methods=['GET'])
@login_required
def get_tokens():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, token_prefix, scopes, created_at, last_used FROM api_tokens ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/tokens', methods=['POST'])
@login_required
def create_token():
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({"error": "Name erforderlich"}), 400
    scopes = data.get('scopes', 'read')
    # Token generieren: ft_ + 32 zufällige Zeichen
    raw_token = 'ft_' + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_prefix = raw_token[:10] + '...'
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO api_tokens (name, token_hash, token_prefix, scopes) VALUES (?, ?, ?, ?)",
        (name, token_hash, token_prefix, scopes)
    )
    conn.commit()
    conn.close()
    # Token wird NUR einmal zurückgegeben — danach nicht mehr abrufbar!
    return jsonify({"ok": True, "id": cur.lastrowid, "token": raw_token, "prefix": token_prefix}), 201


@app.route('/api/tokens/<int:token_id>', methods=['DELETE'])
@login_required
def delete_token(token_id):
    conn = get_db()
    conn.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ── Public API (Token-Auth) ─────────────────────────────────────────────────

# Klartext-Labels für Befinden-Werte, damit externe Tools (z.B. Cowork) die
# rohen Zahlen ohne Kenntnis des Frontend-Codes korrekt einordnen können.
# Müssen mit den Optionen im Frontend (index.html, Befinden-Modal) übereinstimmen.
WB_MOOD_LABELS = {1: "Super", 2: "Gut", 3: "Okay", 4: "Schlecht"}
WB_SLEEP_LABELS = {1: "Sehr gut", 2: "Gut", 3: "Mäßig", 4: "Schlecht"}
WB_JOINTS_LABELS = {1: "Kein Problem", 2: "Leicht steif", 3: "Schmerzhaft"}


def _wb_labels(d):
    """Ergänzt ein Befinden-Dict um Klartext-Labels. hydration ist ein Wert in
    Litern (0.5/1/1.5/2), höher = mehr getrunken. Erwartet ein dict oder None."""
    if not d:
        return d
    d['mood_label'] = WB_MOOD_LABELS.get(d.get('mood'))
    d['sleep_label'] = WB_SLEEP_LABELS.get(d.get('sleep'))
    d['joints_label'] = WB_JOINTS_LABELS.get(d.get('joints'))
    d['hydration_unit'] = 'liters'
    return d


@app.route('/api/v1/summary', methods=['GET'])
@api_read_required
def api_summary():
    """Zusammenfassung der letzten Trainings — für externe Tools (z.B. Cowork)."""
    conn = get_db()
    limit = request.args.get('limit', 10, type=int)
    days = request.args.get('days', 30, type=int)
    start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

    # Trainingstage
    dates = conn.execute(
        "SELECT DISTINCT workout_date FROM workouts WHERE workout_date >= ? ORDER BY workout_date DESC LIMIT ?",
        (start, limit)
    ).fetchall()

    result = []
    for d in dates:
        date = d['workout_date']

        # Alle Geräte dieses Tages
        rows = conn.execute("""
            SELECT w.machine_id, m.name, m.category, w.training_method,
                   w.weight, w.reps, w.drop_set_num, w.duration_seconds, w.notes
            FROM workouts w JOIN machines m ON w.machine_id = m.id
            WHERE w.workout_date = ?
            ORDER BY w.created_at ASC, w.id ASC
        """, (date,)).fetchall()

        # Maschinen gruppieren
        machine_groups = {}
        machine_order = []
        for r in rows:
            key = (r['machine_id'], r['training_method'] or 'normal', r['notes'] or '')
            if key not in machine_groups:
                machine_groups[key] = {
                    'name': r['name'],
                    'category': r['category'],
                    'method': r['training_method'] or 'normal',
                    'sets': []
                }
                machine_order.append(key)
            machine_groups[key]['sets'].append({
                'weight': r['weight'],
                'reps': r['reps'],
                'drop_num': r['drop_set_num']
            })

        # Laufband separat auswerten
        cardio = None
        cardio_rows = [rows[i] for i, k in enumerate(machine_order) if machine_groups[list(machine_groups.keys())[i]]['category'] == 'Cardio'] if machine_order else []

        # Laufband direkt aus DB
        treadmill = conn.execute("""
            SELECT w.weight as minutes, w.reps as distance_m, w.duration_seconds
            FROM workouts w JOIN machines m ON w.machine_id = m.id
            WHERE w.workout_date = ? AND m.category = 'Cardio'
            ORDER BY w.id ASC LIMIT 1
        """, (date,)).fetchone()

        if treadmill:
            cardio = {
                'minutes': treadmill['minutes'],
                'km': round((treadmill['distance_m'] or 0), 2),
                'duration_seconds': treadmill['duration_seconds']
            }

        # Kraftgeräte (nicht Cardio)
        strength_machines = [
            machine_groups[k] for k in machine_order
            if machine_groups[k]['category'] != 'Cardio'
        ]

        # Wellbeing für diesen Tag
        wb = conn.execute(
            "SELECT mood, sleep, hydration, joints FROM wellbeing_logs WHERE log_date = ?",
            (date,)
        ).fetchone()

        result.append({
            'date': date,
            'machine_count': len(set(k[0] for k in machine_order if machine_groups[k]['category'] != 'Cardio')),
            'set_count': sum(len(machine_groups[k]['sets']) for k in machine_order if machine_groups[k]['category'] != 'Cardio'),
            'machines': strength_machines,
            'cardio': cardio,
            'wellbeing': _wb_labels(dict(wb)) if wb else None
        })

    conn.close()
    return jsonify(result)


@app.route('/api/v1/workouts', methods=['GET'])
@api_read_required
def api_workouts():
    """Workout-Daten für externe Tools."""
    conn = get_db()
    days = request.args.get('days', 30, type=int)
    start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    rows = conn.execute("""
        SELECT w.*, m.name as machine_name, m.category
        FROM workouts w JOIN machines m ON w.machine_id = m.id
        WHERE w.workout_date >= ?
        ORDER BY w.workout_date DESC, w.created_at DESC
    """, (start,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/v1/wellbeing', methods=['GET'])
@api_read_required
def api_wellbeing():
    """Befinden-Daten für externe Tools."""
    conn = get_db()
    days = request.args.get('days', 30, type=int)
    start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    rows = conn.execute(
        "SELECT * FROM wellbeing_logs WHERE log_date >= ? ORDER BY log_date DESC",
        (start,)
    ).fetchall()
    conn.close()
    return jsonify([_wb_labels(dict(r)) for r in rows])

# init_db() hier aufrufen, damit es sowohl unter Gunicorn als auch direkt funktioniert
init_db()

# ── Notfall-Passwort-Reset via Umgebungsvariable ────────────────────────────
# Wenn FITTRACK_RESET_PASS in der .env gesetzt ist, wird das Passwort
# beim nächsten Container-Start automatisch zurückgesetzt.
# Danach FITTRACK_RESET_PASS wieder aus der .env entfernen!
_reset_pass = os.environ.get('FITTRACK_RESET_PASS', '').strip()
if _reset_pass:
    if len(_reset_pass) < 6:
        print("[FitTrack] ⚠️  FITTRACK_RESET_PASS ignoriert — Passwort muss mind. 6 Zeichen haben.", flush=True)
    else:
        try:
            conn = get_db()
            new_hash = hash_password(_reset_pass)
            rows = conn.execute("UPDATE users SET password_hash = ?", (new_hash,)).rowcount
            conn.commit()
            conn.close()
            print(f"[FitTrack] ✅ Passwort für {rows} Nutzer zurückgesetzt.", flush=True)
            print("[FitTrack] ⚠️  Bitte FITTRACK_RESET_PASS jetzt aus der .env entfernen und Container neu starten!", flush=True)
        except Exception as e:
            print(f"[FitTrack] ❌ Passwort-Reset fehlgeschlagen: {e}", flush=True)

if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=8484, debug=debug)
