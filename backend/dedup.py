#!/usr/bin/env python3
"""FitTrack — Dubletten in der workouts-Tabelle bereinigen.

Hintergrund: Vor 0.12.9 konnte ein Doppeltipp auf "Speichern & Beenden" ein
Training zweimal speichern -> jeder Satz doppelt. Dieses Skript entfernt exakt
identische Doppelzeilen (gleiches Gerät, Datum, Methode, notes, Satz-Nummer,
Wdh, Gewicht, Dauer) und behält je die kleinste id. Echte unterschiedliche
Sätze sowie L/R-Sätze (notes Links/Rechts) bleiben erhalten.

Aufruf im Container (WORKDIR /app):
    python backend/dedup.py          -> nur anzeigen (Dry-Run, ändert nichts)
    python backend/dedup.py apply    -> Backup anlegen und bereinigen
"""
import sqlite3, os, sys, shutil

DB = os.environ.get("DB_PATH", "/app/data/fittrack.db")
KEY = ("machine_id,workout_date,training_method,notes,"
       "drop_set_num,reps,weight,IFNULL(duration_seconds,-1)")


def main():
    apply = len(sys.argv) > 1 and sys.argv[1] == "apply"
    if not os.path.exists(DB):
        print(f"DB nicht gefunden: {DB}")
        sys.exit(1)
    c = sqlite3.connect(DB)
    total = c.execute("SELECT COUNT(*) FROM workouts").fetchone()[0]
    keep = c.execute(
        f"SELECT COUNT(*) FROM (SELECT MIN(id) FROM workouts GROUP BY {KEY})"
    ).fetchone()[0]
    dele = total - keep
    print(f"Datenbank: {DB}")
    print(f"Saetze gesamt: {total} | behalten: {keep} | Dubletten: {dele}")

    rows = c.execute(
        "SELECT workout_date, COUNT(*) - COUNT(DISTINCT "
        "machine_id||'/'||training_method||'/'||notes||'/'||drop_set_num||'/'"
        "||reps||'/'||weight||'/'||IFNULL(duration_seconds,-1)) AS dup "
        "FROM workouts GROUP BY workout_date HAVING dup > 0 "
        "ORDER BY workout_date"
    ).fetchall()
    if rows:
        print("Betroffene Tage:")
        for d, n in rows:
            print(f"  {d}: {n} Dubletten")

    if not apply:
        print("\n[Dry-Run] Nichts geaendert. Zum Bereinigen:  python backend/dedup.py apply")
        return
    if dele == 0:
        print("Keine Dubletten — nichts zu tun.")
        return

    bak = DB + ".bak"
    shutil.copy(DB, bak)
    print(f"Backup angelegt: {bak}")
    n = c.execute(
        f"DELETE FROM workouts WHERE id NOT IN "
        f"(SELECT MIN(id) FROM workouts GROUP BY {KEY})"
    ).rowcount
    c.commit()
    now = c.execute("SELECT COUNT(*) FROM workouts").fetchone()[0]
    print(f"Geloescht: {n} | Saetze jetzt: {now}")


if __name__ == "__main__":
    main()
