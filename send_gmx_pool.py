#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GMX Weekly Mailer – Pool-basiertt

////////////  START : py -3 send_gmx_pool.py --count 2
////////////  TEST  : py -3 send_gmx_pool.py --count 2 --dry-run


Funktion:
- Nimmt pro Lauf N Empfänger aus einer Pool-CSV (email,name),
- personalisiert Betreff/Text (Platzhalter {name}),
- hängt alle Dateien aus dem Ordner "attachments" an,
- sendet über GMX-SMTP,
- protokolliert jeden Versand in logs/sent_log.csv,
- entfernt die versendeten Empfänger aus dem Pool (keine Doppel-Sends).

Aufruf-Beispiele:
    python send_gmx_pool.py --count 2 --dry-run
    python send_gmx_pool.py --count 2
    python send_gmx_pool.py --count 2 --subject "Initiativbewerbung – {name}"

Konfiguration:
- Zugangsdaten via Umgebungsvariablen:
    GMX_USER = deine-adresse@gmx.de (.net/.at)
    GMX_PASS = (App-)Passwort
- Dateien im selben Ordner:
    recipients_pool.csv   (Spalten: email,name)
    body.txt              (E-Mail-Text; nutzt {name})
    attachments/          (alle Dateien darin werden angehängt)

Geplante Ausführung:
- Windows: Aufgabenplanung (wöchentlich Dienstag 10:00)
- Linux/Mac: cron
"""

import argparse
import csv
import mimetypes
import os
import re
import smtplib
import ssl
import sys
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import imaplib

IMAP_HOST = "imap.gmx.net"
IMAP_PORT = 993

def save_to_sent_imap(msg: EmailMessage, user: str, password: str):
    """
    Speichert die gesendete Nachricht im GMX-Ordner 'Gesendet' (oder Fallback 'Sent').
    """
    MAILBOX_CANDIDATES = ["Gesendet", "Sent", "Gesendete Objekte"]

    try:
        with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as imap:
            imap.login(user, password)

            # Verfügbare Ordner auflisten
            typ, data = imap.list()
            folders_text = " ".join(
                (line.decode("utf-8", "ignore") if isinstance(line, bytes) else str(line))
                for line in (data or [])
            )

            # Zielordner finden
            target = None
            for cand in MAILBOX_CANDIDATES:
                if cand.lower() in folders_text.lower():
                    target = cand
                    break
            if not target:
                target = "Sent"  # Fallback

            # Mail als Kopie ablegen
            imap.append(
                target,
                "\\Seen",
                imaplib.Time2Internaldate(time.time()),
                msg.as_bytes()
            )
            imap.logout()
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ======= EINSTELLUNGEN =======
SUBJECT_DEFAULT = "Bewerbung"   # Anpassen oder per --subject überschreiben
BODY_TEMPLATE_PATH = Path(__file__).with_name("body.txt")
ATTACHMENTS_DIR = Path(__file__).with_name("attachments")

RETRY_ATTEMPTS = 2           # zusätzliche Versuche nach dem ersten
RETRY_SLEEP_SECONDS = 5      # Wartezeit zwischen Versuchen (Sekunden)

SAVE_TO_SENT = True  # Nach Versand per IMAP in "Gesendet" speichern


SMTP_HOST = "mail.gmx.net"
SMTP_PORT = 587  # STARTTLS

BASE_DIR = Path(__file__).parent
POOL_CSV = BASE_DIR / "recipients_pool.csv"
SENT_LOG_CSV = BASE_DIR / "logs" / "sent_log.csv"

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def validate_email(addr: str) -> bool:
    return bool(EMAIL_REGEX.match(addr or ""))


def load_body_template() -> str:
    if not BODY_TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Body-Template fehlt: {BODY_TEMPLATE_PATH}")
    return BODY_TEMPLATE_PATH.read_text(encoding="utf-8")


def iter_attachments():
    if not ATTACHMENTS_DIR.exists():
        return []
    files = []
    for p in sorted(ATTACHMENTS_DIR.iterdir()):
        if p.is_file():
            files.append(p)
    return files


def guess_mime(path: Path):
    mtype, _ = mimetypes.guess_type(path.name)
    if not mtype:
        return ("application", "octet-stream")
    maintype, subtype = mtype.split("/", 1)
    return (maintype, subtype)


def build_message(sender, recipient_email, subject, body_text, attachments):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.set_content(body_text)

    for path in attachments:
        maintype, subtype = guess_mime(path)
        msg.add_attachment(
            path.read_bytes(),
            maintype=maintype,
            subtype=subtype,
            filename=path.name
        )
    return msg


def send_email(msg: EmailMessage, user: str, password: str):
    context = ssl.create_default_context()
    for attempt in range(1, RETRY_ATTEMPTS + 2):  # 1. Versuch + Retries
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login(user, password)
                server.send_message(msg)
            return True, ""
        except Exception as e:
            if attempt <= RETRY_ATTEMPTS:
                time.sleep(RETRY_SLEEP_SECONDS)
                continue
            return False, f"{type(e).__name__}: {e}"


def read_pool():
    if not POOL_CSV.exists():
        return []
    rows = []
    with open(POOL_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "email": (r.get("email") or "").strip(),
                "name": (r.get("name") or "").strip()
            })
    return rows


def write_pool(rows):
    with open(POOL_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["email", "name"])
        writer.writeheader()
        for r in rows:
            writer.writerow({"email": r["email"], "name": r.get("name", "")})


def append_sent_log(entries):
    SENT_LOG_CSV.parent.mkdir(parents=True, exist_ok=True)
    new_file = not SENT_LOG_CSV.exists()
    with open(SENT_LOG_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ts_iso",
                "email",
                "name",
                "subject",
                "status",
                "error",
                "saved_to_sent",
                "save_error",
            ]
        )
        if new_file:
            writer.writeheader()
        for e in entries:
            writer.writerow(e)


def pick_recipients(pool, count: int):
    picked, remaining = [], []
    for r in pool:
        if len(picked) < count and validate_email(r["email"]):
            picked.append(r)
        else:
            remaining.append(r)
    return picked, remaining


def main():
    parser = argparse.ArgumentParser(description="Sende wöchentlich E-Mails aus einem Empfänger-Pool über GMX.")
    parser.add_argument("--count", type=int, default=2, help="Anzahl Empfänger pro Lauf (Default: 2)")
    parser.add_argument("--dry-run", action="store_true", help="Nur anzeigen, nichts senden")
    parser.add_argument("--subject", type=str, default=None, help="Betreff überschreiben (optional)")
    args = parser.parse_args()

    gmx_user = os.getenv("GMX_USER", "").strip()
    gmx_pass = os.getenv("GMX_PASS", "").strip()
    if not gmx_user or not gmx_pass:
        print("FEHLER: Bitte Umgebungsvariablen GMX_USER und GMX_PASS setzen.")
        sys.exit(2)

    pool = read_pool()
    if not pool:
        print("Kein Pool gefunden oder keine Empfänger mehr übrig. Beende.")
        return 0

    body_template = load_body_template()
    attachments = list(iter_attachments())
    if not attachments:
        print("Hinweis: Keine Anhänge im Ordner 'attachments' gefunden – wird ohne Anhang gesendet.")

    count = max(1, args.count)
    picked, remaining = pick_recipients(pool, count)
    if not picked:
        print("Keine gültigen Empfänger ausgewählt (Pool leer oder ungültig).")
        return 0

    logs = []
    for r in picked:
        name = r.get("name") or "Sehr geehrte Damen und Herren"
        subject = (args.subject if args.subject else SUBJECT_DEFAULT).format(name=name)
        body = body_template.format(name=name)
        msg = build_message(gmx_user, r["email"], subject, body, attachments)

        if args.dry_run:
            status, err = True, ""
            save_status, save_err = True, ""
            print(f"[DRY-RUN] Würde senden an {r['email']} ({name}) | Betreff: {subject} | Anhänge: {[p.name for p in attachments]}")
        else:
            status, err = send_email(msg, gmx_user, gmx_pass)
            save_status, save_err = True, ""
            if status and SAVE_TO_SENT:
                save_status, save_err = save_to_sent_imap(msg, gmx_user, gmx_pass)

        logs.append({
            "ts_iso": datetime.now().isoformat(timespec="seconds"),
            "email": r["email"],
            "name": name,
            "subject": subject,
            "status": "SENT" if status else "ERROR",
            "error": err,
            "saved_to_sent": "OK" if (status and save_status) else ("FAIL" if status else "N/A"),
            "save_error": save_err
        })

    # Pool aktualisieren (nur wenn echt gesendet)
    if not args.dry_run:
        write_pool(remaining)

    append_sent_log(logs)

    ok = sum(1 for l in logs if l["status"] == "SENT")
    fail = len(logs) - ok
    rest = len(remaining) if not args.dry_run else len(read_pool())
    print(f"Fertig. Erfolgreich: {ok}, Fehlgeschlagen: {fail}. Verbleibend im Pool: {rest}")
    if fail:
        print("Details siehe logs/sent_log.csv")

    return 0


if __name__ == "__main__":
    sys.exit(main())
