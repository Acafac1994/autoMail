#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI für den GMX Weekly Mailer
Tabs:
- Senden: send_gmx_pool.py mit Optionen (Dry-Run / Count / optionaler Betreff)
- Pool verwalten: CSV (email,name) ansehen, hinzufügen, bearbeiten, löschen, speichern
- Logs: sent_log.csv schön anzeigen + filtern/suchen + Detail-Dialog
Extras:
- Body-Editor zum direkten Bearbeiten von body.txt
- Detail-Dialog zeigt Email-Datensatz + gerenderten Body (body.txt mit {name})

Start: py -3 app_gui.py
"""

import os
import re
import sys
import csv
import subprocess
import threading
import queue
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

HERE = Path(__file__).parent.resolve()
SCRIPT = HERE / "send_gmx_pool.py"
POOL = HERE / "recipients_pool.csv"
BODY = HERE / "body.txt"
ATTACH = HERE / "attachments"
LOGDIR = HERE / "logs"
SENT_LOG = LOGDIR / "sent_log.csv"

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# ---------------------- Helfer ----------------------

def find_python_cmd():
    """Bevorzuge 'py -3', fallback auf 'python'."""
    try:
        out = subprocess.run(["py", "-3", "-V"], capture_output=True, text=True)
        if out.returncode == 0:
            return ["py", "-3"]
    except Exception:
        pass
    return ["python"]

def open_path(p: Path):
    if not p.exists():
        messagebox.showwarning("Nicht gefunden", f"Pfad existiert nicht:\n{p}")
        return
    try:
        if os.name == "nt":
            os.startfile(str(p))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(p)])
        else:
            subprocess.Popen(["xdg-open", str(p)])
    except Exception as e:
        messagebox.showerror("Fehler", f"Konnte nicht öffnen:\n{p}\n\n{e}")

def env_ok():
    return bool(os.getenv("GMX_USER")) and bool(os.getenv("GMX_PASS"))

def load_pool_rows():
    rows = []
    if not POOL.exists():
        return rows
    with open(POOL, newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        for r in rd:
            rows.append({"email": (r.get("email") or "").strip(),
                         "name": (r.get("name") or "").strip()})
    return rows

def save_pool_rows(rows):
    with open(POOL, "w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=["email", "name"])
        wr.writeheader()
        for r in rows:
            wr.writerow({"email": r["email"], "name": r.get("name", "")})

def load_log_rows():
    """liest logs/sent_log.csv; toleriert zusätzliche/fehlende Spalten."""
    rows = []
    if not SENT_LOG.exists():
        return rows
    with open(SENT_LOG, newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        for r in rd:
            rows.append({
                "ts_iso": (r.get("ts_iso") or "").strip(),
                "email": (r.get("email") or "").strip(),
                "name": (r.get("name") or "").strip(),
                "subject": (r.get("subject") or "").strip(),
                "status": (r.get("status") or "").strip(),
                "error": (r.get("error") or "").strip(),
                "saved_to_sent": (r.get("saved_to_sent") or "").strip(),
                "save_error": (r.get("save_error") or "").strip(),
            })
    return rows

def parse_ts(ts):
    # Erwartet ISO z. B. 2025-05-10T10:05:00
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def load_body_text():
    if BODY.exists():
        return BODY.read_text(encoding="utf-8")
    return ""

def render_body_for_name(name: str):
    tpl = load_body_text()
    try:
        return tpl.format(name=name or "Sehr geehrte Damen und Herren")
    except Exception as e:
        return f"[Fehler beim Rendern aus body.txt: {e}]\n\n{tpl}"

# ---------------------- Subprocess Runner ----------------------

class Runner(threading.Thread):
    def __init__(self, args, out_queue):
        super().__init__(daemon=True)
        self.args = args
        self.q = out_queue

    def run(self):
        try:
            proc = subprocess.Popen(
                self.args,
                cwd=str(HERE),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                self.q.put(line.rstrip("\n"))
            proc.wait()
            self.q.put(f"[EXIT] Rückgabecode: {proc.returncode}")
        except Exception as e:
            self.q.put(f"[ERROR] {type(e).__name__}: {e}")

# ---------------------- Dialoge ----------------------

class EntryDialog(tk.Toplevel):
    """Dialog zum Hinzufügen/Bearbeiten eines Pool-Eintrags."""
    def __init__(self, master, title, email="", name=""):
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.result = None

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="E-Mail:").grid(row=0, column=0, sticky="w", padx=(0,8), pady=(0,6))
        self.var_email = tk.StringVar(value=email)
        ttk.Entry(frm, textvariable=self.var_email, width=48).grid(row=0, column=1, sticky="we", pady=(0,6))

        ttk.Label(frm, text="Name / Kommentar:").grid(row=1, column=0, sticky="w", padx=(0,8))
        self.var_name = tk.StringVar(value=name)
        ttk.Entry(frm, textvariable=self.var_name, width=48).grid(row=1, column=1, sticky="we")

        btns = ttk.Frame(frm)
        btns.grid(row=2, column=0, columnspan=2, sticky="e", pady=(10,0))
        ttk.Button(btns, text="Abbrechen", command=self.destroy).pack(side="right", padx=(6,0))
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right")

        frm.grid_columnconfigure(1, weight=1)
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())

        self.transient(master)
        self.grab_set()
        self.wait_visibility()
        self.focus()

    def _ok(self):
        email = self.var_email.get().strip()
        name = self.var_name.get().strip()
        if not EMAIL_REGEX.match(email):
            messagebox.showerror("Ungültige E-Mail", f"Bitte gültige E-Mail eingeben:\n{email}")
            return
        self.result = {"email": email, "name": name}
        self.destroy()

class BodyEditor(tk.Toplevel):
    """Einfacher Editor für body.txt."""
    def __init__(self, master):
        super().__init__(master)
        self.title("body.txt bearbeiten")
        self.geometry("720x520")
        self.minsize(560, 420)

        frm = ttk.Frame(self, padding=8)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=str(BODY)).pack(anchor="w", pady=(0,6))
        self.txt = tk.Text(frm, wrap="word")
        self.txt.pack(fill="both", expand=True)
        self.txt.insert("1.0", load_body_text())

        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(6,0))
        ttk.Button(btns, text="Speichern", command=self._save).pack(side="left")
        ttk.Button(btns, text="Abbrechen", command=self.destroy).pack(side="right")

        self.transient(master)
        self.grab_set()
        self.wait_visibility()
        self.focus()

    def _save(self):
        try:
            BODY.write_text(self.txt.get("1.0","end").rstrip("\n"), encoding="utf-8")
            messagebox.showinfo("Gespeichert", "body.txt wurde gespeichert.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Fehler", f"Konnte body.txt nicht speichern:\n{e}")

class LogDetail(tk.Toplevel):
    """Detailansicht für einen Log-Datensatz inkl. gerendertem Body."""
    def __init__(self, master, record: dict):
        super().__init__(master)
        self.title("Log-Details")
        self.geometry("900x620")
        self.minsize(760, 540)

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # Kopf-Infos
        top = ttk.Frame(frm)
        top.pack(fill="x")
        def row(k, v):
            r = ttk.Frame(top)
            r.pack(fill="x", pady=2)
            ttk.Label(r, text=k, width=18).pack(side="left")
            ttk.Label(r, text=v, foreground="#333").pack(side="left")
        ts_fmt = record.get("ts_iso","")
        try:
            dt = datetime.fromisoformat(ts_fmt)
            ts_fmt = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        row("Versendet am:", ts_fmt or "—")
        row("E-Mail:", record.get("email",""))
        row("Name/Kommentar:", record.get("name",""))
        row("Betreff:", record.get("subject",""))
        row("Status:", record.get("status",""))
        row("Gesendet-Kopie:", (record.get("saved_to_sent") or "—"))
        if record.get("error"):
            row("Fehler:", record.get("error",""))
        if record.get("save_error"):
            row("Save-Fehler:", record.get("save_error",""))

        # Body-Vorschau (gerendert)
        sep = ttk.Separator(frm); sep.pack(fill="x", pady=8)
        ttk.Label(frm, text="E-Mail-Text (body.txt gerendert mit {name}):").pack(anchor="w")

        txt = tk.Text(frm, wrap="word", height=16)
        txt.pack(fill="both", expand=True, pady=(4,0))
        rendered = render_body_for_name(record.get("name",""))
        txt.insert("1.0", rendered)
        txt.configure(state="disabled")

        # Anhangliste (aus aktuellem Ordner)
        sep2 = ttk.Separator(frm); sep2.pack(fill="x", pady=8)
        atts = []
        if ATTACH.exists():
            atts = [p.name for p in sorted(ATTACH.iterdir()) if p.is_file()]
        ttk.Label(frm, text=f"Anhänge im Ordner: {', '.join(atts) if atts else '—'}").pack(anchor="w")

        btns = ttk.Frame(frm); btns.pack(fill="x", pady=(8,0))
        ttk.Button(btns, text="Body bearbeiten…", command=lambda: BodyEditor(self)).pack(side="left")
        ttk.Button(btns, text="Anhänge-Ordner öffnen", command=lambda: open_path(ATTACH)).pack(side="left", padx=6)
        ttk.Button(btns, text="Schließen", command=self.destroy).pack(side="right")

        self.transient(master)
        self.grab_set()
        self.wait_visibility()
        self.focus()

# ---------------------- Haupt-App ----------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GMX Weekly Mailer – UI")
        self.geometry("1100x720")
        self.minsize(940, 620)

        self.python_cmd = find_python_cmd()
        self.queue = queue.Queue()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_send = ttk.Frame(nb)
        self.tab_pool = ttk.Frame(nb)
        self.tab_logs = ttk.Frame(nb)
        nb.add(self.tab_send, text="Senden")
        nb.add(self.tab_pool, text="Pool verwalten")
        nb.add(self.tab_logs, text="Logs")

        self._build_tab_send(self.tab_send)
        self._build_tab_pool(self.tab_pool)
        self._build_tab_logs(self.tab_logs)

        self.after(100, self._drain_queue)

    # -------- Tab: Senden --------
    def _build_tab_send(self, parent):
        topbar = ttk.Frame(parent)
        topbar.pack(fill="x", padx=10, pady=(10,6))

        lbl = ttk.Label(topbar, text=self._env_text(), foreground="green" if env_ok() else "red")
        lbl.pack(side="left")
        ttk.Label(topbar, text=" • Python: " + " ".join(self.python_cmd)).pack(side="left", padx=(10,0))

        btn_open = ttk.Menubutton(topbar, text="Öffnen …")
        m = tk.Menu(btn_open, tearoff=False)
        m.add_command(label="Projektordner", command=lambda: open_path(HERE))
        m.add_command(label="Pool (recipients_pool.csv)", command=lambda: open_path(POOL))
        m.add_command(label="Text (body.txt)", command=lambda: open_path(BODY))
        m.add_command(label="Anhänge (attachments/)", command=lambda: open_path(ATTACH))
        m.add_command(label="Logs (logs/)", command=lambda: open_path(LOGDIR))
        btn_open["menu"] = m
        btn_open.pack(side="right")

        opts = ttk.LabelFrame(parent, text="Optionen")
        opts.pack(fill="x", padx=10, pady=6)

        self.var_count = tk.IntVar(value=2)
        ttk.Label(opts, text="Anzahl Empfänger (count):").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Spinbox(opts, from_=1, to=100, textvariable=self.var_count, width=6).grid(row=0, column=1, sticky="w")

        self.var_subject = tk.StringVar(value="")
        ttk.Label(opts, text="Betreff (optional, {name} erlaubt):").grid(row=0, column=2, sticky="e", padx=8)
        ttk.Entry(opts, textvariable=self.var_subject, width=48).grid(row=0, column=3, sticky="we", padx=(0,8))

        self.var_dry = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Dry-Run (nur anzeigen)", variable=self.var_dry).grid(row=0, column=4, sticky="w", padx=8)

        opts.grid_columnconfigure(3, weight=1)

        btns = ttk.Frame(parent)
        btns.pack(fill="x", padx=10, pady=(0,6))
        ttk.Button(btns, text="Senden / Ausführen", command=self.run_now).pack(side="left")
        ttk.Button(btns, text="Logs öffnen", command=lambda: open_path(LOGDIR)).pack(side="left", padx=(8,0))
        ttk.Button(btns, text="Body bearbeiten…", command=lambda: BodyEditor(self)).pack(side="right")

        outbox = ttk.LabelFrame(parent, text="Ausgabe")
        outbox.pack(fill="both", expand=True, padx=10, pady=(0,10))
        self.txt = tk.Text(outbox, wrap="word", height=20)
        self.txt.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(outbox, command=self.txt.yview)
        scroll.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=scroll.set)

    def _env_text(self):
        u = os.getenv("GMX_USER") or "<nicht gesetzt>"
        p = os.getenv("GMX_PASS")
        return f"GMX_USER: {u} • GMX_PASS: {'gesetzt' if p else 'nicht gesetzt'}"

    def run_now(self):
        if not SCRIPT.exists():
            messagebox.showerror("Fehlt", f"send_gmx_pool.py nicht gefunden:\n{SCRIPT}")
            return
        if not env_ok():
            if not messagebox.askyesno("Umgebung fehlt", "GMX_USER / GMX_PASS scheinen nicht gesetzt.\nTrotzdem fortfahren?"):
                return

        args = self.python_cmd + [str(SCRIPT), "--count", str(self.var_count.get())]
        if self.var_dry.get():
            args.append("--dry-run")
        subj = self.var_subject.get().strip()
        if subj:
            args += ["--subject", subj]

        self.txt.delete("1.0", "end")
        self.txt.insert("end", f"Starte: {' '.join(args)}\n\n")
        runner = Runner(args, self.queue)
        runner.start()

    def _drain_queue(self):
        try:
            while True:
                line = self.queue.get_nowait()
                self.txt.insert("end", line + "\n")
                self.txt.see("end")
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    # -------- Tab: Pool verwalten --------
    def _build_tab_pool(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill="x", padx=10, pady=(10,6))

        self.lbl_pool_info = ttk.Label(top, text=self._pool_info_text())
        self.lbl_pool_info.pack(side="left")
        ttk.Button(top, text="Explorer öffnen", command=lambda: open_path(POOL)).pack(side="right")

        mid = ttk.Frame(parent)
        mid.pack(fill="both", expand=True, padx=10, pady=(0,10))

        self.tree = ttk.Treeview(mid, columns=("email","name"), show="headings", selectmode="extended")
        self.tree.heading("email", text="E-Mail")
        self.tree.heading("name", text="Name / Kommentar")
        self.tree.column("email", width=320, anchor="w")
        self.tree.column("name", width=380, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        scr = ttk.Scrollbar(mid, command=self.tree.yview)
        scr.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scr.set)

        btns = ttk.Frame(parent)
        btns.pack(fill="x", padx=10, pady=(0,10))
        ttk.Button(btns, text="Neu", command=self._pool_add).pack(side="left")
        ttk.Button(btns, text="Bearbeiten", command=self._pool_edit).pack(side="left", padx=(8,0))
        ttk.Button(btns, text="Löschen", command=self._pool_delete).pack(side="left", padx=(8,0))
        ttk.Button(btns, text="Speichern", command=self._pool_save).pack(side="right")
        ttk.Button(btns, text="Neu laden", command=self._pool_reload).pack(side="right", padx=(0,8))
        ttk.Button(btns, text="Import (.csv)…", command=self._pool_import_csv).pack(side="right", padx=(0,8))
        ttk.Button(btns, text="Export (.csv)…", command=self._pool_export_csv).pack(side="right", padx=(0,8))

        self._pool_reload()

    def _pool_info_text(self):
        count = len(load_pool_rows())
        return f"Datei: {POOL} — Einträge im Pool: {count}"

    def _pool_reload(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = load_pool_rows()
        for r in rows:
            self.tree.insert("", "end", values=(r["email"], r.get("name","")))
        self.lbl_pool_info.config(text=self._pool_info_text())

    def _pool_collect(self):
        rows = []
        for iid in self.tree.get_children():
            email, name = self.tree.item(iid, "values")
            rows.append({"email": email.strip(), "name": (name or "").strip()})
        return rows

    def _pool_add(self):
        dlg = EntryDialog(self, "Neuer Eintrag")
        self.wait_window(dlg)
        if dlg.result:
            self.tree.insert("", "end", values=(dlg.result["email"], dlg.result["name"]))
            self.lbl_pool_info.config(text=self._pool_info_text())

    def _pool_edit(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Hinweis", "Bitte einen Eintrag auswählen.")
            return
        if len(sel) > 1:
            messagebox.showinfo("Hinweis", "Bitte nur einen Eintrag bearbeiten.")
            return
        iid = sel[0]
        email, name = self.tree.item(iid, "values")
        dlg = EntryDialog(self, "Eintrag bearbeiten", email=email, name=name)
        self.wait_window(dlg)
        if dlg.result:
            self.tree.item(iid, values=(dlg.result["email"], dlg.result["name"]))

    def _pool_delete(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Hinweis", "Bitte Eintrag/Einträge auswählen.")
            return
        if not messagebox.askyesno("Löschen bestätigen", f"{len(sel)} Eintrag/Einträge löschen?"):
            return
        for iid in sel:
            self.tree.delete(iid)
        self.lbl_pool_info.config(text=self._pool_info_text())

    def _pool_save(self):
        rows = self._pool_collect()
        bad = [r["email"] for r in rows if not EMAIL_REGEX.match(r["email"])]
        if bad:
            messagebox.showerror("Ungültige E-Mail(s)", "Bitte folgende Adressen korrigieren:\n\n" + "\n".join(bad))
            return
        save_pool_rows(rows)
        self.lbl_pool_info.config(text=self._pool_info_text())
        messagebox.showinfo("Gespeichert", f"{len(rows)} Einträge gespeichert.")

    def _pool_import_csv(self):
        path = filedialog.askopenfilename(
            title="CSV importieren",
            filetypes=[("CSV-Datei","*.csv"), ("Alle Dateien","*.*")]
        )
        if not path:
            return
        try:
            with open(path, newline="", encoding="utf-8") as f:
                rd = csv.DictReader(f)
                new_rows = []
                for r in rd:
                    email = (r.get("email") or "").strip()
                    name = (r.get("name") or "").strip()
                    if email:
                        new_rows.append({"email": email, "name": name})
            if not new_rows:
                messagebox.showwarning("Leer", "Die gewählte CSV enthält keine verwertbaren Zeilen.")
                return
            for r in new_rows:
                self.tree.insert("", "end", values=(r["email"], r["name"]))
            self.lbl_pool_info.config(text=self._pool_info_text())
            messagebox.showinfo("Import", f"{len(new_rows)} Einträge importiert (hinzugefügt, nicht gespeichert).")
        except Exception as e:
            messagebox.showerror("Fehler", f"Import fehlgeschlagen:\n{e}")

    def _pool_export_csv(self):
        path = filedialog.asksaveasfilename(
            title="CSV exportieren",
            defaultextension=".csv",
            filetypes=[("CSV-Datei","*.csv"), ("Alle Dateien","*.*")]
        )
        if not path:
            return
        try:
            rows = self._pool_collect()
            with open(path, "w", newline="", encoding="utf-8") as f:
                wr = csv.DictWriter(f, fieldnames=["email","name"])
                wr.writeheader()
                for r in rows:
                    wr.writerow(r)
            messagebox.showinfo("Export", f"{len(rows)} Einträge exportiert:\n{path}")
        except Exception as e:
            messagebox.showerror("Fehler", f"Export fehlgeschlagen:\n{e}")

    # -------- Tab: Logs --------
    def _build_tab_logs(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill="x", padx=10, pady=(10,6))

        ttk.Label(top, text=f"Datei: {SENT_LOG}").pack(side="left")

        right = ttk.Frame(top)
        right.pack(side="right")
        self.var_filter_status = tk.StringVar(value="ALLE")
        ttk.Label(right, text="Status:").pack(side="left", padx=(0,4))
        ttk.Combobox(right, textvariable=self.var_filter_status,
                     values=["ALLE", "SENT", "ERROR"], width=8, state="readonly").pack(side="left")

        self.var_search = tk.StringVar()
        ttk.Entry(right, textvariable=self.var_search, width=26).pack(side="left", padx=(8,4))
        ttk.Button(right, text="Suchen/Filter", command=self._logs_reload).pack(side="left", padx=(4,0))
        ttk.Button(right, text="Neu laden", command=self._logs_reload).pack(side="left", padx=(6,0))
        ttk.Button(right, text="Ordner öffnen", command=lambda: open_path(LOGDIR)).pack(side="left", padx=(10,0))
        ttk.Button(right, text="Details…", command=self._open_log_detail).pack(side="left", padx=(6,0))
        ttk.Button(right, text="Body bearbeiten…", command=lambda: BodyEditor(self)).pack(side="left", padx=(6,0))

        mid = ttk.Frame(parent)
        mid.pack(fill="both", expand=True, padx=10, pady=(0,10))

        cols = ("ts_fmt","email","name","subject","status","saved_to_sent","error")
        self.tree_logs = ttk.Treeview(mid, columns=cols, show="headings", selectmode="browse")
        self.tree_logs.heading("ts_fmt", text="Versendet am")
        self.tree_logs.heading("email", text="E-Mail")
        self.tree_logs.heading("name", text="Name/Kommentar")
        self.tree_logs.heading("subject", text="Betreff")
        self.tree_logs.heading("status", text="Status")
        self.tree_logs.heading("saved_to_sent", text="Gesendet-Kopie")
        self.tree_logs.heading("error", text="Fehler")
        self.tree_logs.column("ts_fmt", width=160, anchor="w")
        self.tree_logs.column("email", width=240, anchor="w")
        self.tree_logs.column("name", width=200, anchor="w")
        self.tree_logs.column("subject", width=260, anchor="w")
        self.tree_logs.column("status", width=80, anchor="center")
        self.tree_logs.column("saved_to_sent", width=120, anchor="center")
        self.tree_logs.column("error", width=320, anchor="w")
        self.tree_logs.pack(side="left", fill="both", expand=True)

        scr = ttk.Scrollbar(mid, command=self.tree_logs.yview)
        scr.pack(side="right", fill="y")
        self.tree_logs.configure(yscrollcommand=scr.set)

        # Doppelklick -> Details
        self.tree_logs.bind("<Double-1>", lambda e: self._open_log_detail())

        self._logs_reload()

    def _logs_reload(self):
        for i in self.tree_logs.get_children():
            self.tree_logs.delete(i)

        rows = load_log_rows()

        flt = self.var_filter_status.get() if hasattr(self, "var_filter_status") else "ALLE"
        q = (self.var_search.get().strip().lower() if hasattr(self, "var_search") else "")
        filtered = []
        for r in rows:
            if flt != "ALLE" and r["status"].upper() != flt:
                continue
            text_blob = " ".join([r.get("email",""), r.get("name",""), r.get("subject",""), r.get("error","")]).lower()
            if q and q not in text_blob:
                continue
            filtered.append(r)

        def sort_key(r):
            dt = parse_ts(r.get("ts_iso","")) or datetime.min
            return dt
        filtered.sort(key=sort_key, reverse=True)

        for r in filtered:
            dt = parse_ts(r.get("ts_iso",""))
            ts_fmt = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else (r.get("ts_iso","") or "")
            saved = r.get("saved_to_sent") or ""
            if saved.upper() == "OK":
                saved = "OK"
            elif saved.upper() == "FAIL":
                saved = "FAIL"
            elif saved.upper() in ("", "N/A"):
                saved = "—"
            self.tree_logs.insert("", "end", values=(
                ts_fmt,
                r.get("email",""),
                r.get("name",""),
                r.get("subject",""),
                r.get("status",""),
                saved,
                r.get("error",""),
            ), tags=(r.get("ts_iso",""),))  # ts_iso als Tag zum Wiederfinden

        # Zeilen einfärben (optional minimal)
        # (kann bei Bedarf erweitert werden)

    def _get_selected_log(self):
        sel = self.tree_logs.selection()
        if not sel:
            messagebox.showinfo("Hinweis", "Bitte einen Log-Eintrag auswählen.")
            return None
        item = sel[0]
        ts_tag = self.tree_logs.item(item, "tags")[0] if self.tree_logs.item(item, "tags") else ""
        # Finde passenden Datensatz erneut (robust bei Filterwechsel)
        for r in load_log_rows():
            if r.get("ts_iso","") == ts_tag:
                return r
        # Fallback: anhand der sichtbaren Werte grob zusammensetzen
        vals = self.tree_logs.item(item, "values")
        return {
            "ts_iso": ts_tag,
            "email": vals[1],
            "name": vals[2],
            "subject": vals[3],
            "status": vals[4],
            "saved_to_sent": vals[5],
            "error": vals[6],
            "save_error": "",
        }

    def _open_log_detail(self):
        rec = self._get_selected_log()
        if rec:
            LogDetail(self, rec)

# ---------------------- main ----------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()
