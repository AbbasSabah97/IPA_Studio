"""IPA Studio Windows GUI; Tkinter/ttk, no mandatory runtime PyPI packages.

Apple ID operations use the bundled open-source iPASide Python Engine.
IPA Studio does not issue Apple certificates or bypass Apple's restrictions.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import arabic_reshaper
    from bidi.algorithm import get_display as bidi_display
except ImportError:
    arabic_reshaper = None
    bidi_display = None


def visual_text(value: str) -> str:
    # Tk/Windows combinations differ in Arabic shaping support.  Pre-shape
    # static interface text only, not typed paths, passwords or Bundle IDs.
    if not any('\u0600' <= c <= '\u06ff' for c in value):
        return value
    if arabic_reshaper and bidi_display:
        return bidi_display(arabic_reshaper.reshape(value))
    return value


from .core import (
    StudioError, inspect_ipa, guess_engine, bundled_engine,
    run_engine, default_output_path,
)
from .privacy import SERVERS, selected_url

BG = "#0c1221"
PANEL = "#141e32"
PANEL2 = "#1d2c43"
TEXT = "#edf5ff"
MUTED = "#a9bdd5"
ACCENT = "#2cd4bd"
ACCENT2 = "#0e6b64"
RED = "#ff7777"


def storage_path() -> Path:
    root = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(root) / "IPAStudio" / "settings.json"


def load_settings() -> dict:
    try:
        data = json.loads(storage_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(data: dict) -> None:
    path = storage_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IPA Studio Trusted 4.0 · Secure iPhone Installer")
        self.geometry("1050x760")
        self.minsize(870, 670)
        self.configure(bg=BG)
        self.events: queue.Queue = queue.Queue()
        self.busy = False
        self.info = None
        self.devices: list[dict] = []
        self.installs: list[dict] = []
        s = load_settings()
        self.engine = tk.StringVar(value=str(bundled_engine() or ""))
        self.ipa = tk.StringVar(value="")
        self.apple_email = tk.StringVar(value="")
        self.apple_password = tk.StringVar(value="")
        self.apple_2fa = tk.StringVar(value="")
        self.connection = tk.StringVar(value="usb")
        self.server_label = tk.StringVar(value=s.get("server_label") if s.get("server_label") in SERVERS else "SideStore V3")
        self.privacy_consent = tk.BooleanVar(value=False)
        self.device_var = tk.StringVar(value="")
        self.keep_signed = tk.BooleanVar(value=True)
        self.output_dir = tk.StringVar(value=s.get("output_dir") or str(Path.home() / 'Documents' / 'IPA Studio' / 'Signed'))
        self.status = tk.StringVar(value="جاهز · Ready")
        self.details = tk.StringVar(value="اختر ملف IPA لفحص محتواه وتوقيعه")
        self._build_style()
        self._build_ui()
        self.after(100, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("Panel.TLabelframe", background=PANEL, relief="flat", borderwidth=0)
        style.configure("Panel.TLabelframe.Label", background=PANEL, foreground=ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED)
        style.configure("Accent.TButton", background=ACCENT2, foreground="#fff", padding=(16, 11), font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#1b9787"), ("disabled", "#334255")])
        style.configure("TButton", background=PANEL2, foreground=TEXT, padding=(12, 9), borderwidth=0)
        style.map("TButton", background=[("active", "#2f4563"), ("disabled", "#19263a")], foreground=[("disabled", "#7d8ea7")])
        style.configure("TEntry", fieldbackground="#eef5ff", foreground="#18253b", padding=(7, 6))
        style.configure("TCombobox", fieldbackground="#eef5ff", foreground="#18253b", padding=5)
        style.configure("TCheckbutton", background=PANEL, foreground=TEXT)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(20, 10), background=PANEL2, foreground=TEXT)
        style.map("TNotebook.Tab", background=[("selected", ACCENT2)], foreground=[("selected", "white")])
        style.configure("Treeview", background="#15243a", fieldbackground="#15243a", foreground=TEXT, rowheight=30)
        style.map("Treeview", background=[("selected", "#11685f")])
        style.configure("Treeview.Heading", background=PANEL2, foreground=TEXT, font=("Segoe UI", 10, "bold"))

    def _build_ui(self):
        head = ttk.Frame(self)
        head.pack(fill="x", padx=25, pady=(19, 7))
        tk.Label(head, text="IPA  STUDIO", font=("Segoe UI", 25, "bold"), fg=ACCENT, bg=BG).pack(side="left")
        ttk.Label(head, text="Python · Windows · iOS Signing", style="Muted.TLabel").pack(side="left", padx=20, pady=(9, 0))
        self.work_state = tk.Label(head, text="●  Limited network access", fg=ACCENT, bg=BG, font=("Segoe UI", 10))
        self.work_state.pack(side="right")

        ttk.Label(self, text="توقيع مجاني بحساب Apple العادي · خادم Anisette واحد بموافقتك · USB فقط", style="Muted.TLabel").pack(anchor="e", padx=27, pady=(0, 12))
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=22, pady=5)
        self.main_tab = ttk.Frame(self.tabs)
        self.apple_tab = ttk.Frame(self.tabs)
        self.config_tab = ttk.Frame(self.tabs)
        self.logs_tab = ttk.Frame(self.tabs)
        for frame, name in [(self.main_tab, "الرئيسية · IPA"), (self.apple_tab, "Apple ID"),
                            (self.config_tab, "الخصوصية والإعدادات"), (self.logs_tab, "سجل العمليات")]:
            self.tabs.add(frame, text=name)
        self.main_body = self._scroll_body(self.main_tab)
        self.apple_body = self._scroll_body(self.apple_tab)
        self.config_body = self._scroll_body(self.config_tab)
        self._main_tab()
        self._apple_tab()
        self._config_tab()
        self._logs_tab()
        self._shape_static_labels()
        foot = ttk.Frame(self)
        foot.pack(fill="x", padx=25, pady=(6, 15))
        ttk.Label(foot, textvariable=self.status, style="Muted.TLabel").pack(side="left")
        ttk.Label(foot, text="Apple ID free profile ≈ 7 days · لا توجد شهادة دائمة مجانية", style="Muted.TLabel").pack(side="right")

    def _shape_static_labels(self):
        # Notebook tabs are not ordinary widgets and need special handling.
        for tab_id in self.tabs.tabs():
            self.tabs.tab(tab_id, text=visual_text(self.tabs.tab(tab_id, "text")))
        def visit(widget):
            if widget is not self:
                try:
                    # Skip dynamic StringVar-controlled text.
                    if "textvariable" in widget.keys() and widget.cget("textvariable"):
                        pass
                    elif "text" in widget.keys():
                        label = widget.cget("text")
                        if isinstance(label, str):
                            widget.configure(text=visual_text(label))
                except (tk.TclError, TypeError):
                    pass
            for child in widget.winfo_children():
                visit(child)
        visit(self)

    def _scroll_body(self, parent):
        canvas = tk.Canvas(parent, background=BG, highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas)
        slot = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(slot, width=e.width))
        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>",
                    lambda evt: canvas.yview_scroll(-int(evt.delta / 120) or 1, "units")))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))
        return body

    def _group(self, parent, title, pady=9):
        box = ttk.LabelFrame(parent, text="  " + title + "  ", style="Panel.TLabelframe", padding=17)
        box.pack(fill="x", pady=pady)
        return box

    def _file_row(self, parent, label, var, types, extra=0):
        row = ttk.Frame(parent, style="Panel.TFrame")
        row.pack(fill="x", pady=5)
        ttk.Label(row, text=label, width=15, style="Panel.TLabel").pack(side="right", padx=(10, 0))
        ttk.Button(row, text="استعراض", command=lambda: self._pick_file(var, types)).pack(side="right", padx=(8, 0))
        ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)
        return row

    def _pick_file(self, var, types):
        picked = filedialog.askopenfilename(filetypes=types)
        if picked:
            var.set(picked)

    def _main_tab(self):
        outer = self.main_body
        p = self._group(outer, "1 · اختر تطبيق IPA")
        self._file_row(p, "IPA", self.ipa, [("iOS applications", "*.ipa"), ("All files", "*.*")])
        row = ttk.Frame(p, style="Panel.TFrame"); row.pack(fill="x", pady=(5, 0))
        ttk.Button(row, text="فحص ملف IPA", command=self.inspect).pack(side="left", padx=(0, 9))
        ttk.Label(row, textvariable=self.details, style="PanelMuted.TLabel", wraplength=720).pack(side="left", fill="x")
        p = self._group(outer, "2 · الآيفون المتصل")
        rr = ttk.Frame(p, style="Panel.TFrame"); rr.pack(fill="x")
        ttk.Button(rr, text="تحديث الأجهزة", command=self.scan_devices).pack(side="right", padx=(9, 0))
        self.device_select = ttk.Combobox(rr, textvariable=self.device_var, state="readonly")
        self.device_select.pack(side="left", fill="x", expand=True)
        self.device_select.bind("<<ComboboxSelected>>", self._on_device)
        self.device_status = ttk.Label(p, text="وصل الآيفون بكابل USB ثم اضغط Trust", style="PanelMuted.TLabel")
        self.device_status.pack(anchor="e", pady=(9, 0))
        p = self._group(outer, "3 · التوقيع المجاني وإعادة التثبيت")
        rr = ttk.Frame(p, style="Panel.TFrame"); rr.pack(fill="x", pady=(0, 9))
        ttk.Button(rr, text="وقّع وثبّت على الآيفون", style="Accent.TButton", command=self.sideload).pack(side="left", padx=(0, 8))
        ttk.Button(rr, text="وقّع فقط واحفظ IPA", command=self.engine_sign_only).pack(side="left", padx=(0, 8))
        ttk.Button(rr, text="جدّد كل التطبيقات", command=self.refresh_all).pack(side="left")
        ttk.Checkbutton(p, text="احتفظ بنسخة موقعة بعد التثبيت", variable=self.keep_signed).pack(anchor="e", pady=3)
        p = self._group(outer, "التطبيقات السابقة · صلاحية الشهادة")
        rr = ttk.Frame(p, style="Panel.TFrame"); rr.pack(fill="x", pady=(0, 8))
        ttk.Button(rr, text="عرض التطبيقات", command=self.list_installs).pack(side="left", padx=(0, 8))
        ttk.Button(rr, text="تجديد المحدد", command=self.refresh_one).pack(side="left")
        cols = ("app", "bundle", "expires")
        tree = ttk.Treeview(p, columns=cols, show="headings", height=4)
        for col, name, width in [("app", "App", 180), ("bundle", "Bundle ID", 310), ("expires", "Remaining", 110)]:
            tree.heading(col, text=name)
            tree.column(col, width=width, stretch=True)
        tree.pack(fill="x")
        self.installs_tree = tree

    def _apple_tab(self):
        p = self._group(self.apple_body, "تسجيل الدخول بحساب Apple العادي (دون اشتراك مطور)")
        ttk.Label(p, text="كلمة المرور ورمز 2FA إلى Apple عبر المحرك المحلي؛ لا يتم حفظهما في إعدادات IPA Studio.",
                  style="PanelMuted.TLabel", wraplength=850).pack(anchor="e", pady=(0, 12))
        ttk.Label(p, text="خادم Anisette المجتمعي يرى عنوان IP ومعرّفاً عشوائياً وبيانات تهيئة، وليس كلمة المرور وفق التصميم الموثق. راجع تبويب الخصوصية أولاً.",
                  style="PanelMuted.TLabel", wraplength=850).pack(anchor="e", pady=(0, 14))
        for label, var, secret in [("البريد الإلكتروني", self.apple_email, False), ("كلمة المرور", self.apple_password, True),
                                   ("رمز التحقق 2FA", self.apple_2fa, False)]:
            rr = ttk.Frame(p, style="Panel.TFrame"); rr.pack(fill="x", pady=5)
            ttk.Label(rr, text=label, width=18, style="Panel.TLabel").pack(side="right", padx=(12, 0))
            ttk.Entry(rr, textvariable=var, show="*" if secret else "").pack(side="left", fill="x", expand=True)
        rr = ttk.Frame(p, style="Panel.TFrame"); rr.pack(fill="x", pady=(14, 2))
        ttk.Button(rr, text="تسجيل الدخول", style="Accent.TButton", command=self.apple_login).pack(side="left", padx=(0, 8))
        ttk.Button(rr, text="إكمال 2FA", command=lambda: self.apple_login(twofa=True)).pack(side="left", padx=(0, 8))
        ttk.Button(rr, text="حالة الحساب", command=self.apple_status).pack(side="left", padx=(0, 8))
        ttk.Button(rr, text="تسجيل الخروج", command=self.apple_logout).pack(side="left")
        self.auth_state = ttk.Label(p, text="لم يتم فحص الحساب", style="PanelMuted.TLabel")
        self.auth_state.pack(anchor="w", pady=(14, 2))
        p = self._group(self.apple_body, "كيفية الاستخدام")
        for line in [
            "1. اختر خادم Anisette V3 من تبويب الخصوصية، واقرأ إشعار البيانات ثم فعّل الموافقة.",
            "2. سجّل Apple ID العادي وتابع 2FA. يُخزّن محرك iPASide رموز الجلسة محلياً.",
            "3. صِل الآيفون عبر USB واضغط Trust على الجهاز ثم حدده من الرئيسية.",
            "4. أضف IPA، اضغط فحص IPA ثم وقّع وثبّت. المحرك يُصدر بيانات توقيع مجانية من Apple.",
            "5. قبل انتهاء 7 أيام صِل الهاتف مجدداً واستخدم التجديد اليدوي.",
        ]:
            ttk.Label(p, text=line, style="Panel.TLabel", wraplength=850).pack(anchor="e", pady=5)

    def _config_tab(self):
        p = self._group(self.config_body, "خادم Anisette V3 واحد فقط · لا يوجد تبديل تلقائي")
        rr = ttk.Frame(p, style="Panel.TFrame"); rr.pack(fill="x")
        ttk.Label(rr, text="مزود الخدمة", style="Panel.TLabel").pack(side="right", padx=12)
        selector = ttk.Combobox(rr, textvariable=self.server_label, values=list(SERVERS), state="readonly", width=38)
        selector.pack(side="left", padx=4)
        ttk.Label(p, text="SideStore V3: new.ani.sidestore.io | jkcoxson: mac-ani.jkcoxson.com",
                  style="PanelMuted.TLabel").pack(anchor="w", pady=(6, 0))
        for note in [
            "هذه الخدمات ليست تابعة لـApple، ولا يمكننا ضمان أمان أو استمرارية تشغيلها.",
            "الخادم يستطيع رؤية عنوان IP، ومعرّف تهيئة عشوائي، وبيانات بروتوكول Anisette المعتمة.",
            "وفق شيفرة المحرك، كلمة مرور Apple ورمز 2FA ورمز جلسة Apple لا تُرسل إلى خادم Anisette.",
            "الاتصال بحساب Apple والشهادات يتم مباشرة إلى gsa.apple.com و developerservices2.apple.com.",
            "البرنامج يمنع التبديل التلقائي إلى خادم آخر. اتصال الآيفون USB فقط.",
            r"قد تُحفظ رموز جلسة Apple محلياً في %LOCALAPPDATA%\iPASide\session؛ احمِ حساب Windows.",
        ]:
            ttk.Label(p, text=note, style="Panel.TLabel", wraplength=850).pack(anchor="w", pady=4)
        def server_changed(*_):
            self.privacy_consent.set(False)
        self.server_label.trace_add("write", server_changed)
        ttk.Checkbutton(p, text="أوافق على الاتصال بهذا الخادم المحدد بعد قراءة البيانات التي قد يراها",
                        variable=self.privacy_consent).pack(anchor="w", pady=(15, 4))
        p = self._group(self.config_body, "محرك التوقيع المضمن · لا نسمح بمحرك خارجي")
        ttk.Entry(p, textvariable=self.engine, state="readonly").pack(fill="x", pady=6)
        ttk.Button(p, text="اختبار المحرك", command=self.check_engine).pack(anchor="e")
        p = self._group(self.config_body, "مسار حفظ IPA الموقع")
        rr = ttk.Frame(p, style="Panel.TFrame"); rr.pack(fill="x")
        ttk.Button(rr, text="اختر المجلد", command=self._pick_output_dir).pack(side="right")
        ttk.Entry(rr, textvariable=self.output_dir).pack(side="left", fill="x", expand=True, padx=(0, 12))
        ttk.Button(self.config_body, text="حفظ الإعدادات", style="Accent.TButton", command=self._save).pack(anchor="e", pady=16, padx=8)
        ttk.Label(self.config_body, text="لا تُحفظ موافقة الخادم تلقائياً بعد إعادة تشغيل البرنامج. لا يوجد تحديث تلقائي أو رفع IPA.",
                  style="Muted.TLabel", wraplength=850).pack(anchor="e", pady=5)

    def _logs_tab(self):
        p = self._group(self.logs_tab, "التشخيص · Operation logs")
        self.logbox = tk.Text(p, bg="#08111e", fg=TEXT, insertbackground=TEXT, relief="flat",
                              wrap="word", height=24, font=("Consolas", 10), padx=12, pady=12)
        self.logbox.pack(fill="both", expand=True)
        self.logbox.configure(state="disabled")
        ttk.Button(self.logs_tab, text="مسح السجل", command=self._clear_logs).pack(anchor="e", padx=10, pady=4)
        self._log("IPA Studio Trusted 4.0. Read the privacy policy before connecting.")

    def _on_device(self, _event=None):
        idx = self.device_select.current()
        if 0 <= idx < len(self.devices):
            item = self.devices[idx]
            self.device_status.configure(text=f"UDID: {item.get('serial', '?')} · {item.get('connection_type', '?')}")

    def _target(self) -> list[str]:
        args = ["--connection", "usb"]
        idx = self.device_select.current()
        if 0 <= idx < len(self.devices):
            udid = self.devices[idx].get("serial")
            if udid:
                args += ["--udid", str(udid)]
        return args

    def _post(self, event, *items):
        self.events.put((event, items))

    def _log(self, text):
        self._post("log", str(text))

    def _pump(self):
        try:
            for _ in range(70):
                event, items = self.events.get_nowait()
                if event == "log":
                    text = f"[{datetime.now():%H:%M:%S}] {items[0]}\n"
                    self.logbox.configure(state="normal")
                    self.logbox.insert("end", text)
                    self.logbox.see("end")
                    self.logbox.configure(state="disabled")
                elif event == "success":
                    callback, result, label = items
                    self.busy = False
                    self.status.set(label)
                    self.work_state.configure(text="●  Ready", fg=ACCENT)
                    if callback:
                        try:
                            callback(result)
                        except Exception as exc:
                            self._log(f"UI callback failed: {exc}")
                elif event == "error":
                    message = items[0]
                    self.busy = False
                    self.status.set("فشلت العملية · راجع السجل")
                    self.work_state.configure(text="●  Error", fg=RED)
                    self._log(f"ERROR: {message}")
                    messagebox.showerror("IPA Studio", message[:1400])
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def _work(self, title, worker, callback=None):
        if self.busy:
            messagebox.showinfo("IPA Studio", "هناك عملية قيد التنفيذ حالياً")
            return
        self.busy = True
        self.status.set(title)
        self.work_state.configure(text="●  Working...", fg="#f1c46b")
        self._log(title)
        def job():
            try:
                result = worker()
                self._post("success", callback, result, f"✓ {title} · Completed")
            except Exception as exc:
                self._post("error", str(exc))
        threading.Thread(target=job, daemon=True, name="IPAStudioJob").start()

    def _engine(self, cli_args, *, password=None, code=None, email=None):
        # Explicit consent required for every remote-auth/provision/sign/refresh.
        if cli_args and cli_args[0] in ("login", "provision", "sign", "sideload", "refresh"):
            self._require_consent()
        return run_engine(self.engine.get(), cli_args, password=password, code=code, email=email,
                          server=selected_url(self.server_label.get()), logger=self._log)

    def _require_consent(self):
        if not self.privacy_consent.get():
            raise StudioError("وافق على خادم Anisette المحدد في تبويب الخصوصية قبل الاتصال")


    def inspect(self):
        try:
            self.info = inspect_ipa(self.ipa.get())
        except StudioError as exc:
            messagebox.showerror("IPA inspection", str(exc))
            return
        i = self.info
        text = f"{i.name}  •  {i.bundle_id}  •  v{i.version}  •  iOS ≥ {i.minimum_ios}  •  {i.size_mb} MB"
        self.details.set(text)
        self._log("IPA INSPECT: " + text)
        if i.extensions or i.watch_apps:
            self._log(f"NOTE: {i.extensions} extensions, {i.watch_apps} watch apps; free signing may strip them")

    def system_doctor(self):
        def done(report):
            checks = report.get("checks", []) if isinstance(report, dict) else []
            for c in checks:
                self._log(f"[{c.get('status','?')}] {c.get('name','?')}: {c.get('detail','')}")
            if isinstance(report, dict) and report.get("overall") == "ok":
                messagebox.showinfo("USB readiness", "فحص النظام ناجح. تأكد من اتصال الآيفون وثقته بالحاسوب.")
            else:
                messagebox.showwarning("USB readiness", "توجد إعدادات قد تكون ناقصة. راجع سجل العمليات للتفاصيل.")
                self.tabs.select(self.logs_tab)
        self._work("Checking Apple device drivers and signing prerequisites",
                   lambda: self._engine(["doctor"]), done)

    def scan_devices(self):
        engine = self.engine.get()
        def done(devices):
            self.devices = [d for d in devices if "USB" in str(d.get("connection_type", "")).upper()] if isinstance(devices, list) else []
            items = [f"{d.get('serial','?')}   ({d.get('connection_type','?')})" for d in self.devices]
            self.device_select.configure(values=items)
            if len(items) == 1:
                self.device_select.current(0)
                self._on_device()
            else:
                self.device_var.set("")
                self.device_status.configure(text=f"{len(items)} device(s). Choose an iPhone before signing.")
        self._work("Searching for connected iPhones", lambda: self._engine(["devices"]), done)

    def sideload(self):
        try:
            inspect_ipa(self.ipa.get())
        except StudioError as exc:
            messagebox.showerror("IPA", str(exc)); return
        if self.device_select.current() < 0:
            messagebox.showwarning("USB", "حدد الآيفون المتصل بكابل USB أولاً"); return
        engine, ipa, target = self.engine.get(), self.ipa.get(), self._target()
        cli = ["sideload", ipa, *target]
        if self.keep_signed.get():
            cli.extend(["--keep-signed", "--signed-dir", self.output_dir.get()])
        def done(result):
            self._log("Signing and USB installation finished according to the engine.")
            self.list_installs()
            messagebox.showinfo("IPA Studio", "اكتملت عملية التوقيع والتثبيت بحسب المحرك. فعّل Developer Mode ووثّق المطوّر على الآيفون إذا لزم الأمر.")
        self._work("Signing and installing IPA", lambda: self._engine(cli), done)

    def engine_sign_only(self):
        try:
            info = inspect_ipa(self.ipa.get())
        except StudioError as exc:
            messagebox.showerror("IPA", str(exc)); return
        if self.device_select.current() < 0:
            messagebox.showwarning("USB", "حدد الآيفون المتصل بكابل USB أولاً"); return
        engine, target = self.engine.get(), self._target()
        output = default_output_path(info.path)
        output = Path(self.output_dir.get()) / output.name
        def worker():
            output.parent.mkdir(parents=True, exist_ok=True)
            self._engine(["provision", "--bundle-id", info.bundle_id,
                                "--app-name", info.name, *(target[2:] if "--udid" in target else [])])
            response = self._engine(["sign", str(info.path), "--output", str(output)])
            if not output.is_file() or not output.stat().st_size:
                raise StudioError("Engine returned success but signed IPA was not created")
            return response
        def done(resp):
            self._log("Signed copy saved: " + str(output))
            messagebox.showinfo("IPA signed", "Signed IPA saved to:\n" + str(output))
        self._work("Provisioning and signing IPA (without installing)", worker, done)

    def list_installs(self):
        engine = self.engine.get()
        def done(records):
            self.installs = records if isinstance(records, list) else []
            tree = self.installs_tree
            for item in tree.get_children(): tree.delete(item)
            for idx, rec in enumerate(self.installs):
                remaining = "EXPIRED" if rec.get("expired") else str(rec.get("days_left", "—")) + " days"
                tree.insert("", "end", iid=str(idx), values=(rec.get("name", ""), rec.get("bundle_id", ""), remaining))
        self._work("Loading signed app library", lambda: self._engine(["installs"]), done)

    def refresh_all(self):
        engine = self.engine.get(); con = self.connection.get()
        if not messagebox.askyesno("تجديد", "إعادة توقيع وإعادة تثبيت كل التطبيقات المسجلة الآن؟ اتصل بهاتفك أولاً."):
            return
        self._work("Refreshing all signed apps", lambda: self._engine(["refresh", "--all", "--connection", "usb"]), self._refresh_report)

    def refresh_one(self):
        selected = self.installs_tree.selection()
        if not selected:
            messagebox.showinfo("IPA Studio", "اختر تطبيقاً من القائمة أولاً"); return
        record = self.installs[int(selected[0])]
        bid = record.get("bundle_id")
        if not bid: return
        engine = self.engine.get(); con = self.connection.get()
        self._work(f"Refreshing {bid}", lambda: self._engine(["refresh", "--bundle-id", bid, "--connection", "usb"]), self._refresh_report)

    def _refresh_report(self, result):
        errors = [r for r in result.get("refreshed", []) if r.get("status") == "error"] if isinstance(result, dict) else []
        self._log("Manual refresh operation completed; see results shown above.")
        if errors:
            messagebox.showwarning("Refresh", "Some apps did not refresh. See logs for details.")
        else:
            messagebox.showinfo("Refresh", "Refresh operation finished. Check iPhone for updated apps.")
        self.list_installs()

    def apple_login(self, twofa=False):
        email = self.apple_email.get().strip()
        password = self.apple_password.get()
        code = self.apple_2fa.get().strip()
        if not email or not password:
            messagebox.showwarning("Apple ID", "Enter Apple ID and password. Neither is saved by IPA Studio."); return
        if twofa and not code:
            messagebox.showwarning("2FA", "Enter the six-digit verification code"); return
        engine = self.engine.get()
        args = ["login"]
        def done(result):
            state = result.get("status", "?") if isinstance(result, dict) else "?"
            if state == "2fa_required":
                self.auth_state.configure(text="Apple طلب رمز 2FA؛ أدخله ثم اضغط إكمال 2FA")
                self._log("Apple requests 2FA. Code is not stored.")
            else:
                self.apple_password.set("")
                self.apple_2fa.set("")
                self.auth_state.configure(text=f"✓ Apple ID connected: {email}")
                self._log("Apple ID login status: " + state)
        self._work("Authenticating Apple ID", lambda: self._engine(args, password=password, code=code if twofa else None, email=email), done)

    def apple_logout(self):
        if not messagebox.askyesno("Apple ID", "تسجيل الخروج وحذف رموز جلسة Apple المسجلة في محرك التوقيع؟"):
            return
        def done(_r):
            self.apple_password.set("")
            self.apple_2fa.set("")
            self.auth_state.configure(text="تم تسجيل الخروج")
        self._work("Signing out of Apple ID", lambda: self._engine(["login", "--logout"]), done)

    def apple_status(self):
        engine = self.engine.get()
        def done(r):
            self.auth_state.configure(text="✓ Connected: " + str(r.get("email", "")) if r.get("authenticated") else "Not connected")
        self._work("Checking Apple ID status", lambda: self._engine(["login", "--status"]), done)

    def check_engine(self):
        exe = self.engine.get()
        def done(res):
            messagebox.showinfo("Engine", "Engine detected: " + str(res.get("version", "?")))
        self._work("Checking iPASide Python Engine", lambda: self._engine(["version"]), done)

    def _pick_output_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir.set(directory)

    def _save(self):
        save_settings({"server_label": self.server_label.get(), "output_dir": self.output_dir.get()})
        self._log("Settings saved (no account or certificate passwords)")
        messagebox.showinfo("IPA Studio", "تم حفظ الإعدادات")

    def _clear_logs(self):
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.configure(state="disabled")

    def _close(self):
        if self.busy and not messagebox.askyesno("IPA Studio", "A signing operation may still be running. Exit anyway?"):
            return
        self.apple_password.set("")
        self.apple_2fa.set("")
        self._save_silent()
        self.destroy()

    def _save_silent(self):
        try:
            save_settings({"server_label": self.server_label.get(), "output_dir": self.output_dir.get()})
        except OSError:
            pass


def main():
    App().mainloop()


if __name__ == '__main__':
    main()
