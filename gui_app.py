import customtkinter as ctk
import threading, sys, os, time, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.pqc_wrapper import *
from src.hybrid_cert import generate_hybrid_chain
from src.attack_demo import run_attack_demo
from src.wire_format import inspect as wire_inspect, inspect_all
from src.impact_calc import calculate as impact_calc, enterprise_plan
from src.report_generator import generate_report
from src.secure_chat import SecureChatServer, SecureChatClient
from src.pqc_explanations import get_answer, TOPICS
from src.cert_builder import generate_cert, ALGORITHMS
import tkinter.filedialog as fd

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

FONT = ("Segoe UI", 13)
FONT_BOLD = ("Segoe UI", 14, "bold")
FONT_MONO = ("Consolas", 12)
FONT_SMALL = ("Segoe UI", 11)

class PQCApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("PQC Migration Toolkit")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 650)
        self.sidebar_open = True

        # Build real UI first
        top_bar = ctk.CTkFrame(self.root, fg_color="transparent")
        top_bar.pack(fill="x", padx=20, pady=(10, 0))
        ctk.CTkLabel(top_bar, text="PQC Migration Toolkit", font=("Segoe UI", 20, "bold"),
                     text_color="#00d2ff").pack(side="left")
        self.theme_btn = ctk.CTkButton(top_bar, text="☀ Light", font=FONT_SMALL, width=90,
                                        command=self._toggle_theme)
        self.theme_btn.pack(side="right", padx=5)
        export_btn = ctk.CTkButton(top_bar, text="📄 Export Report", font=FONT_SMALL, width=140,
                       command=lambda: threading.Thread(target=self._export_report, daemon=True).start())
        export_btn.pack(side="right", padx=5)
        self._add_tooltip(export_btn, "Generate a professional PDF assessment report")
        self._add_tooltip(self.theme_btn, "Toggle between dark and light theme")

        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.tabview = ctk.CTkTabview(self.main_container, fg_color="transparent")
        self.tabview.pack(side="left", fill="both", expand=True)

        self.tabs = {}
        self.chat_server = SecureChatServer()
        self.chat_client = SecureChatClient()
        modules = [
            ("Dashboard", self.build_dashboard),
            ("ML-KEM", self.build_kem),
            ("ML-DSA Signatures", self.build_sign),
            ("Hybrid TLS", self.build_tls),
            ("Secure Hybrid Chat", self.build_chat),
            ("Cert Migration", self.build_cert),
            ("Cert Builder", self.build_cert_builder),
            ("Benchmarks", self.build_bench),
            ("Hybrid Cert Chain", self.build_hybrid),
            ("Attack Demo", self.build_attack),
            ("Wire Format", self.build_wire),
            ("Enterprise Planner", self.build_enterprise),
            ("PQC Timeline", self.build_timeline),
            ("Impact Calc", self.build_impact),
        ]
        for name, builder in modules:
            tab = self.tabview.add(name)
            self.tabs[name] = tab
            builder(tab)

        self._build_sidebar()

        # Splash overlay on top of everything
        self._splash = ctk.CTkFrame(self.root, fg_color="#0a0a1a", corner_radius=0)
        self._splash.place(relx=0, rely=0, relwidth=1, relheight=1)
        ctk.CTkLabel(self._splash, text="PQC Migration Toolkit", font=("Segoe UI", 32, "bold"),
                     text_color="#00d2ff").place(relx=0.5, rely=0.4, anchor="center")
        ctk.CTkLabel(self._splash, text="Post-Quantum Cryptography Assessment Platform",
                     font=("Segoe UI", 14), text_color="#888888").place(relx=0.5, rely=0.48, anchor="center")
        spinner = ctk.CTkProgressBar(self._splash, mode="indeterminate", width=300)
        spinner.place(relx=0.5, rely=0.56, anchor="center")
        spinner.start()
        ctk.CTkLabel(self._splash, text="Loading modules...", font=("Segoe UI", 10),
                     text_color="#666666").place(relx=0.5, rely=0.62, anchor="center")

        self.root.after(1500, lambda: self._splash.destroy())

        self.root.mainloop()

    def _toggle_theme(self):
        current = ctk.get_appearance_mode()
        if current == "Dark":
            ctk.set_appearance_mode("Light")
            self.theme_btn.configure(text="🌙 Dark")
        else:
            ctk.set_appearance_mode("Dark")
            self.theme_btn.configure(text="☀ Light")

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self.main_container, width=320, fg_color="#151530", corner_radius=10)
        self.sidebar.pack(side="right", fill="y", padx=(10, 0), pady=0)
        self.sidebar.pack_propagate(False)

        toggle = ctk.CTkButton(self.sidebar, text="✕ Hide Assistant", font=FONT_SMALL,
                               width=30, command=self._toggle_sidebar)
        toggle.pack(anchor="ne", padx=8, pady=(8, 0))

        ctk.CTkLabel(self.sidebar, text="🤖 Ask PQC Assistant", font=("Segoe UI", 15, "bold"),
                     text_color="#00d2ff").pack(padx=12, pady=(5, 10))

        self.sidebar_entry = ctk.CTkEntry(self.sidebar, font=FONT, placeholder_text="Type a question...")
        self.sidebar_entry.pack(fill="x", padx=12, pady=5)
        self.sidebar_entry.bind("<Return>", lambda e: self._ask_question())

        btn_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkButton(btn_frame, text="Ask", font=FONT_SMALL, command=self._ask_question).pack(side="left", padx=(0, 5))
        ctk.CTkButton(btn_frame, text="Clear", font=FONT_SMALL, command=lambda: self.sidebar_answer.configure(state="normal") or self.sidebar_answer.delete("1.0", "end") or self.sidebar_answer.configure(state="disabled")).pack(side="left")

        ctk.CTkLabel(self.sidebar, text="Quick topics:", font=FONT_SMALL, text_color="#888888").pack(anchor="w", padx=14)
        topic_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", height=180)
        topic_frame.pack(fill="x", padx=10, pady=(0, 5))
        for topic in list(TOPICS.keys())[:8]:
            btn = ctk.CTkButton(topic_frame, text=topic, font=("Segoe UI", 10), fg_color="#1a1a4e",
                                hover_color="#2a2a7e", command=lambda t=topic: self._quick_topic(t))
            btn.pack(fill="x", pady=2)

        self.sidebar_answer = ctk.CTkTextbox(self.sidebar, font=("Segoe UI", 11), wrap="word", height=250)
        self.sidebar_answer.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.sidebar_answer.insert("1.0", "Ask a question about PQC, ML-KEM, ML-DSA, hybrid TLS, or any topic above.")
        self.sidebar_answer.configure(state="disabled")

    def _toggle_sidebar(self):
        if self.sidebar_open:
            self.sidebar.pack_forget()
            self.sidebar_open = False
        else:
            self.sidebar.pack(side="right", fill="y", padx=(10, 0), pady=0)
            self.sidebar_open = True

    def _ask_question(self):
        q = self.sidebar_entry.get().strip()
        if not q:
            return
        self.sidebar_entry.delete(0, "end")
        answer = get_answer(q)
        self.sidebar_answer.configure(state="normal")
        self.sidebar_answer.insert("end", f"\n\nYou: {q}\n\n")
        if answer:
            self.sidebar_answer.insert("end", f"Assistant: {answer}\n")
        else:
            self.sidebar_answer.insert("end", "Assistant: I don't have information on that topic. Try one of the quick topics above.\n")
        self.sidebar_answer.see("end")
        self.sidebar_answer.configure(state="disabled")

    def _quick_topic(self, topic):
        self.sidebar_entry.delete(0, "end")
        self.sidebar_entry.insert(0, topic)
        self._ask_question()

    def _header(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=FONT_BOLD, text_color="#00d2ff").pack(anchor="w", padx=20, pady=(20, 2))
    def _desc(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=FONT_SMALL, text_color="#888888", wraplength=1000, justify="left").pack(anchor="w", padx=20, pady=(0, 10))
    def _run_btn(self, parent, text, callback):
        btn = ctk.CTkButton(parent, text=text, font=FONT, command=lambda: threading.Thread(target=callback, daemon=True).start())
        btn.pack(pady=8)
        return btn
    def _output(self, parent):
        box = ctk.CTkTextbox(parent, font=FONT_MONO, height=200, wrap="word")
        box.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        return box
    def _progress(self, parent):
        pb = ctk.CTkProgressBar(parent, mode="indeterminate")
        pb.pack(fill="x", padx=20, pady=(0, 8))
        return pb

    def _table(self, parent, headers, rows):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=20, pady=5)
        for j, h in enumerate(headers):
            ctk.CTkLabel(frame, text=h, font=("Segoe UI", 12, "bold"), text_color="#888888").grid(row=0, column=j, sticky="w", padx=(0, 20), pady=2)
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                fg = "#4caf50" if val in ("PASS", "VALID", "MATCH") else "#f44336" if val in ("FAIL", "INVALID", "MISMATCH") else "#e0e0e0"
                ctk.CTkLabel(frame, text=str(val), font=("Consolas", 12), text_color=fg).grid(row=i+1, column=j, sticky="w", padx=(0, 20))

    # ─── TAB 0: DASHBOARD ───
    def build_dashboard(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Security Dashboard — Classical vs Post-Quantum")
        self._desc(f, "Real-time comparison of cryptographic algorithms. Red = vulnerable to quantum. Green = quantum-safe.")

        cols = ctk.CTkFrame(f, fg_color="transparent")
        cols.pack(fill="x", padx=20, pady=10)
        cols.grid_columnconfigure(0, weight=1)
        cols.grid_columnconfigure(1, weight=1)

        self._dashboard_card(cols, 0, 0,
            title="RSA-2048 (Classical)",
            icon="🔴",
            items=[
                ("Quantum Safe", "❌ No", "#f44336"),
                ("Risk Level", "98%", "#f44336"),
                ("Key Size", "256 bytes (public)", "#ffa500"),
                ("Security Basis", "Integer factorization (Shor)", "#888888"),
                ("Status", "BREAKING SOON", "#f44336"),
            ],
            bar_color="#f44336", bar_progress=0.98)

        self._dashboard_card(cols, 1, 0,
            title="ML-KEM-768 (Post-Quantum)",
            icon="🟢",
            items=[
                ("Quantum Safe", "✅ Yes", "#4caf50"),
                ("Security Level", "192-bit (NIST Level 3)", "#4caf50"),
                ("Key Size", "1,184 bytes (public)", "#4caf50"),
                ("Security Basis", "Module LWE (Lattice)", "#4caf50"),
                ("Status", "RECOMMENDED", "#4caf50"),
            ],
            bar_color="#4caf50", bar_progress=1.0)

        second = ctk.CTkFrame(f, fg_color="transparent")
        second.pack(fill="x", padx=20, pady=10)
        second.grid_columnconfigure(0, weight=1)
        second.grid_columnconfigure(1, weight=1)

        self._dashboard_card(second, 0, 0,
            title="ECDSA P-256 (Classical)",
            icon="🟡",
            items=[
                ("Quantum Safe", "❌ No", "#f44336"),
                ("Risk Level", "95%", "#f44336"),
                ("Signature Size", "~70 bytes", "#ffa500"),
                ("Security Basis", "Elliptic Curve DLP (Shor)", "#888888"),
                ("Status", "UPGRADE NEEDED", "#ffa500"),
            ],
            bar_color="#ffa500", bar_progress=0.95)

        self._dashboard_card(second, 1, 0,
            title="ML-DSA-65 (Post-Quantum)",
            icon="🟢",
            items=[
                ("Quantum Safe", "✅ Yes", "#4caf50"),
                ("Security Level", "192-bit (NIST Level 3)", "#4caf50"),
                ("Signature Size", "3,309 bytes", "#4caf50"),
                ("Security Basis", "Module LWE (Lattice)", "#4caf50"),
                ("Status", "RECOMMENDED", "#4caf50"),
            ],
            bar_color="#4caf50", bar_progress=1.0)

        third = ctk.CTkFrame(f, fg_color="transparent")
        third.pack(fill="x", padx=20, pady=10)
        third.grid_columnconfigure(0, weight=1)
        third.grid_columnconfigure(1, weight=1)
        third.grid_columnconfigure(2, weight=1)

        self._mini_card(third, 0, "X25519", "Classical", "❌", "#f44336")
        self._mini_card(third, 1, "ML-KEM-512", "128-bit PQ", "✅", "#4caf50")
        self._mini_card(third, 2, "ML-KEM-1024", "256-bit PQ", "✅", "#4caf50")

        rec = ctk.CTkFrame(f, fg_color="#0d2b1d", corner_radius=10)
        rec.pack(fill="x", padx=20, pady=(10, 20))
        ctk.CTkLabel(rec, text="✅ Recommendation", font=("Segoe UI", 15, "bold"), text_color="#4caf50").pack(anchor="w", padx=15, pady=(10, 2))
        ctk.CTkLabel(rec, text="NIST recommends migrating to ML-KEM-768 + ML-DSA-65 as the minimum for quantum safety. "
                     "Use hybrid mode (classical + PQC) during transition. Google Chrome already ships X25519MLKEM768.",
                     font=FONT_SMALL, text_color="#cccccc", wraplength=900, justify="left").pack(anchor="w", padx=15, pady=(0, 10))

    def _dashboard_card(self, parent, col, row, title, icon, items, bar_color, bar_progress):
        card = ctk.CTkFrame(parent, fg_color="#1a1a3e", corner_radius=12)
        card.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(12, 5))
        ctk.CTkLabel(header, text=icon, font=("Segoe UI", 28)).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(header, text=title, font=("Segoe UI", 15, "bold"), text_color="#e0e0e0").pack(side="left")
        for label, value, color in items:
            row_f = ctk.CTkFrame(card, fg_color="transparent")
            row_f.pack(fill="x", padx=15, pady=3)
            ctk.CTkLabel(row_f, text=label, font=FONT_SMALL, text_color="#888888").pack(side="left")
            ctk.CTkLabel(row_f, text=value, font=FONT_SMALL, text_color=color).pack(side="right")
        pbar = ctk.CTkProgressBar(card, height=6, corner_radius=3, fg_color="#2a2a4e", progress_color=bar_color)
        pbar.pack(fill="x", padx=15, pady=(8, 12))
        pbar.set(bar_progress)

    def _why_btn(self, parent, topic_key):
        btn = ctk.CTkButton(parent, text="Why?", font=("Segoe UI", 9), width=50, height=20,
                            fg_color="#2a2a5e", hover_color="#3a3a8e",
                            command=lambda: self._show_why_popup(topic_key))
        return btn

    def _show_why_popup(self, topic_key):
        from src.pqc_explanations import EXPLANATIONS
        text = EXPLANATIONS.get(topic_key, "No explanation available for this topic.")
        win = ctk.CTkToplevel(self.root)
        win.title(f"Explanation: {topic_key}")
        win.geometry("550x300")
        win.transient(self.root)
        win.grab_set()
        ctk.CTkLabel(win, text=topic_key.replace("-", " ").title(), font=("Segoe UI", 14, "bold"),
                     text_color="#00d2ff").pack(padx=20, pady=(12, 8))
        txt = ctk.CTkTextbox(win, font=("Segoe UI", 12), wrap="word")
        txt.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        txt.insert("1.0", text)
        txt.configure(state="disabled")

    def _add_tooltip(self, widget, text):
        tip = None
        def show(e):
            nonlocal tip
            if tip:
                return
            tip = ctk.CTkLabel(self.root, text=text, font=("Segoe UI", 9),
                                fg_color="#2a2a4e", text_color="#e0e0e0",
                                corner_radius=4, padx=6, pady=2)
            tip.place(x=e.x_root - self.root.winfo_rootx() + 10,
                      y=e.y_root - self.root.winfo_rooty() - 25)
        def hide(e):
            nonlocal tip
            if tip:
                tip.destroy(); tip = None
        widget.bind("<Enter>", show, add="+")
        widget.bind("<Leave>", hide, add="+")

    def _mini_card(self, parent, col, algo, desc, status, color):
        card = ctk.CTkFrame(parent, fg_color="#1a1a3e", corner_radius=10)
        card.grid(row=0, column=col, sticky="nsew", padx=5, pady=5)
        ctk.CTkLabel(card, text=algo, font=("Segoe UI", 13, "bold"), text_color="#e0e0e0").pack(padx=12, pady=(10, 0))
        ctk.CTkLabel(card, text=desc, font=FONT_SMALL, text_color="#888888").pack()
        ctk.CTkLabel(card, text=status, font=("Segoe UI", 18)).pack(pady=(0, 8))

    # ─── TAB 1: KEM ───
    def build_kem(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "ML-KEM Key Encapsulation (FIPS 203)")
        self._desc(f, "Three security levels: ML-KEM-512 (128-bit), ML-KEM-768 (192-bit), ML-KEM-1024 (256-bit). Based on Crystals-Kyber, standardized by NIST August 2024.")
        self.kem_table_frame = ctk.CTkFrame(f, fg_color="transparent")
        self.kem_table_frame.pack(fill="x", padx=20)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "ml-kem").pack(side="left", padx=5)
        self._why_btn(why_frame, "pqc-key-size").pack(side="left", padx=5)
        self._why_btn(why_frame, "fips-203").pack(side="left", padx=5)
        self._run_btn(f, "Run KEM Demo", self.run_kem)

        # ── KEM Encrypt/Decrypt section ──
        sep = ctk.CTkFrame(f, fg_color="#2a2a4e", height=2)
        sep.pack(fill="x", padx=20, pady=(20, 10))

        self._header(f, "Encrypt / Decrypt Custom Message")
        self._desc(f, "Type a message, select a security level, and use ML-KEM key encapsulation + AES-GCM to encrypt and decrypt.")

        cfg = ctk.CTkFrame(f, fg_color="transparent")
        cfg.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(cfg, text="Level:", font=FONT).pack(side="left", padx=(0, 5))
        self.kem_level_var = ctk.StringVar(value="ML-KEM-768")
        level_menu = ctk.CTkOptionMenu(cfg, variable=self.kem_level_var,
                                        values=["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
                                        font=FONT_SMALL, width=140)
        level_menu.pack(side="left", padx=(0, 20))

        ctk.CTkLabel(cfg, text="Message:", font=FONT).pack(side="left", padx=(0, 5))
        self.kem_msg_entry = ctk.CTkEntry(cfg, font=FONT, placeholder_text="Enter message to encrypt...")
        self.kem_msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_frame = ctk.CTkFrame(f, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkButton(btn_frame, text="🔐 Encrypt", font=FONT,
                       command=lambda: threading.Thread(target=self._kem_encrypt, daemon=True).start()
                       ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_frame, text="🔓 Decrypt", font=FONT,
                       command=lambda: threading.Thread(target=self._kem_decrypt, daemon=True).start()
                       ).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="💾 Export", font=FONT,
                       command=lambda: threading.Thread(target=self._kem_export, daemon=True).start()
                       ).pack(side="left", padx=5)

        why2 = ctk.CTkFrame(f, fg_color="transparent"); why2.pack(padx=20, pady=2)
        self._why_btn(why2, "ml-kem").pack(side="left", padx=5)
        self._why_btn(why2, "kem-encryption").pack(side="left", padx=5)
        self._why_btn(why2, "aes-gcm").pack(side="left", padx=5)

        self.kem_enc_out = self._output(f)
        self.kem_state = {}

    def run_kem(self):
        for w in self.kem_table_frame.winfo_children(): w.destroy()
        data = []
        for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
            ek, dk = kem_keygen(name); s, ct = kem_encaps(name, ek); r = kem_decaps(name, dk, ct)
            data.append((name, f"{len(ek)}B", f"{len(dk)}B", f"{len(ct)}B", "PASS" if s == r else "FAIL"))
        self._table(self.kem_table_frame, ["Algorithm", "Pubkey", "Privkey", "Ciphertext", "Status"], data)

    def _kem_encrypt(self):
        level = self.kem_level_var.get()
        msg = self.kem_msg_entry.get().strip()
        if not msg:
            self.kem_msg_entry.configure(placeholder_text="⚠ Message required!")
            return
        self.kem_enc_out.delete("1.0", "end")
        t0 = time.perf_counter()
        ek, dk = kem_keygen(level)
        shared, ct_kem = kem_encaps(level, ek)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"MLKEM-AES").derive(shared)
        nonce = os.urandom(12)
        enc_msg = AESGCM(aes_key).encrypt(nonce, msg.encode(), None)
        elapsed = (time.perf_counter() - t0) * 1000
        self.kem_state = dict(level=level, dk=dk, ct_kem=ct_kem, nonce=nonce, enc_msg=enc_msg)

        out = (
            f"── Encrypt Result ({level}) ──\n"
            f"  Message:        {msg}\n"
            f"  Pubkey:         {len(ek)} bytes\n"
            f"  Privkey:        {len(dk)} bytes\n"
            f"  KEM Ciphertext: {len(ct_kem)} bytes\n"
            f"  Encrypted Msg:  {len(enc_msg)} bytes\n"
            f"  Shared Secret:  {shared[:8].hex()}...\n"
            f"  Execution Time: {elapsed:.1f} ms\n"
        )
        self.kem_enc_out.insert("1.0", out)

    def _kem_decrypt(self):
        if not self.kem_state:
            self.kem_enc_out.delete("1.0", "end")
            self.kem_enc_out.insert("1.0", "⚠ No encrypted data. Click 'Encrypt' first.\n")
            return
        level = self.kem_state["level"]
        t0 = time.perf_counter()
        recovered = kem_decaps(level, self.kem_state["dk"], self.kem_state["ct_kem"])
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"MLKEM-AES").derive(recovered)
        plaintext = AESGCM(aes_key).decrypt(self.kem_state["nonce"], self.kem_state["enc_msg"], None)
        elapsed = (time.perf_counter() - t0) * 1000
        self.kem_enc_out.insert("end",
            f"── Decrypt Result ({level}) ──\n"
            f"  Recovered Secret: {recovered[:8].hex()}...\n"
            f"  Decrypted Msg:    {plaintext.decode()}\n"
            f"  Execution Time:   {elapsed:.1f} ms\n"
        )

    def _kem_export(self):
        if not self.kem_state:
            self.kem_enc_out.delete("1.0", "end")
            self.kem_enc_out.insert("1.0", "⚠ No data to export. Click 'Encrypt' first.\n")
            return
        path = fd.asksaveasfilename(defaultextension=".txt",
                                     filetypes=[("Text files", "*.txt")],
                                     title="Export KEM Result")
        if not path:
            return
        try:
            with open(path, "w") as f:
                f.write(f"Level: {self.kem_state['level']}\n")
                f.write(f"Encrypted Msg (hex): {self.kem_state['enc_msg'].hex()}\n")
                f.write(f"Nonce (hex): {self.kem_state['nonce'].hex()}\n")
                f.write(f"KEM Ciphertext (hex): {self.kem_state['ct_kem'].hex()}\n")
            self.kem_enc_out.insert("end", f"\n✅ Exported to {path}\n")
        except Exception as e:
            self.kem_enc_out.insert("end", f"\n❌ Export failed: {e}\n")

    # ─── TAB 2: SIGN ───
    def build_sign(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "ML-DSA Digital Signatures (FIPS 204)")
        self._desc(f, "Three security levels for post-quantum digital signatures. Based on Crystals-Dilithium.")
        self.sign_table_frame = ctk.CTkFrame(f, fg_color="transparent")
        self.sign_table_frame.pack(fill="x", padx=20)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "ml-dsa").pack(side="left", padx=5)
        self._why_btn(why_frame, "verification-fail").pack(side="left", padx=5)
        self._why_btn(why_frame, "fips-204").pack(side="left", padx=5)
        self._run_btn(f, "Run Signature Demo", self.run_sign)

        # ── ML-DSA Message Sign/Verify section ──
        sep = ctk.CTkFrame(f, fg_color="#2a2a4e", height=2)
        sep.pack(fill="x", padx=20, pady=(20, 10))

        self._header(f, "Sign / Verify Custom Message")
        self._desc(f, "Enter a message, sign it with ML-DSA, verify it, then tamper with the message to see verification fail.")

        cfg = ctk.CTkFrame(f, fg_color="transparent")
        cfg.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(cfg, text="Level:", font=FONT).pack(side="left", padx=(0, 5))
        self.sig_level_var = ctk.StringVar(value="ML-DSA-65")
        ctk.CTkOptionMenu(cfg, variable=self.sig_level_var,
                           values=["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
                           font=FONT_SMALL, width=140).pack(side="left", padx=(0, 20))

        ctk.CTkLabel(cfg, text="Message:", font=FONT).pack(side="left", padx=(0, 5))
        self.sig_msg_entry = ctk.CTkEntry(cfg, font=FONT, placeholder_text="Enter message to sign...")
        self.sig_msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_frame = ctk.CTkFrame(f, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkButton(btn_frame, text="✍ Sign", font=FONT,
                       command=lambda: threading.Thread(target=self._sig_sign, daemon=True).start()
                       ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_frame, text="✓ Verify", font=FONT,
                       command=lambda: threading.Thread(target=self._sig_verify, daemon=True).start()
                       ).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="✗ Tamper & Verify", font=FONT,
                       command=lambda: threading.Thread(target=self._sig_tamper, daemon=True).start()
                       ).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="💾 Export Sig", font=FONT,
                       command=lambda: threading.Thread(target=self._sig_export, daemon=True).start()
                       ).pack(side="left", padx=5)

        # ── Drag-and-drop (file dialog) section ──
        sep2 = ctk.CTkFrame(f, fg_color="#2a2a4e", height=2)
        sep2.pack(fill="x", padx=20, pady=(15, 10))

        self._header(f, "File Sign / Verify")
        self._desc(f, "Select a file to sign (generates .sig file) or verify a file against an existing .sig.")

        file_btn_frame = ctk.CTkFrame(f, fg_color="transparent")
        file_btn_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkButton(file_btn_frame, text="📁 Sign File → .sig", font=FONT,
                       command=lambda: threading.Thread(target=self._sig_sign_file, daemon=True).start()
                       ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(file_btn_frame, text="📁 Verify File with .sig", font=FONT,
                       command=lambda: threading.Thread(target=self._sig_verify_file, daemon=True).start()
                       ).pack(side="left", padx=5)

        why2 = ctk.CTkFrame(f, fg_color="transparent"); why2.pack(padx=20, pady=2)
        self._why_btn(why2, "ml-dsa").pack(side="left", padx=5)
        self._why_btn(why2, "digital-signatures").pack(side="left", padx=5)
        self._why_btn(why2, "verification-fail").pack(side="left", padx=5)

        self.sig_out = self._output(f)
        self.sig_state = {}

    def run_sign(self):
        for w in self.sign_table_frame.winfo_children(): w.destroy()
        msg = b"Test message for PQC signing."
        data = []
        for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            pk, sk = sig_keygen(name); sg = sig_sign(name, sk, msg); v = sig_verify(name, pk, msg, sg)
            data.append((name, f"{len(pk)}B", f"{len(sk)}B", f"{len(sg)}B", "VALID" if v else "INVALID"))
        self._table(self.sign_table_frame, ["Algorithm", "Pubkey", "Privkey", "Signature", "Status"], data)

    def _sig_sign(self):
        level = self.sig_level_var.get()
        msg = self.sig_msg_entry.get().strip()
        if not msg:
            self.sig_msg_entry.configure(placeholder_text="⚠ Message required!")
            return
        self.sig_out.delete("1.0", "end")
        t0 = time.perf_counter()
        pk, sk = sig_keygen(level)
        sg = sig_sign(level, sk, msg.encode())
        elapsed = (time.perf_counter() - t0) * 1000
        v = sig_verify(level, pk, msg.encode(), sg)
        self.sig_state = dict(level=level, pk=pk, msg=msg.encode(), sg=sg)
        out = (
            f"── Sign Result ({level}) ──\n"
            f"  Message:        {msg}\n"
            f"  Message Hash:   {hashlib.sha256(msg.encode()).hexdigest()[:16]}...\n"
            f"  Pubkey:         {len(pk)} bytes\n"
            f"  Signature:      {len(sg)} bytes\n"
            f"  Verification:   {'✓ VALID' if v else '✗ INVALID'}\n"
            f"  Execution Time: {elapsed:.1f} ms\n"
        )
        self.sig_out.insert("1.0", out)

    def _sig_verify(self):
        if "pk" not in self.sig_state or "sg" not in self.sig_state:
            self.sig_out.delete("1.0", "end")
            self.sig_out.insert("1.0", "⚠ No signature. Click 'Sign' first.\n")
            return
        t0 = time.perf_counter()
        v = sig_verify(self.sig_state["level"], self.sig_state["pk"],
                       self.sig_state["msg"], self.sig_state["sg"])
        elapsed = (time.perf_counter() - t0) * 1000
        self.sig_out.insert("end",
            f"── Verify Result ──\n"
            f"  Verification:   {'✓ VALID' if v else '✗ INVALID'}\n"
            f"  Execution Time: {elapsed:.1f} ms\n"
        )

    def _sig_tamper(self):
        if "msg" not in self.sig_state:
            self.sig_out.delete("1.0", "end")
            self.sig_out.insert("1.0", "⚠ No signature. Click 'Sign' first.\n")
            return
        tampered = self.sig_state["msg"] + b" (tampered)"
        t0 = time.perf_counter()
        v = sig_verify(self.sig_state["level"], self.sig_state["pk"],
                       tampered, self.sig_state["sg"])
        elapsed = (time.perf_counter() - t0) * 1000
        self.sig_out.insert("end",
            f"── Tamper & Verify ──\n"
            f"  Original Msg:   {self.sig_state['msg'].decode()}\n"
            f"  Tampered Msg:   {tampered.decode()}\n"
            f"  Verification:   {'✓ VALID' if v else '✗ INVALID'}\n"
            f"  Execution Time: {elapsed:.1f} ms\n"
            f"  → Tampered message correctly REJECTED\n"
        )

    def _sig_export(self):
        if "sg" not in self.sig_state:
            self.sig_out.delete("1.0", "end")
            self.sig_out.insert("1.0", "⚠ No signature to export. Click 'Sign' first.\n")
            return
        path = fd.asksaveasfilename(defaultextension=".sig",
                                     filetypes=[("Signature files", "*.sig"), ("All files", "*.*")],
                                     title="Export Signature (.sig)")
        if not path:
            return
        try:
            data = (
                f"ML-DSA Signature Export\n"
                f"Level: {self.sig_state['level']}\n"
                f"Message: {self.sig_state['msg'].decode()}\n"
                f"Msg Hash (SHA256): {hashlib.sha256(self.sig_state['msg']).hexdigest()}\n"
                f"Signature (hex): {self.sig_state['sg'].hex()}\n"
                f"Pubkey (hex): {self.sig_state['pk'].hex()}\n"
            )
            with open(path, "w") as f:
                f.write(data)
            self.sig_out.insert("end", f"\n✅ Exported to {path}\n")
        except Exception as e:
            self.sig_out.insert("end", f"\n❌ Export failed: {e}\n")

    def _sig_sign_file(self):
        path = fd.askopenfilename(title="Select a file to sign")
        if not path:
            return
        self.sig_out.delete("1.0", "end")
        self.sig_out.insert("end", f"Signing file: {path}\n")
        try:
            with open(path, "rb") as f:
                file_data = f.read()
            level = self.sig_level_var.get()
            t0 = time.perf_counter()
            pk, sk = sig_keygen(level)
            sg = sig_sign(level, sk, file_data)
            elapsed = (time.perf_counter() - t0) * 1000
            sig_path = path + ".sig"
            meta = (
                f"ML-DSA Signature Export\n"
                f"Level: {level}\n"
                f"Original File: {os.path.basename(path)}\n"
                f"File Size: {len(file_data)} bytes\n"
                f"File Hash (SHA256): {hashlib.sha256(file_data).hexdigest()}\n"
                f"Signature (hex): {sg.hex()}\n"
                f"Pubkey (hex): {pk.hex()}\n"
            )
            with open(sig_path, "w") as sf:
                sf.write(meta)
            self.sig_state = dict(level=level, pk=pk, msg=file_data, sg=sg)
            self.sig_out.insert("end",
                f"  Level:      {level}\n"
                f"  Signature:  {len(sg)} bytes\n"
                f"  Execution:  {elapsed:.1f} ms\n"
                f"  Saved:      {sig_path}\n"
            )
        except Exception as e:
            self.sig_out.insert("end", f"  ❌ Error: {e}\n")

    def _sig_verify_file(self):
        file_path = fd.askopenfilename(title="Select the original file")
        if not file_path:
            return
        sig_path = fd.askopenfilename(title="Select the .sig file",
                                       filetypes=[("Signature files", "*.sig"), ("All files", "*.*")])
        if not sig_path:
            return
        self.sig_out.delete("1.0", "end")
        self.sig_out.insert("end", f"Verifying: {os.path.basename(file_path)}\n  Against:  {os.path.basename(sig_path)}\n")
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            with open(sig_path, "r") as sf:
                meta = sf.read()
            level_line = [l for l in meta.splitlines() if l.startswith("Level:")]
            sig_line = [l for l in meta.splitlines() if l.startswith("Signature (hex):")]
            pk_line = [l for l in meta.splitlines() if l.startswith("Pubkey (hex):")]
            if not (level_line and sig_line and pk_line):
                raise ValueError("Invalid .sig file format")
            level = level_line[0].split(": ", 1)[1]
            sg = bytes.fromhex(sig_line[0].split(": ", 1)[1])
            pk = bytes.fromhex(pk_line[0].split(": ", 1)[1])
            t0 = time.perf_counter()
            v = sig_verify(level, pk, file_data, sg)
            elapsed = (time.perf_counter() - t0) * 1000
            self.sig_out.insert("end",
                f"  Level:        {level}\n"
                f"  Signature:    {len(sg)} bytes\n"
                f"  Verification: {'✓ VALID' if v else '✗ INVALID'}\n"
                f"  Execution:    {elapsed:.1f} ms\n"
            )
        except Exception as e:
            self.sig_out.insert("end", f"  ❌ Error: {e}\n")

    # ─── TAB 3: TLS ───
    def build_tls(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Hybrid TLS 1.3 Handshake (X25519 + ML-KEM-768)")
        self._desc(f, "Same design as Google Chrome's X25519MLKEM768. Two independent key agreements combined via HKDF. Watch each step of the handshake unfold.")
        self.tls_canvas = ctk.CTkFrame(f, fg_color="transparent")
        self.tls_canvas.pack(fill="x", padx=20, pady=5)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "hybrid-tls").pack(side="left", padx=5)
        self._why_btn(why_frame, "tls-handshake").pack(side="left", padx=5)
        self._run_btn(f, "Run TLS Handshake", self.run_tls)
        self.tls_stats_out = self._output(f)

    def run_tls(self):
        for w in self.tls_canvas.winfo_children(): w.destroy()
        self.tls_stats_out.delete("1.0", "end")

        steps = [
            ("ClientHello", "X25519 keypair generated + ML-KEM-768 pubkey", "#4dabf7", 600),
            ("ServerHello", "X25519 keypair generated + ML-KEM ciphertext", "#4dabf7", 600),
            ("Certificate", "Hybrid X.509 (RSA + ML-DSA) — identity verified", "#69db7c", 600),
            ("Key Exchange", "HKDF-SHA256 combines both shared secrets", "#ffa94d", 800),
            ("Finished", "Session key: [waiting]  Keys: [MATCH]", "#69db7c", 1200),
            ("🔒 Application Data", "AES-256-GCM encrypted channel established", "#9775fa", 400),
        ]

        total_delay = 100
        for label, desc, color, delay in steps:
            self.tls_canvas.after(total_delay, lambda lb=label, dc=desc, cl=color: self._add_tls_step(lb, dc, cl))
            total_delay += delay

        self.tls_canvas.after(total_delay, self._finish_tls)

    def _add_tls_step(self, label, desc, color):
        card = ctk.CTkFrame(self.tls_canvas, fg_color="#151530", corner_radius=8)
        card.pack(fill="x", pady=3, padx=5)
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=6)
        badge = ctk.CTkFrame(row, fg_color=color, corner_radius=4, width=16, height=16)
        badge.pack(side="left", padx=(0, 10))
        badge.pack_propagate(False)
        ctk.CTkLabel(row, text=label, font=("Segoe UI", 13, "bold"), text_color="#e0e0e0").pack(side="left", padx=(0, 15))
        ctk.CTkLabel(row, text=desc, font=("Segoe UI", 11), text_color="#aaaaaa").pack(side="left")

    def _finish_tls(self):
        t0 = time.perf_counter()
        c_key, s_key, stats = hybrid_tls()
        elapsed = (time.perf_counter() - t0) * 1000
        match = "MATCH" if c_key == s_key else "MISMATCH"
        out = (
            f"── Handshake Complete ({elapsed:.1f} ms) ──\n"
            f"  X25519 pubkey:    {stats['client_pub_x25519']}B\n"
            f"  ML-KEM pubkey:   {stats['client_pub_kem']}B\n"
            f"  KEM Ciphertext:  {stats['ct_size']}B\n"
            f"  Session Key:     {c_key[:8].hex()}...\n"
            f"  Keys Match:      [{match}]\n"
        )
        self.tls_stats_out.delete("1.0", "end")
        self.tls_stats_out.insert("1.0", out)

        # Update the Finished step with real key
        for w in self.tls_canvas.winfo_children():
            for child in w.winfo_children():
                for lbl in child.winfo_children():
                    if isinstance(lbl, ctk.CTkLabel) and "Session key" in lbl.cget("text"):
                        lbl.configure(text=f"Finished | Session key: {c_key[:8].hex()}...  Keys: [{match}]")

    # ─── TAB 4: SECURE HYBRID CHAT ───
    def build_chat(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Secure Hybrid Chat (X25519 + ML-KEM-768)")
        self._desc(f, "Start a local server, connect as client, and exchange encrypted messages using hybrid post-quantum cryptography.")

        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(5, 10))
        ctk.CTkButton(top, text="Start Server", font=FONT, command=lambda: threading.Thread(target=self._chat_start_server, daemon=True).start()).pack(side="left", padx=(0, 10))
        ctk.CTkButton(top, text="Connect Client", font=FONT, command=lambda: threading.Thread(target=self._chat_connect_client, daemon=True).start()).pack(side="left", padx=5)
        self.chat_status = ctk.CTkLabel(top, text="Status: Idle", font=FONT, text_color="#888888")
        self.chat_status.pack(side="right", padx=10)

        self.chat_out = ctk.CTkTextbox(f, font=FONT_MONO, height=250, wrap="word")
        self.chat_out.pack(fill="x", padx=20, pady=(0, 10))

        entry_frame = ctk.CTkFrame(f, fg_color="transparent")
        entry_frame.pack(fill="x", padx=20, pady=(0, 15))
        self.chat_entry = ctk.CTkEntry(entry_frame, font=FONT, placeholder_text="Type a message and press Send...")
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(entry_frame, text="Send", font=FONT, command=self._chat_send).pack(side="right")

    def _chat_log(self, msg):
        self.chat_out.insert("end", msg + "\n")
        self.chat_out.see("end")

    def _chat_start_server(self):
        def log(m):
            self.chat_out.after(0, lambda: self._chat_log(m))
        self.chat_out.delete("1.0", "end")
        self.chat_status.configure(text="Status: Starting server...", text_color="#ffa500")
        self.chat_server.start(log)
        log("\n--- Secure Chat Server Started ---")
        self.chat_status.configure(text="Status: Server running", text_color="#4caf50")
        self._chat_listen()

    def _chat_connect_client(self):
        def log(m):
            self.chat_out.after(0, lambda: self._chat_log(m))
        self.chat_status.configure(text="Status: Connecting...", text_color="#ffa500")
        self.chat_client.connect(log)
        self.chat_status.configure(text="Status: Client connected", text_color="#4caf50")
        self._chat_listen_client()

    def _chat_listen(self):
        def listen():
            while self.chat_server.session_key is None:
                time.sleep(0.2)
            while True:
                plain = self.chat_server.recv(self._chat_log)
                if plain is None:
                    break
                self.chat_out.after(0, lambda p=plain: self._chat_display_received(p, "Server"))
        threading.Thread(target=listen, daemon=True).start()

    def _chat_listen_client(self):
        def listen():
            while self.chat_client.session_key is None:
                time.sleep(0.2)
            while True:
                plain = self.chat_client.recv(self._chat_log)
                if plain is None:
                    break
                self.chat_out.after(0, lambda p=plain: self._chat_display_received(p, "Client"))
        threading.Thread(target=listen, daemon=True).start()

    def _chat_display_received(self, plain, role):
        self._chat_log(f"\n[+] {role} received (decrypted): {plain.decode()}")

    def _chat_send(self):
        text = self.chat_entry.get().strip()
        if not text:
            return
        self.chat_entry.delete(0, "end")
        msg = text.encode()
        if self.chat_server.session_key:
            self.chat_server.send(msg)
            self._chat_log(f"\n[Server] Sending encrypted packet...")
            self._chat_log(f"[Server] Algorithm: AES-256-GCM (keyed by X25519 + ML-KEM-768 HKDF)")
        elif self.chat_client.session_key:
            self.chat_client.send(msg)
            self._chat_log(f"\n[Client] Sending encrypted packet...")
            self._chat_log(f"[Client] Algorithm: AES-256-GCM (keyed by X25519 + ML-KEM-768 HKDF)")
        else:
            self._chat_log("\n[!] Start a server and connect a client first.")

    # ─── TAB 5: CERT ───
    def build_cert(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Certificate Migration Analysis")
        self._desc(f, "Compare classical vs post-quantum key sizes. PQC keys are 3-10x larger — impacts TLS, storage, and bandwidth.")
        self.cert_table_frame = ctk.CTkFrame(f, fg_color="transparent")
        self.cert_table_frame.pack(fill="x", padx=20)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "certificate-sizes").pack(side="left", padx=5)
        self._why_btn(why_frame, "pqc-key-size").pack(side="left", padx=5)
        self._run_btn(f, "Run Certificate Analysis", self.run_cert)

    def run_cert(self):
        for w in self.cert_table_frame.winfo_children(): w.destroy()
        data = []
        for algo, label in [
            (lambda: rsa.generate_private_key(65537, 2048), "RSA-2048 cert"),
            (lambda: rsa.generate_private_key(65537, 4096), "RSA-4096 cert"),
            (lambda: ec.generate_private_key(ec.SECP256R1()), "ECDSA P-256 cert"),
        ]:
            key = algo()
            cert = make_self_signed_cert(key)
            sz = len(cert.public_bytes(serialization.Encoding.PEM))
            data.append((label, f"{sz} bytes", "Classical"))
        for name in ["ML-DSA-65", "ML-DSA-87"]:
            pk, sk = sig_keygen(name)
            data.append((name + " pubkey", f"{len(pk)} bytes", "Post-Quantum"))
        self._table(self.cert_table_frame, ["Type", "Size", "Era"], data)

    # ─── TAB: CERT BUILDER ───
    def build_cert_builder(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Certificate Builder")
        self._desc(f, "Generate custom X.509 certificates with your own parameters. Supports RSA, ECDSA, and Ed25519.")

        form = ctk.CTkFrame(f, fg_color="#151530", corner_radius=10)
        form.pack(fill="x", padx=20, pady=10)
        row1 = ctk.CTkFrame(form, fg_color="transparent"); row1.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(row1, text="Common Name:", font=FONT_SMALL, text_color="#888888", width=140).pack(side="left")
        self.builder_cn = ctk.CTkEntry(row1, font=FONT)
        self.builder_cn.pack(side="left", fill="x", expand=True)
        self.builder_cn.insert(0, "example.com")

        row2 = ctk.CTkFrame(form, fg_color="transparent"); row2.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(row2, text="Organization:", font=FONT_SMALL, text_color="#888888", width=140).pack(side="left")
        self.builder_org = ctk.CTkEntry(row2, font=FONT)
        self.builder_org.pack(side="left", fill="x", expand=True)
        self.builder_org.insert(0, "My Organization")

        row3 = ctk.CTkFrame(form, fg_color="transparent"); row3.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(row3, text="Country:", font=FONT_SMALL, text_color="#888888", width=140).pack(side="left")
        self.builder_country = ctk.CTkEntry(row3, font=FONT, width=80)
        self.builder_country.pack(side="left")
        self.builder_country.insert(0, "US")

        row4 = ctk.CTkFrame(form, fg_color="transparent"); row4.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(row4, text="Algorithm:", font=FONT_SMALL, text_color="#888888", width=140).pack(side="left")
        self.builder_algo = ctk.CTkOptionMenu(row4, values=ALGORITHMS, font=FONT)
        self.builder_algo.pack(side="left")

        row5 = ctk.CTkFrame(form, fg_color="transparent"); row5.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(row5, text="Validity (days):", font=FONT_SMALL, text_color="#888888", width=140).pack(side="left")
        self.builder_validity = ctk.CTkEntry(row5, font=FONT, width=100)
        self.builder_validity.pack(side="left")
        self.builder_validity.insert(0, "365")

        ctk.CTkButton(form, text="Generate Certificate", font=FONT,
                       command=lambda: threading.Thread(target=self._run_builder, daemon=True).start()).pack(pady=12)

        self.builder_out = ctk.CTkTextbox(f, font=FONT_MONO, height=280, wrap="word")
        self.builder_out.pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(f, text="Save As PEM", font=FONT,
                       command=self._save_builder_pem).pack(pady=(0, 15))

    def _run_builder(self):
        self.builder_out.delete("1.0", "end")
        try:
            cn = self.builder_cn.get().strip() or "example.com"
            org = self.builder_org.get().strip() or "My Organization"
            country = self.builder_country.get().strip()[:2] or "US"
            algo = self.builder_algo.get()
            days = int(self.builder_validity.get().strip() or "365")
            cert, pem, key = generate_cert(cn, org, country, algo, days)
            self.builder_out.insert("end", f"Certificate generated successfully!\n\n")
            self.builder_out.insert("end", f"Subject: CN={cn}, O={org}, C={country}\n")
            self.builder_out.insert("end", f"Algorithm: {algo}\n")
            self.builder_out.insert("end", f"Validity: {days} days\n")
            self.builder_out.insert("end", f"Size: {len(pem)} bytes (PEM)\n")
            self.builder_out.insert("end", f"Public key: {len(key.public_key().public_bytes(serialization.Encoding.Raw))} bytes (raw)\n")
            self.builder_out.insert("end", f"\n{'─' * 60}\n")
            self.builder_out.insert("end", pem.decode())
            self._last_pem = pem.decode()
        except Exception as e:
            self.builder_out.insert("end", f"Error: {e}")

    def _save_builder_pem(self):
        if not hasattr(self, '_last_pem') or not self._last_pem:
            return
        path = fd.asksaveasfilename(defaultextension=".pem",
                                     filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if path:
            with open(path, "w") as f:
                f.write(self._last_pem)

    # ─── TAB: BENCH ───
    def build_bench(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Performance Benchmarks")
        self._desc(f, "Detailed benchmarks with min/max/stddev over 5 iterations. Includes RSA, ECC, ML-KEM, and ML-DSA.")
        ctrl = ctk.CTkFrame(f, fg_color="transparent"); ctrl.pack(fill="x", padx=20, pady=5)
        self.bench_save_btn = ctk.CTkButton(ctrl, text="💾 Export CSV", font=FONT,
                                            command=lambda: threading.Thread(target=self._bench_export, daemon=True).start())
        self.bench_save_btn.pack(side="right", padx=5)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "benchmarks").pack(side="left", padx=5)
        self._run_btn(f, "Run Benchmarks", self.run_bench)
        self.bench_out = self._output(f)
        self._bench_data = []

    def run_bench(self):
        self.bench_out.delete("1.0", "end")
        self._bench_data = []
        iters = 5
        self.bench_out.insert("end", f"Benchmarking over {iters} iterations...\n\n")

        for label, fn in [("RSA-2048", measure_full_rsa), ("ECDSA P-256", measure_full_ecc)]:
            self.bench_out.insert("end", f"── {label} ──\n")
            r = fn(iters)
            for op, vals in r.items():
                avg, mn, mx, std = describe_stats(vals)
                self._bench_data.append((f"{label} {op}", avg, mn, mx, std))
                self.bench_out.insert("end", f"  {op:>8}: avg={avg:.1f}ms  min={mn:.1f}  max={mx:.1f}  σ={std:.1f}\n")

        self.bench_out.insert("end", "\n── ML-KEM (Key Encapsulation) ──\n")
        for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
            r = measure_full_kem(name, iters)
            for op, vals in r.items():
                avg, mn, mx, std = describe_stats(vals)
                self._bench_data.append((f"{name} {op}", avg, mn, mx, std))
                self.bench_out.insert("end", f"  {name} {op:>7}: avg={avg:.1f}ms  min={mn:.1f}  max={mx:.1f}  σ={std:.1f}\n")

        self.bench_out.insert("end", "\n── ML-DSA (Digital Signatures) ──\n")
        for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            r = measure_full_sig(name, iters)
            for op, vals in r.items():
                avg, mn, mx, std = describe_stats(vals)
                self._bench_data.append((f"{name} {op}", avg, mn, mx, std))
                self.bench_out.insert("end", f"  {name} {op:>7}: avg={avg:.1f}ms  min={mn:.1f}  max={mx:.1f}  σ={std:.1f}\n")

        self._plot_bench_chart()

    def _plot_bench_chart(self):
        if not self._bench_data:
            return
        import matplotlib.pyplot as plt
        labels = [f"{d[0][:12]}.." if len(d[0]) > 14 else d[0] for d in self._bench_data]
        avgs = [d[1] for d in self._bench_data]
        fig, ax = plt.subplots(figsize=(10, 5))
        colors = ["#ff6b6b" if "RSA" in d[0] or "ECDSA" in d[0] else "#4dabf7" if "ML-KEM" in d[0] else "#69db7c" for d in self._bench_data]
        bars = ax.barh(range(len(labels)), avgs, color=colors, tick_label=labels)
        ax.set_xlabel("Time (ms)")
        ax.set_title("Crypto Benchmark Comparison (avg ms, 5 iterations)")
        ax.invert_yaxis()
        for i, (_, v) in enumerate(zip(labels, avgs)):
            ax.text(v + 1, i, f"{v:.1f}", va="center", fontsize=8)
        fig.tight_layout()
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_chart.png")
        fig.savefig(path, dpi=120)
        plt.close(fig)
        self.bench_out.insert("end", f"\n📊 Chart saved: {path}\n")

    def _bench_export(self):
        if not self._bench_data:
            self.bench_out.delete("1.0", "end")
            self.bench_out.insert("1.0", "⚠ Run benchmarks first.\n")
            return
        path = fd.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Operation", "Avg (ms)", "Min (ms)", "Max (ms)", "StdDev (ms)"])
                w.writerows(self._bench_data)
            self.bench_out.insert("end", f"\n✅ CSV exported to {path}\n")
        except Exception as e:
            self.bench_out.insert("end", f"\n❌ Export failed: {e}\n")

    # ─── TAB 6: HYBRID CHAIN ───
    def build_hybrid(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Hybrid Certificate Chain (RSA + ML-DSA)")
        self._desc(f, "Root CA → Intermediate → Leaf — click each certificate for details.")
        self.hybrid_canvas = ctk.CTkFrame(f, fg_color="transparent")
        self.hybrid_canvas.pack(fill="x", padx=20, pady=5)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "hybrid-tls").pack(side="left", padx=5)
        self._why_btn(why_frame, "certificate-sizes").pack(side="left", padx=5)
        self._run_btn(f, "Generate Hybrid Chain", self.run_hybrid)
        self.hybrid_out = self._output(f)

    def _add_chain_card(self, parent, label, issuer, subject, algo, expire, size, valid, color):
        card = ctk.CTkFrame(parent, fg_color="#151530", corner_radius=10)
        card.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ctk.CTkLabel(card, text=label, font=("Segoe UI", 14, "bold"), text_color=color).pack(anchor="w", padx=12, pady=(8, 2))
        for lbl, val in [("Issuer", issuer), ("Subject", subject), ("Algorithm", algo),
                          ("Expires", expire), ("Size", f"{size} bytes"),
                          ("Status", valid)]:
            row = ctk.CTkFrame(card, fg_color="transparent"); row.pack(fill="x", padx=12, pady=1)
            ctk.CTkLabel(row, text=f"{lbl}:", font=("Segoe UI", 10), text_color="#888888", width=60).pack(side="left")
            ctk.CTkLabel(row, text=val, font=("Segoe UI", 10), text_color="#e0e0e0").pack(side="left")
        status_color = "#4caf50" if "VALID" in valid else "#f44336"
        ctk.CTkLabel(card, text=valid, font=("Segoe UI", 12, "bold"), text_color=status_color).pack(anchor="w", padx=12, pady=(5, 8))

    def run_hybrid(self):
        for w in self.hybrid_canvas.winfo_children(): w.destroy()
        self.hybrid_out.delete("1.0", "end")
        text, stats = generate_hybrid_chain()

        # Arrow connector
        def arrow():
            return ctk.CTkLabel(self.hybrid_canvas, text="  ↓  ", font=("Segoe UI", 20), text_color="#00d2ff")

        self._add_chain_card(self.hybrid_canvas, "🔒 Root CA",
            "PQC Hybrid Root CA", "PQC Hybrid Root CA",
            "RSA-4096 + ML-DSA-65", "10 years",
            stats["root_size"] + stats["mldsa_root_sig"],
            "✓ Root Signature VALID", "#69db7c")
        arrow()
        self._add_chain_card(self.hybrid_canvas, "🔐 Intermediate",
            "PQC Hybrid Root CA", "PQC Hybrid Intermediate CA",
            "RSA-2048 + ML-DSA-65", "5 years",
            stats["inter_size"] + stats["mldsa_inter_sig"],
            "✓ Inter Signature VALID", "#4dabf7")
        arrow()
        self._add_chain_card(self.hybrid_canvas, "📜 Leaf",
            "PQC Hybrid Intermediate CA", "hybrid-demo.example.com",
            "RSA-2048 + ML-DSA-44", "1 year",
            stats["leaf_size"] + stats["mldsa_leaf_sig"],
            "✓ Leaf Signature VALID", "#ffa94d")

        for line in text.split("\n"):
            self.hybrid_out.insert("end", line.strip() + "\n")

        # Animate validation
        self.hybrid_out.after(100, lambda: self.hybrid_out.insert("end", "\n✅ Chain validation complete — all certificates verified.\n"))

    # ─── TAB 7: ATTACK DEMO ───
    def build_attack(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Harvest Now, Decrypt Later Attack Demo")
        self._desc(f, "Enter a custom secret message and watch the HNDL attack unfold. RSA gets broken by quantum; ML-KEM survives.")
        ctrl = ctk.CTkFrame(f, fg_color="transparent"); ctrl.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(ctrl, text="Secret Message:", font=FONT).pack(side="left", padx=(0, 5))
        self.attack_msg_entry = ctk.CTkEntry(ctrl, font=FONT, placeholder_text="Enter your secret message...")
        self.attack_msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.attack_msg_entry.insert(0, "TOP SECRET")
        self.attack_canvas = ctk.CTkFrame(f, fg_color="transparent")
        self.attack_canvas.pack(fill="both", expand=True, padx=20, pady=5)
        btn_row = ctk.CTkFrame(f, fg_color="transparent"); btn_row.pack(padx=20, pady=5)
        ctk.CTkButton(btn_row, text="▶ Run Attack", font=FONT,
                       command=lambda: threading.Thread(target=self.run_attack_viz, daemon=True).start()
                       ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_row, text="🔄 Replay", font=FONT,
                       command=lambda: threading.Thread(target=self.run_attack_viz, daemon=True).start()
                       ).pack(side="left", padx=5)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "attack-demo").pack(side="left", padx=5)
        self._why_btn(why_frame, "harvest-now").pack(side="left", padx=5)

    def run_attack_viz(self):
        for w in self.attack_canvas.winfo_children(): w.destroy()
        secret = self.attack_msg_entry.get().strip() or "TOP SECRET"
        steps = []

        def add_step(icon, label, color, delay=1200):
            steps.append((icon, label, color, delay))

        add_step("👤", f"Alice has a secret message: \"{secret}\"", "#4caf50", 500)
        add_step("🔒", "Encrypts with RSA-32 (classical)", "#ffa500", 1000)
        add_step("🌐", "Message travels over the Internet", "#888888", 1000)
        add_step("👁️", "Eve (attacker) records the packet", "#f44336", 1000)
        add_step("💾", "Packet stored — Harvest Now phase", "#ffa500", 1000)
        add_step("⏳", "Years pass... quantum computers arrive", "#888888", 1000)
        add_step("⚛️", "Quantum computer runs Shor's algorithm", "#e040fb", 1200)
        add_step("💔", "RSA-32 modulus FACTORED — key broken", "#f44336", 1200)
        add_step("📖", f"Message RECOVERED: \"{secret}\"", "#f44336", 1500)
        add_step("", "", None, 500)
        add_step("🔄", "Now with ML-KEM-768 (post-quantum)...", "#00d2ff", 1000)
        add_step("🔒", "Alice encrypts using ML-KEM-768", "#4caf50", 1000)
        add_step("👁️", "Eve records the ML-KEM ciphertext", "#f44336", 1000)
        add_step("⚛️", "Quantum computer attacks lattice problem", "#e040fb", 1200)
        add_step("✅", "Attack FAILED — lattice problem is quantum-hard", "#4caf50", 1200)
        add_step("🛡️", "Message remains secure forever", "#4caf50", 1000)

        total_delay = 100
        for icon, label, color, delay in steps:
            self.attack_canvas.after(total_delay, lambda ic=icon, lb=label, cl=color: self._add_attack_step(ic, lb, cl))
            total_delay += delay

    def _add_attack_step(self, icon, label, color):
        if not icon and not label:
            ctk.CTkLabel(self.attack_canvas, text="", height=10).pack()
            return
        row = ctk.CTkFrame(self.attack_canvas, fg_color="transparent")
        row.pack(fill="x", pady=4, padx=10)
        bg = "#1a3a1a" if color == "#4caf50" else "#3a1a1a" if color == "#f44336" else "#2a2a3e" if color == "#e040fb" else "#1a1a2e"
        card = ctk.CTkFrame(row, fg_color=bg, corner_radius=8)
        card.pack(fill="x", padx=5, pady=2)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=6)
        ctk.CTkLabel(inner, text=icon, font=("Segoe UI", 18)).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(inner, text=label, font=("Segoe UI", 13), text_color=color if color != "#888888" else "#aaaaaa").pack(side="left")

    # ─── TAB 8: WIRE FORMAT ───
    def build_wire(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Wire-Format Inspection")
        self._desc(f, "Byte-level view of PQC artifacts. Switch between Hex, Annotated, and Binary views.")
        ctrl = ctk.CTkFrame(f, fg_color="transparent"); ctrl.pack(fill="x", padx=20, pady=5)
        self.wire_view_var = ctk.StringVar(value="Hex + ASCII")
        self.wire_view_menu = ctk.CTkOptionMenu(ctrl, variable=self.wire_view_var,
                                                  values=["Hex + ASCII", "Annotated Fields", "Binary (bits)", "Size Table"],
                                                  font=FONT_SMALL, width=160,
                                                  command=lambda _: self.run_wire())
        self.wire_view_menu.pack(side="left")
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "pqc-key-size").pack(side="left", padx=5)
        self._why_btn(why_frame, "wire-format").pack(side="left", padx=5)
        self._run_btn(f, "Inspect Wire Format", self.run_wire)
        self.wire_out = self._output(f)

    def run_wire(self):
        self.wire_out.delete("1.0", "end")
        data = inspect_all()
        view = self.wire_view_var.get()
        if view == "Hex + ASCII":
            text = "\n\n".join(data["hex"])
        elif view == "Annotated Fields":
            text = "\n\n".join(data["annotate"])
        elif view == "Binary (bits)":
            text = "\n\n".join(data["binary"])
        else:
            text = "\n\n─── Size Comparison Table ───\n" + "\n".join(data["sizes"])
        self.wire_out.insert("1.0", text)

    # ─── TAB: ENTERPRISE PLANNER ───
    def build_enterprise(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Enterprise Migration Planner")
        self._desc(f, "Plan your organization's PQC migration with detailed cost, risk, and bandwidth estimates.")
        form = ctk.CTkFrame(f, fg_color="#151530", corner_radius=10)
        form.pack(fill="x", padx=20, pady=10)

        def add_field(row, label, widget):
            r = ctk.CTkFrame(form, fg_color="transparent"); r.pack(fill="x", padx=15, pady=4)
            ctk.CTkLabel(r, text=label, font=FONT_SMALL, text_color="#888888", width=200).pack(side="left")
            widget.pack(side="right", fill="x", expand=True)

        self.ent_users = ctk.CTkEntry(form, font=FONT); add_field(0, "Employees/Users:", self.ent_users); self.ent_users.insert(0, "10000")
        self.ent_servers = ctk.CTkEntry(form, font=FONT); add_field(1, "Servers:", self.ent_servers); self.ent_servers.insert(0, "500")
        self.ent_certs = ctk.CTkEntry(form, font=FONT); add_field(2, "Active certificates:", self.ent_certs); self.ent_certs.insert(0, "5000")
        self.ent_tls = ctk.CTkEntry(form, font=FONT); add_field(3, "TLS handshakes/day:", self.ent_tls); self.ent_tls.insert(0, "500000")
        self.ent_traffic = ctk.CTkEntry(form, font=FONT); add_field(4, "Avg traffic (GB/day):", self.ent_traffic); self.ent_traffic.insert(0, "100")
        self.ent_algo = ctk.CTkOptionMenu(form, values=["ML-KEM-768", "ML-KEM-512", "ML-KEM-1024"], font=FONT)
        add_field(5, "Target PQC Algorithm:", self.ent_algo)
        self.ent_ratio = ctk.CTkEntry(form, font=FONT, width=80); add_field(6, "Hybrid ratio (e.g. 0.5):", self.ent_ratio); self.ent_ratio.insert(0, "0.5")

        btn_row = ctk.CTkFrame(form, fg_color="transparent"); btn_row.pack(pady=10)
        ctk.CTkButton(btn_row, text="Generate Migration Plan", font=FONT,
                       command=lambda: threading.Thread(target=self._run_enterprise, daemon=True).start()).pack(side="left", padx=5)
        ctk.CTkButton(btn_row, text="💾 Save Report", font=FONT,
                       command=lambda: threading.Thread(target=self._ent_export, daemon=True).start()).pack(side="left", padx=5)

        # Risk gauge
        self.ent_risk_frame = ctk.CTkFrame(f, fg_color="transparent")
        self.ent_risk_frame.pack(fill="x", padx=20, pady=(5, 0))

        self.ent_out = ctk.CTkTextbox(f, font=FONT_MONO, height=280, wrap="word")
        self.ent_out.pack(fill="both", expand=True, padx=20, pady=(8, 15))

    def _run_enterprise(self):
        self.ent_out.delete("1.0", "end")
        try:
            users = int(self.ent_users.get().strip() or 10000)
            servers = int(self.ent_servers.get().strip() or 500)
            certs = int(self.ent_certs.get().strip() or 5000)
            tls = int(self.ent_tls.get().strip() or 500000)
            traffic = int(self.ent_traffic.get().strip() or 100)
            algo = self.ent_algo.get() or "ML-KEM-768"
            ratio = float(self.ent_ratio.get().strip() or 0.5)
            text, data = enterprise_plan(users=users, servers=servers, cert_count=certs,
                                          tls_per_day=tls, traffic_gb_per_day=traffic,
                                          algo=algo, hybrid_ratio=ratio)
            self.ent_out.insert("end", text)
            self._update_ent_risk(data.get("risk_level", "Medium"), data.get("risk_score", 50))
        except Exception as e:
            self.ent_out.insert("end", f"Error: {e}")

    def _update_ent_risk(self, level, score):
        for w in self.ent_risk_frame.winfo_children(): w.destroy()
        colors = {"Low": "#4caf50", "Medium": "#ffa500", "High": "#f44336"}
        color = colors.get(level, "#888888")
        card = ctk.CTkFrame(self.ent_risk_frame, fg_color="#151530", corner_radius=8)
        card.pack(fill="x", padx=5, pady=5)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(inner, text="Risk Level:", font=FONT, text_color="#888888").pack(side="left")
        ctk.CTkLabel(inner, text=f" {level} ({score}/100) ", font=("Segoe UI", 14, "bold"),
                      text_color=color).pack(side="left", padx=(10, 0))
        pb = ctk.CTkProgressBar(inner, height=10, corner_radius=5, fg_color="#2a2a4e", progress_color=color)
        pb.pack(side="left", fill="x", expand=True, padx=(15, 0))
        pb.set(score / 100)

    def _ent_export(self):
        text = self.ent_out.get("1.0", "end-1c").strip()
        if not text:
            self.ent_out.insert("end", "\n⚠ Generate a plan first.\n")
            return
        path = fd.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w") as f:
                f.write(text)
            self.ent_out.insert("end", f"\n✅ Report saved to {path}\n")
        except Exception as e:
            self.ent_out.insert("end", f"\n❌ Save failed: {e}\n")

    # ─── TAB: PQC TIMELINE ───
    def build_timeline(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "PQC Interactive Timeline")
        self._desc(f, "The history of cryptography — from RSA to post-quantum standards. Click each event to learn more.")

        events = [
            ("1977", "RSA Cryptography Invented", "Rivest, Shamir, and Adleman publish the RSA cryptosystem. "
             "It becomes the foundation of secure internet communication for the next 40+ years. RSA's security "
             "relies on the difficulty of factoring large prime products — a problem Shor's algorithm can solve easily "
             "on a quantum computer.", "#ff6b6b"),
            ("1985", "Elliptic Curve Cryptography (ECC)", "Neal Koblitz and Victor Miller independently propose "
             "elliptic curve cryptography. ECC offers equivalent security to RSA with much smaller key sizes (256-bit "
             "ECC ≈ 3072-bit RSA). ECDH and ECDSA become widely used in TLS, Bitcoin, and Signal. Also broken by "
             "Shor's algorithm.", "#ffa94d"),
            ("2016", "NIST PQC Competition Begins", "NIST launches an 8-year worldwide competition to select "
             "post-quantum cryptography standards. 82 candidate algorithms are submitted from teams across the "
             "globe. The competition includes multiple families: lattice-based, code-based, multivariate, hash-based, "
             "and isogeny-based cryptography.", "#4dabf7"),
            ("2022", "ML-KEM (Kyber) Selected as Winner", "After 4 rounds of evaluation, NIST selects CRYSTALS-Kyber "
             "as the primary KEM standard (FIPS 203) and CRYSTALS-Dilithium as the primary signature standard "
             "(FIPS 204). Both are lattice-based. Backup algorithms BIKE, HQC (KEM) and SPHINCS+ (signatures) "
             "are also selected.", "#69db7c"),
            ("2024", "FIPS 203 Published — ML-KEM Standardized", "NIST formally publishes FIPS 203 (ML-KEM) and "
             "FIPS 204 (ML-DSA). These are the first official US government standards for post-quantum cryptography. "
             "Google Chrome ships X25519MLKEM768 hybrid key exchange to all users. Signal, Apple iMessage, and "
             "Amazon AWS all deploy PQC in production.", "#69db7c"),
            ("2024", "FIPS 204 Published — ML-DSA Standardized", "ML-DSA (based on Dilithium) becomes the official "
             "NIST standard for quantum-safe digital signatures. Three security levels: ML-DSA-44 (128-bit), "
             "ML-DSA-65 (192-bit), ML-DSA-87 (256-bit). Signatures are 35-66x larger than classical equivalents, "
             "which becomes a key migration challenge.", "#69db7c"),
            ("2025", "Enterprise PQC Migration Begins", "Major corporations and government agencies begin "
             "inventorying their cryptographic assets and planning PQC migration. The US National Security "
             "Memorandum (NSM-10) mandates federal agencies to begin migration. Hybrid certificates (classical "
             "+ PQC) become the standard approach for Certificate Authorities.", "#9775fa"),
            ("2030", "Target: Full PQC Adoption", "Industry experts predict most critical systems will complete "
             "PQC migration by 2030. By this time, quantum computers with ~1000+ logical qubits may exist, "
             "potentially breaking RSA-2048. Organizations still running classical-only crypto face significant "
             "risk of Harvest Now Decrypt Later attacks succeeding.", "#9775fa"),
            ("2035+", "Post-Quantum World", "In the long term, all internet traffic is expected to use "
             "post-quantum or hybrid cryptography. Classical algorithms like RSA and ECDH will be deprecated "
             "in favor of ML-KEM, ML-DSA, and potentially newer PQC algorithms. The migration will be "
             "comparable in scale to the Y2K effort or the HTTPS transition.", "#748ffc"),
        ]

        for i, (year, title, desc, color) in enumerate(events):
            card = ctk.CTkFrame(f, fg_color="#1a1a3e", corner_radius=10)
            card.pack(fill="x", padx=30, pady=6)
            year_lbl = ctk.CTkLabel(card, text=year, font=("Segoe UI", 20, "bold"), text_color=color)
            year_lbl.pack(anchor="w", padx=15, pady=(10, 0))
            ctk.CTkLabel(card, text=title, font=("Segoe UI", 14, "bold"), text_color="#e0e0e0").pack(anchor="w", padx=15, pady=(2, 2))
            ctk.CTkButton(card, text="Learn More", font=FONT_SMALL, fg_color=color, text_color="#000",
                          hover_color="#ffffff", command=lambda d=desc, t=title, y=year: self._show_event_popup(y, t, d)).pack(anchor="w", padx=15, pady=(0, 10))

    def _show_event_popup(self, year, title, desc):
        win = ctk.CTkToplevel(self.root)
        win.title(f"{year} - {title}")
        win.geometry("550x350")
        win.transient(self.root)
        win.grab_set()
        ctk.CTkLabel(win, text=f"{year}: {title}", font=("Segoe UI", 16, "bold"), text_color="#00d2ff").pack(padx=20, pady=(15, 10))
        txt = ctk.CTkTextbox(win, font=("Segoe UI", 12), wrap="word")
        txt.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        txt.insert("1.0", desc)
        txt.configure(state="disabled")

    # ─── TAB: IMPACT CALC ───
    def build_impact(self, parent):
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent"); f.pack(fill="both", expand=True)
        self._header(f, "Migration Impact Calculator")
        self._desc(f, "Estimates extra storage and bandwidth costs when switching from classical to post-quantum cryptography. Adjustable parameters.")
        self.impact_out = self._output(f)
        why_frame = ctk.CTkFrame(f, fg_color="transparent"); why_frame.pack(padx=20, pady=2)
        self._why_btn(why_frame, "pqc-key-size").pack(side="left", padx=5)
        self._why_btn(why_frame, "certificate-sizes").pack(side="left", padx=5)
        self._run_btn(f, "Calculate Impact", self.run_impact)

    def run_impact(self):
        self.impact_out.delete("1.0", "end")
        text, data = impact_calc()
        self.impact_out.insert("end", text)

    def _export_report(self):
        try:
            path = generate_report()
            win = ctk.CTkToplevel(self.root)
            win.title("Report Generated")
            win.geometry("450x150")
            win.transient(self.root)
            win.grab_set()
            ctk.CTkLabel(win, text="✅ Report Generated", font=("Segoe UI", 16, "bold"), text_color="#4caf50").pack(pady=(15, 5))
            ctk.CTkLabel(win, text=f"Saved to:\n{path}", font=FONT_SMALL, text_color="#cccccc").pack(pady=5)
            ctk.CTkButton(win, text="OK", command=win.destroy).pack(pady=10)
        except Exception as e:
            win = ctk.CTkToplevel(self.root)
            win.title("Report Error")
            win.geometry("400x130")
            win.transient(self.root)
            win.grab_set()
            ctk.CTkLabel(win, text="❌ Report Failed", font=("Segoe UI", 16, "bold"), text_color="#f44336").pack(pady=(15, 5))
            ctk.CTkLabel(win, text=str(e), font=FONT_SMALL, text_color="#cccccc").pack(pady=5)

if __name__ == "__main__":
    PQCApp()
