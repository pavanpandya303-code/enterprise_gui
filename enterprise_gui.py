"""Enterprise PQC Assessment — standalone CustomTkinter dashboard.

Runs independently of gui_app.py (`python enterprise_gui.py`) so the main
toolkit is never touched. Uses the analysis engine in
:mod:`src.enterprise_assessment` for all logic.
"""

import datetime
import os
import shutil
import sys
import tempfile
import threading
from typing import List, Tuple

import customtkinter as ctk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.enterprise_assessment import (
    CryptoInventory, EnterpriseAssessor, ALGORITHM_KB, RiskLevel,
    RISK_WEIGHTS,
)
from src.algorithm_demo import (ALGORITHMS as DEMO_ALGORITHMS, GROUPS, run_multi,
                                REVERSIBLE_ALGORITHMS, cascade_encrypt,
                                cascade_decrypt, cascade_verify)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

FONT = ("Segoe UI", 13)
FONT_BOLD = ("Segoe UI", 15, "bold")
FONT_SMALL = ("Segoe UI", 11)
FONT_MONO = ("Consolas", 12)

RISK_COLORS = {
    RiskLevel.CRITICAL.value: "#f44336",
    RiskLevel.HIGH.value: "#ff9800",
    RiskLevel.MEDIUM.value: "#ffc107",
    RiskLevel.LOW.value: "#8bc34a",
    RiskLevel.SAFE.value: "#4caf50",
}

# Inventory profiles are deliberately data-driven.  The assessor can therefore
# calculate findings from the selected organization's actual asset mix instead
# of displaying the same generic result set for every organization.
ORGANIZATION_PROFILES = {
    "Small Office": [
        ("Server", "RSA-2048", 2048, 3),
        ("TLS", "TLS 1.2", 0, 3),
        ("Symmetric", "AES-256", 256, 10),
        ("Hash", "SHA-256", 0, 10),
    ],
    "Enterprise": [
        ("Server", "RSA-2048", 2048, 80),
        ("Server", "ECDSA P-256", 256, 60),
        ("Server", "X25519", 256, 200),
        ("Certificate", "RSA-2048", 2048, 400),
        ("TLS", "TLS 1.2", 0, 120),
        ("TLS", "TLS 1.3", 0, 180),
        ("Hash", "SHA-1", 0, 40),
        ("Symmetric", "AES-256", 256, 500),
    ],
    "Bank / Government": [
        ("Server", "RSA-2048", 2048, 250),
        ("Server", "ECDSA P-256", 256, 90),
        ("Certificate", "SHA-1", 0, 320),
        ("TLS", "TLS 1.2", 0, 400),
        ("Symmetric", "AES-128", 128, 900),
        ("Hash", "SHA-256", 0, 900),
    ],
    "Healthcare": [
        ("Server", "RSA-2048", 2048, 45),
        ("Certificate", "RSA-2048", 2048, 180),
        ("TLS", "TLS 1.2", 0, 210),
        ("TLS", "TLS 1.3", 0, 70),
        ("Symmetric", "AES-128", 128, 320),
        ("Hash", "SHA-1", 0, 18),
    ],
    "SaaS / Cloud": [
        ("Server", "ECDSA P-256", 256, 120),
        ("Server", "X25519", 256, 480),
        ("Certificate", "RSA-2048", 2048, 260),
        ("TLS", "TLS 1.3", 0, 620),
        ("Symmetric", "AES-256", 256, 850),
        ("Hash", "SHA-256", 0, 850),
    ],
    "Retail": [
        ("Server", "RSA-2048", 2048, 30),
        ("Certificate", "RSA-2048", 2048, 90),
        ("TLS", "TLS 1.2", 0, 140),
        ("Symmetric", "AES-128", 128, 500),
        ("Hash", "SHA-256", 0, 500),
    ],
}


class AssessmentApp:
    """Main dashboard window."""

    def __init__(self) -> None:
        self.root = ctk.CTk()
        self.root.title("Enterprise PQC Assessment")
        self.root.geometry("1250x820")
        self.root.minsize(1024, 700)

        self.inventory = CryptoInventory()
        # Working-copy inventory used by the most recent ANALYZE run. Mirrors
        # the real inventory plus the quick-add selection that was scored.
        self._scored_inventory: CryptoInventory | None = None
        # Tracks which organization profile the current inventory matches.
        # None means the inventory contains custom/manual edits.
        self._loaded_org: str | None = None
        # True when the user has (touched) the quick-add Algorithm / Count /
        # Category fields so ANALYZE should fold that selection into the
        # working copy. Kept False on a plain ANALYZE so the baseline report
        # is never polluted by a default dropdown value.
        self._pending_dirty = False

        self._build_top_bar()
        self._build_body()
        # Start with a meaningful organization-specific inventory rather than
        # an empty/generic report.
        self._load_selected_organization()

    # ── Layout ───────────────────────────────────────────────
    def _build_top_bar(self) -> None:
        bar = ctk.CTkFrame(self.root, fg_color="transparent")
        bar.pack(fill="x", padx=20, pady=(12, 4))
        ctk.CTkLabel(bar, text="Enterprise PQC Assessment",
                     font=("Segoe UI", 20, "bold"),
                     text_color="#00d2ff").pack(side="left")
        ctk.CTkButton(bar, text="📄 Executive Report (PDF)", font=FONT_SMALL,
                      command=lambda: threading.Thread(
                          target=self._export_report, daemon=True).start()
                      ).pack(side="right", padx=5)
        self.theme_btn = ctk.CTkButton(bar, text="☀ Light", font=FONT_SMALL,
                                       width=90, command=self._toggle_theme)
        self.theme_btn.pack(side="right", padx=5)

    def _build_body(self) -> None:
        container = ctk.CTkFrame(self.root, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=15, pady=(4, 10))

        container.grid_columnconfigure(1, weight=1)
        container.grid_rowconfigure(0, weight=1)

        # Left: manual input form
        self._build_form(container)

        # Right: tabbed dashboard
        self.tabview = ctk.CTkTabview(container, fg_color="transparent")
        self.tabview.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        for name in ("Dashboard", "Crypto Inventory", "Risk Analysis",
                     "Recommendations", "Migration Roadmap", "🔬 Crypto Playground",
                     "🧮 Calculation Trace"):
            self.tabview.add(name)

        self._build_dashboard_tab(self.tabview.tab("Dashboard"))
        self._build_inventory_tab(self.tabview.tab("Crypto Inventory"))
        self._build_risk_tab(self.tabview.tab("Risk Analysis"))
        self._build_recs_tab(self.tabview.tab("Recommendations"))
        self._build_roadmap_tab(self.tabview.tab("Migration Roadmap"))
        self._build_demo_tab(self.tabview.tab("🔬 Crypto Playground"))
        self._build_trace_tab(self.tabview.tab("🧮 Calculation Trace"))

    # ── Left form ────────────────────────────────────────────
    def _build_form(self, parent) -> None:
        form = ctk.CTkFrame(parent, fg_color="#151530", corner_radius=12, width=320)
        form.grid(row=0, column=0, sticky="nsw", padx=(0, 5))
        form.pack_propagate(False)

        ctk.CTkLabel(form, text="🖥 Manual Infrastructure Input",
                     font=FONT_BOLD, text_color="#00d2ff").pack(
            anchor="w", padx=15, pady=(14, 4))

        ctk.CTkLabel(form, text="Organization profile:", font=FONT_SMALL,
                     text_color="#888888").pack(anchor="w", padx=15,
                                                 pady=(5, 0))
        self.organization_menu = ctk.CTkOptionMenu(
            form, values=list(ORGANIZATION_PROFILES), font=FONT_SMALL,
            command=lambda _v: self._on_profile_changed())
        self.organization_menu.set("Small Office")
        self.organization_menu.pack(fill="x", padx=15, pady=3)
        ctk.CTkButton(form, text="Load Selected Organization", font=FONT_SMALL,
                      command=self._load_selected_organization).pack(
            fill="x", padx=15, pady=(2, 6))

        # Quick-add asset by algorithm
        ctk.CTkLabel(form, text="Algorithm:", font=FONT_SMALL,
                     text_color="#888888").pack(anchor="w", padx=15)
        self.algo_menu = ctk.CTkOptionMenu(form, values=sorted(ALGORITHM_KB),
                                           font=FONT_SMALL,
                                           command=lambda _v:
                                           self._mark_quick_add_dirty())
        self.algo_menu.pack(fill="x", padx=15, pady=3)

        ctk.CTkLabel(form, text="Count:", font=FONT_SMALL,
                     text_color="#888888").pack(anchor="w", padx=15)
        self.count_entry = ctk.CTkEntry(form, font=FONT_SMALL)
        self.count_entry.insert(0, "1")
        self.count_entry.pack(fill="x", padx=15, pady=3)
        self.count_entry.bind("<KeyRelease>",
                              lambda _e: self._mark_quick_add_dirty())

        self.asset_cat = ctk.CTkOptionMenu(form, values=["Server", "Certificate",
                                                          "TLS", "Hash", "Symmetric"],
                                           font=FONT_SMALL,
                                           command=lambda _v:
                                           self._mark_quick_add_dirty())
        self.asset_cat.pack(fill="x", padx=15, pady=3)

        ctk.CTkButton(form, text="➕ Add Asset", font=FONT_SMALL,
                      command=self._add_asset).pack(fill="x", padx=15, pady=(3, 6))

        # Preset inventory templates
        ctk.CTkLabel(form, text="Presets:", font=FONT_SMALL,
                     text_color="#888888").pack(anchor="w", padx=15, pady=(6, 2))
        presets = ctk.CTkFrame(form, fg_color="transparent")
        presets.pack(fill="x", padx=15, pady=2)
        for text, cmd in [("🏢 Small Office", self._preset_small),
                          ("🏛 Enterprise", self._preset_enterprise),
                          ("🏦 Bank / Gov", self._preset_bank)]:
            ctk.CTkButton(presets, text=text, font=("Segoe UI", 10), height=26,
                          fg_color="#1a1a4e", hover_color="#2a2a7e",
                          command=cmd).pack(fill="x", pady=2)

        self.added_label = ctk.CTkLabel(form, text="", font=FONT_SMALL,
                                        text_color="#4caf50")
        self.added_label.pack(anchor="w", padx=15, pady=3)

        ctk.CTkButton(form, text="🔍 ANALYZE", font=FONT_BOLD, height=40,
                      fg_color="#0d47a1", hover_color="#1565c0",
                      command=lambda: threading.Thread(
                          target=self._run_analysis, daemon=True).start()
                      ).pack(fill="x", padx=15, pady=(14, 4))
        self.analyze_hint = ctk.CTkLabel(form, text="Press ANALYZE to run risk "
                                                    "analysis & scoring.",
                                         font=("Segoe UI", 9),
                                         text_color="#888888", wraplength=280)
        self.analyze_hint.pack(anchor="w", padx=15, pady=(0, 14))

        self.form = form

    # ── Input handlers ───────────────────────────────────────
    def _pending_selection(self) -> Tuple[str, str, int]:
        """(algorithm, category, count) currently shown in the quick-add
        fields without needing an "Add Asset" click."""
        algo = self.algo_menu.get()
        cat = self.asset_cat.get()
        try:
            count = max(1, int(self.count_entry.get().strip() or "1"))
        except ValueError:
            count = 1
        return algo, cat, count

    def _mark_quick_add_dirty(self) -> None:
        """Remember the user deliberately changed the quick-add fields so a
        later ANALYZE folds that algorithm into the scored working copy."""
        self._pending_dirty = True
        self._invalidate_analysis()

    def _typical_deployment_scale(self) -> int:
        """Estimate how many instances of a crypto asset this organization
        typically deploys per class.

        Derived only from the org's own inventory (total assets / number of
        distinct classes), so a quick-add selection is folded into the scored
        copy at a representative size. For huge inventories (Enterprise 1580,
        Bank 2860, SaaS 3180 assets) a single extra asset would otherwise move
        the weighted readiness by ~0.03% — invisible after rounding — which is
        exactly why every organization except the tiny Small Office appeared
        to return identical results.
        """
        total = self.inventory.total_assets()
        n = max(len(self.inventory.assets), 1)
        return max(1, round(total / n))

    def _working_inventory(self) -> CryptoInventory:
        """Clone the real inventory and fold in the algorithm the user has
        selected in the quick-add fields, so ANALYZE reflects that selection.

        The real inventory (and any custom edits) is never mutated here; the
        selection is scored on a working copy only unless the user clicks
        "Add Asset". When the user changed the Algorithm / Count / Category
        since the last add, the just-selected asset is merged into the copy at
        the organization's typical deployment scale (matching what a broad
        deployment of that algorithm would look like), so a different pick
        always yields a visibly different scored inventory for ANY sized
        organization.
        """
        inv = CryptoInventory()
        for a in self.inventory.to_dict():
            inv.add(a["category"], a["name"], a["algorithm"],
                    a["key_size"], a["count"])
        if self._pending_dirty:
            algo, cat, count = self._pending_selection()
            inv.add(cat, algo, algo, key_size=self._kb_bits(algo), count=count)
        return inv

    def _add_asset(self) -> None:
        algo = self.algo_menu.get()
        try:
            count = max(1, int(self.count_entry.get().strip() or "1"))
        except ValueError:
            count = 1
        cat = self.asset_cat.get()
        self.inventory.add(cat, algo, algo, key_size=self._kb_bits(algo),
                           count=count)
        self._loaded_org = None
        self._pending_dirty = False  # the selected asset is now committed
        self._invalidate_analysis()
        self.added_label.configure(
            text=f"✓ Added {count}× {algo} ({cat})")

    def _load_selected_organization(self) -> None:
        """Replace the working inventory with the selected profile.

        This is explicit rather than automatic so adding a custom asset does
        not unexpectedly erase the user's work when the dropdown changes.
        """
        organization = self.organization_menu.get()
        self.inventory = CryptoInventory()
        for category, name, key_size, count in ORGANIZATION_PROFILES[organization]:
            self.inventory.add(category, name, name, key_size, count)
        # Seed the quick-add count with a representative deployment size for
        # this organization, so swapping the algorithm alone still moves the
        # score meaningfully for large inventories. The count the user types
        # afterwards is always honored exactly.
        scale = self._typical_deployment_scale()
        self.count_entry.delete(0, "end")
        self.count_entry.insert(0, str(scale))
        self._loaded_org = organization
        self._pending_dirty = False  # fresh profile: nothing pending
        self._invalidate_analysis()
        self.added_label.configure(
            text=f"✓ {organization} profile loaded "
                 f"({len(ORGANIZATION_PROFILES[organization])} asset types)")

    def _invalidate_analysis(self) -> None:
        """Ensure a report cannot be exported from a previous inventory."""
        if hasattr(self, "result"):
            del self.result
        if hasattr(self, "analyze_hint"):
            self.analyze_hint.configure(
                text="Inventory changed. Press ANALYZE for an updated report.",
                text_color="#ffa500")

    def _on_profile_changed(self) -> None:
        """Dropdown changed: drop any stale report until ANALYZE is pressed.

        The inventory is *not* replaced here on purpose (a manual "Load
        Selected Organization" click keeps custom assets safe), but any
        previously computed results no longer represent the selection.
        """
        self._invalidate_analysis()
        self.added_label.configure(
            text="Profile selected but not yet applied. "
                 "Press Load Selected Organization or ANALYZE.")

    def _ensure_selected_profile(self) -> None:
        """Make ANALYZE always score the profile shown in the dropdown.

        If the dropdown was changed without pressing "Load Selected
        Organization" (and without manual asset edits), reload that profile so
        results cannot silently reflect a different organization under the same
        selection. Custom assets (which clear ``self._loaded_org``) are never
        discarded by this path.
        """
        if self._loaded_org is None:
            return  # custom inventory: the user owns the exact contents
        selected = self.organization_menu.get()
        if selected != self._loaded_org:
            self._load_selected_organization()

    @staticmethod
    def _kb_bits(algo: str) -> int:
        bits = 0
        for part in algo.split("-"):
            if part.isdigit():
                bits = int(part)
        return bits

    def _preset_small(self) -> None:
        self.organization_menu.set("Small Office")
        self._load_selected_organization()

    def _preset_enterprise(self) -> None:
        self.organization_menu.set("Enterprise")
        self._load_selected_organization()

    def _preset_bank(self) -> None:
        self.organization_menu.set("Bank / Government")
        self._load_selected_organization()

    def _clear_inventory(self) -> None:
        self.inventory = CryptoInventory()
        self._pending_dirty = False

    # ── Right tabs ───────────────────────────────────────────
    def _build_dashboard_tab(self, parent) -> None:
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True)

        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=10)
        top.grid_columnconfigure(0, weight=1)
        top.grid_columnconfigure(1, weight=2)

        # Circular gauge
        gauge_card = ctk.CTkFrame(top, fg_color="#151530", corner_radius=12)
        gauge_card.grid(row=0, column=0, sticky="nsew", padx=5)
        ctk.CTkLabel(gauge_card, text="PQC Readiness Score",
                     font=FONT_BOLD).pack(padx=15, pady=(12, 4))
        self.gauge_canvas = self._make_canvas(gauge_card, 200, 200)
        self.gauge_canvas.pack(pady=4)
        self.gauge_label = ctk.CTkLabel(gauge_card, text="—",
                                        font=("Segoe UI", 26, "bold"),
                                        text_color="#888888")
        self.gauge_label.pack(pady=(0, 4))
        self.grade_label = ctk.CTkLabel(gauge_card, text="Run ANALYZE to begin",
                                        font=FONT_SMALL, text_color="#888888")
        self.grade_label.pack(pady=(0, 12))

        # Summary cards
        summary_card = ctk.CTkFrame(top, fg_color="#151530", corner_radius=12)
        summary_card.grid(row=0, column=1, sticky="nsew", padx=5)
        ctk.CTkLabel(summary_card, text="📊 Enterprise Summary",
                     font=FONT_BOLD).pack(anchor="w", padx=15, pady=(12, 6))
        self.summary_grid = ctk.CTkFrame(summary_card, fg_color="transparent")
        self.summary_grid.pack(fill="both", expand=True, padx=10, pady=(0, 12))
        self._init_summary_grid()

        # Risk distribution bars
        bar_card = ctk.CTkFrame(f, fg_color="#151530", corner_radius=12)
        bar_card.pack(fill="x", padx=25, pady=8)
        ctk.CTkLabel(bar_card, text="⚠ Risk Distribution",
                     font=FONT_BOLD).pack(anchor="w", padx=15, pady=(10, 4))
        self.risk_bars = ctk.CTkFrame(bar_card, fg_color="transparent")
        self.risk_bars.pack(fill="x", padx=15, pady=(0, 12))

    def _init_summary_grid(self) -> None:
        self.summary_items = {}
        labels = [("Total Assets", "total_assets"), ("Quantum Vulnerable", "vulnerable_assets"),
                  ("Quantum Safe", "safe_assets"), ("Compliance", "compliance"),
                  ("Overall Risk", "overall_risk"), ("Migration Difficulty", "migration_difficulty")]
        for i, (text, key) in enumerate(labels):
            r, c = divmod(i, 2)
            card = ctk.CTkFrame(self.summary_grid, fg_color="#1a1a3e", corner_radius=8)
            card.grid(row=r, column=c, sticky="nsew", padx=4, pady=4)
            ctk.CTkLabel(card, text=text, font=FONT_SMALL,
                         text_color="#888888").pack(padx=10, pady=(8, 0))
            val = ctk.CTkLabel(card, text="—", font=("Segoe UI", 16, "bold"),
                               text_color="#e0e0e0")
            val.pack(padx=10, pady=(0, 8))
            self.summary_items[key] = val
        self.summary_grid.grid_columnconfigure((0, 1), weight=1)

    @staticmethod
    def _make_canvas(parent, w, h):
        import tkinter as tk
        return tk.Canvas(parent, width=w, height=h, bg="#151530",
                         highlightthickness=0)

    def _build_inventory_tab(self, parent) -> None:
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True)
        self.inv_grid = ctk.CTkFrame(f, fg_color="transparent")
        self.inv_grid.pack(fill="x", padx=15, pady=10)

    def _build_risk_tab(self, parent) -> None:
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True)
        self.risk_list = ctk.CTkFrame(f, fg_color="transparent")
        self.risk_list.pack(fill="x", padx=15, pady=10)

    def _build_recs_tab(self, parent) -> None:
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True)
        self.recs_list = ctk.CTkFrame(f, fg_color="transparent")
        self.recs_list.pack(fill="x", padx=15, pady=10)

    def _build_roadmap_tab(self, parent) -> None:
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True)
        self.roadmap_list = ctk.CTkFrame(f, fg_color="transparent")
        self.roadmap_list.pack(fill="x", padx=15, pady=10)

    # ── Calculation trace (debug / transparency) ─────────────
    def _build_trace_tab(self, parent) -> None:
        """Read-only panel showing exactly which inputs produced a result.

        Renders the actual working inventory (the same object handed to
        :class:`EnterpriseAssessor`) and the real engine outputs. Nothing here
        is hardcoded or derived from anything other than the current state.
        """
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True)

        ctk.CTkLabel(
            f, text="🧮 Calculation Trace",
            font=FONT_BOLD, text_color="#00d2ff").pack(
            anchor="w", padx=15, pady=(10, 2))
        ctk.CTkLabel(
            f, text="Shows the live inputs and the engine's real math, "
                    "proving results follow the selected inventory.",
            font=FONT_SMALL, text_color="#888888").pack(
            anchor="w", padx=15, pady=(0, 8))

        info = ctk.CTkFrame(f, fg_color="#151530", corner_radius=12)
        info.pack(fill="x", padx=15, pady=4)
        self.trace_status = ctk.CTkLabel(
            info, text="Run ANALYZE to populate the trace.",
            font=FONT_SMALL, text_color="#ffa500",
            justify="left", anchor="w", wraplength=720)
        self.trace_status.pack(fill="x", padx=15, pady=10)

        formula_card = ctk.CTkFrame(f, fg_color="#151530", corner_radius=12)
        formula_card.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(formula_card, text="Readiness formula",
                     font=FONT_BOLD).pack(anchor="w", padx=15, pady=(10, 2))
        self.trace_formula = ctk.CTkLabel(
            formula_card,
            text="readiness = Σ(weight × count) / Σ(count) × 100",
            font=("Consolas", 12), text_color="#e0e0e0",
            justify="left", anchor="w")
        self.trace_formula.pack(anchor="w", padx=15, pady=(0, 10))

        inputs_card = ctk.CTkFrame(f, fg_color="#151530", corner_radius=12)
        inputs_card.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(inputs_card, text="Live input inventory",
                     font=FONT_BOLD).pack(anchor="w", padx=15, pady=(10, 2))
        self.trace_inventory = ctk.CTkFrame(inputs_card, fg_color="transparent")
        self.trace_inventory.pack(fill="x", padx=15, pady=(0, 10))

        weights_card = ctk.CTkFrame(f, fg_color="#151530", corner_radius=12)
        weights_card.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(weights_card, text="Risk weights used by the scorer",
                     font=FONT_BOLD).pack(anchor="w", padx=15, pady=(10, 2))
        self.trace_weights = ctk.CTkFrame(weights_card, fg_color="transparent")
        self.trace_weights.pack(fill="x", padx=15, pady=(0, 10))

        counts_card = ctk.CTkFrame(f, fg_color="#151530", corner_radius=12)
        counts_card.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(counts_card, text="Risk counts as scored",
                     font=FONT_BOLD).pack(anchor="w", padx=15, pady=(10, 2))
        self.trace_counts = ctk.CTkFrame(counts_card, fg_color="transparent")
        self.trace_counts.pack(fill="x", padx=15, pady=(0, 10))

    def _render_trace(self, result) -> None:
        def clear(container: ctk.CTkFrame) -> None:
            for w in container.winfo_children():
                w.destroy()

        # Status line: which inventory drove this result.
        selected = self.organization_menu.get()
        scored = self._scored_inventory if hasattr(self, "_scored_inventory") \
            else self.inventory
        if self._loaded_org is not None and self._loaded_org != selected:
            note = (f"⚠ Computed from '{self._loaded_org}' inventory while the "
                    f"dropdown shows '{selected}'. Press Load / ANALYZE to "
                    f"re-score the selection.")
        else:
            note = (f"Computed live from the working inventory"
                    + (f" ({selected})." if self._loaded_org is not None else " (custom)."))
        algo, cat, count = self._pending_selection()
        if self._pending_dirty:
            note += (f"\n🔹 Includes quick-add selection: {count}× "
                     f"{algo} ({cat}) — scored on a working copy; not yet "
                     f"added permanently.")
        self.trace_status.configure(text=note, text_color="#4caf50"
                                    if self._loaded_org == selected
                                    else "#ffa500")

        # Live input inventory (the exact object handed to the assessor).
        clear(self.trace_inventory)
        for a in scored.to_dict():
            kb = ALGORITHM_KB.get(a["algorithm"])
            risk = kb["risk"].value if kb else RiskLevel.MEDIUM.value
            row = ctk.CTkFrame(self.trace_inventory, fg_color="#1a1a3e",
                               corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{a['name']} × {a['count']}",
                         font=("Consolas", 12), text_color="#e0e0e0"
                         ).pack(side="left", padx=8, pady=4)
            ctk.CTkLabel(row, text=risk, font=("Consolas", 12), width=80,
                         text_color=RISK_COLORS.get(risk, "#e0e0e0")
                         ).pack(side="right", padx=8, pady=4)

        # Weights table.
        clear(self.trace_weights)
        for i, (level, weight) in enumerate(RISK_WEIGHTS.items()):
            row = ctk.CTkFrame(self.trace_weights, fg_color="transparent")
            row.grid(row=i // 5, column=i % 5, padx=6, pady=2)
            ctk.CTkLabel(row, text=f"{level.value}",
                         font=FONT_SMALL,
                         text_color=RISK_COLORS.get(level.value,
                                                    "#e0e0e0")).pack(side="left")
            ctk.CTkLabel(row, text=f"{weight:g}", font=FONT_SMALL,
                         text_color="#00d2ff").pack(side="left", padx=4)

        # Granular counts + recomputed score (must equal result["readiness"]).
        clear(self.trace_counts)
        counts = result["risk_counts"]
        for level, n in counts.items():
            row = ctk.CTkFrame(self.trace_counts, fg_color="#1a1a3e",
                               corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{level}", font=("Consolas", 12), width=90,
                         text_color=RISK_COLORS.get(level, "#e0e0e0")
                         ).pack(side="left", padx=8, pady=4)
            ctk.CTkLabel(row, text=str(n), font=("Consolas", 12), width=60,
                         text_color="#e0e0e0").pack(side="left", padx=8, pady=4)
            ctk.CTkLabel(row, text=f"× {RISK_WEIGHTS.get(level, 0):g}",
                         font=("Consolas", 12), text_color="#888888"
                         ).pack(side="right", padx=8, pady=4)

        total = sum(counts.values())
        weighted = sum(RISK_WEIGHTS.get(r, 0) * n
                       for r, n in counts.items()) / max(total, 1) * 100
        self.trace_formula.configure(
            text=f"Σ(weight×count) / Σ(count)×100 → {weighted:.1f}%  "
                 f"(gauge shows this; engine rounds to {result['readiness']}% "
                 f"for the grade band)")

    # ── Analysis ─────────────────────────────────────────────
    def _run_analysis(self) -> None:
        self._ensure_selected_profile()
        self._scored_inventory = self._working_inventory()
        result = EnterpriseAssessor(self._scored_inventory).assess()
        result["organization"] = self.organization_menu.get()
        self.result = result
        self.root.after(0, lambda: self._render(result))

    def _render(self, result) -> None:
        self._render_gauge(result)
        self._render_summary(result["summary"])
        self._render_risk_bars(result["risk_counts"])
        self._render_inventory(result["assets"])
        self._render_risk_list(result["findings"])
        self._render_recs(result["recommendations"])
        self._render_roadmap(result["roadmap"])
        self._render_trace(result)

    def _render_gauge(self, result) -> None:
        score = result["readiness"]
        color = result["grade_color"]
        counts = result["risk_counts"]
        total = sum(counts.values())
        precise = sum(RISK_WEIGHTS.get(r, 0) * n for r, n in counts.items()) \
            / max(total, 1) * 100
        self.gauge_label.configure(text=f"{precise:.1f}%", text_color=color)
        self.grade_label.configure(text=result["grade_label"],
                                   text_color=color)
        self.gauge_canvas.delete("all")
        c = self.gauge_canvas
        x, y, r = 100, 100, 80
        c.create_oval(x - r, y - r, x + r, y + r, outline="#2a2a4e",
                      width=14)
        c.create_arc(x - r, y - r, x + r, y + r, start=90,
                     extent=-(score * 3.6), style="arc", outline=color,
                     width=14)
        c.create_oval(x - 2, y - 2, x + 2, y + 2, outline=color)

    def _render_summary(self, summary) -> None:
        for key, widget in self.summary_items.items():
            val = summary.get(key, "—")
            color = "#e0e0e0"
            if key in ("overall_risk",) and val == "High":
                color = "#f44336"
            elif key in ("overall_risk",):
                color = "#4caf50"
            widget.configure(text=str(val), text_color=color)

    def _render_risk_bars(self, counts) -> None:
        for w in self.risk_bars.winfo_children():
            w.destroy()
        total = sum(counts.values()) or 1
        for level in (RiskLevel.CRITICAL.value, RiskLevel.HIGH.value,
                      RiskLevel.MEDIUM.value, RiskLevel.LOW.value,
                      RiskLevel.SAFE.value):
            n = counts.get(level, 0)
            row = ctk.CTkFrame(self.risk_bars, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{level}", font=FONT_SMALL, width=80,
                         text_color=RISK_COLORS[level]).pack(side="left")
            pb = ctk.CTkProgressBar(row, height=12, corner_radius=6,
                                    fg_color="#2a2a4e",
                                    progress_color=RISK_COLORS[level])
            pb.pack(side="left", fill="x", expand=True, padx=8)
            pb.set(n / total)
            ctk.CTkLabel(row, text=str(n), font=FONT_SMALL, width=50,
                         text_color="#e0e0e0").pack(side="right")

    def _render_inventory(self, assets) -> None:
        for w in self.inv_grid.winfo_children():
            w.destroy()
        if not assets:
            ctk.CTkLabel(self.inv_grid, text="No assets yet. Add assets on the "
                                             "left or load a preset.",
                         text_color="#888888").pack(padx=10, pady=10)
            return
        for i, a in enumerate(assets):
            card = ctk.CTkFrame(self.inv_grid, fg_color="#1a1a3e",
                                corner_radius=8)
            card.grid(row=i // 3, column=i % 3, sticky="nsew", padx=5, pady=5)
            ctk.CTkLabel(card, text=f"🔑 {a['name']}",
                         font=("Segoe UI", 12, "bold"),
                         text_color="#00d2ff").pack(anchor="w", padx=10,
                                                    pady=(8, 0))
            ctk.CTkLabel(card, text=f"Category: {a['category']}",
                         font=FONT_SMALL, text_color="#888888").pack(
                anchor="w", padx=10)
            ctk.CTkLabel(card, text=f"Key size: {a['key_size'] or 'n/a'} bits",
                         font=FONT_SMALL, text_color="#888888").pack(
                anchor="w", padx=10)
            ctk.CTkLabel(card, text=f"Count: {a['count']}",
                         font=FONT_SMALL, text_color="#888888").pack(
                anchor="w", padx=10, pady=(0, 8))

    def _render_risk_list(self, findings) -> None:
        for w in self.risk_list.winfo_children():
            w.destroy()
        for f in findings:
            color = RISK_COLORS.get(f["risk"], "#888888")
            card = ctk.CTkFrame(self.risk_list, fg_color="#1a1a3e",
                                corner_radius=8)
            card.pack(fill="x", pady=3, padx=3)
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=12, pady=6)
            badge = ctk.CTkLabel(inner, text=f" {f['risk']} ",
                                 font=("Segoe UI", 10, "bold"),
                                 fg_color=color, text_color="#000",
                                 corner_radius=4)
            badge.pack(side="left", padx=(0, 10))
            ctk.CTkLabel(inner, text=f"{f['name']}",
                         font=("Segoe UI", 12, "bold"),
                         text_color="#e0e0e0").pack(side="left")
            ctk.CTkLabel(inner, text=f"(×{f['count']})",
                         font=FONT_SMALL, text_color="#888888").pack(
                side="left", padx=6)
            ctk.CTkLabel(card, text=f"Reason: {f['reason']}",
                         font=FONT_SMALL, text_color="#aaaaaa").pack(
                anchor="w", padx=12)
            ctk.CTkLabel(card, text=f"Fix: {f['replacement']}",
                         font=FONT_SMALL, text_color="#4caf50").pack(
                anchor="w", padx=12, pady=(0, 6))

    def _render_recs(self, recs) -> None:
        for w in self.recs_list.winfo_children():
            w.destroy()
        if not recs:
            ctk.CTkLabel(self.recs_list,
                         text="🎉 No vulnerable assets found!",
                         font=FONT_BOLD, text_color="#4caf50").pack(
                padx=10, pady=10)
            return
        for r in recs:
            card = ctk.CTkFrame(self.recs_list, fg_color="#1a1a3e",
                                corner_radius=8)
            card.pack(fill="x", pady=4, padx=3)
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=12, pady=6)
            ctk.CTkLabel(inner, text=f"{r['detected']}", font=FONT_SMALL,
                         text_color="#f44336").pack(side="left")
            ctk.CTkLabel(inner, text="  ↓  ", font=("Segoe UI", 14),
                         text_color="#00d2ff").pack(side="left")
            ctk.CTkLabel(inner, text=f"{r['recommended']}",
                         font=("Segoe UI", 12, "bold"),
                         text_color="#4caf50").pack(side="left")
            priority = ctk.CTkLabel(inner, text=f" {r['priority']} ",
                                    font=("Segoe UI", 9, "bold"),
                                    fg_color=RISK_COLORS.get(r["priority"],
                                                             "#888888"),
                                    text_color="#000", corner_radius=4)
            priority.pack(side="right")
            ctk.CTkLabel(card, text=f"{r['nist']} · {r['reason']}",
                         font=FONT_SMALL, text_color="#aaaaaa").pack(
                anchor="w", padx=12, pady=(0, 6))

    def _render_roadmap(self, roadmap) -> None:
        for w in self.roadmap_list.winfo_children():
            w.destroy()
        for p in roadmap:
            card = ctk.CTkFrame(self.roadmap_list, fg_color="#151530",
                                corner_radius=8)
            card.pack(fill="x", pady=4, padx=3)
            ctk.CTkLabel(card, text=p["name"], font=("Segoe UI", 13, "bold"),
                         text_color="#00d2ff").pack(anchor="w", padx=12,
                                                    pady=(8, 0))
            ctk.CTkLabel(card, text=p["desc"], font=FONT_SMALL,
                         text_color="#aaaaaa").pack(anchor="w", padx=12)
            meta = ctk.CTkFrame(card, fg_color="transparent")
            meta.pack(fill="x", padx=12, pady=(4, 8))
            ctk.CTkLabel(meta, text=f"⏱ {p['time']}",
                         font=FONT_SMALL, text_color="#4dabf7").pack(
                side="left", padx=(0, 15))
            ctk.CTkLabel(meta, text=f"⚠ Risk: {p['risk']}",
                         font=FONT_SMALL,
                         text_color=RISK_COLORS.get(p["risk"], "#888888")
                         ).pack(side="left", padx=(0, 15))
            ctk.CTkLabel(meta, text=f"🛑 {p['downtime']}",
                         font=FONT_SMALL, text_color="#888888").pack(
                side="left")

    # ── Crypto Playground tab ────────────────────────────────
    def _build_demo_tab(self, parent) -> None:
        f = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        f.pack(fill="both", expand=True)

        ctk.CTkLabel(f, text="🔬 Crypto Playground",
                     font=FONT_BOLD, text_color="#00d2ff").pack(
            anchor="w", padx=20, pady=(14, 2))
        ctk.CTkLabel(f, text="Type any text, pick one or more algorithms, "
                             "and see what each one does to your text.",
                     font=FONT_SMALL, text_color="#888888",
                     wraplength=800, justify="left").pack(anchor="w",
                                                          padx=20)

        # Text input
        ctk.CTkLabel(f, text="Your text:", font=FONT_SMALL,
                     text_color="#888888").pack(anchor="w", padx=20, pady=(10, 3))
        self.demo_text = ctk.CTkTextbox(f, font=FONT_MONO, height=80,
                                        wrap="word")
        self.demo_text.pack(fill="x", padx=20)
        self.demo_text.insert("1.0", "Hello, post-quantum world!")

        # Algorithm selection
        ctrl = ctk.CTkFrame(f, fg_color="transparent")
        ctrl.pack(fill="x", padx=20, pady=(12, 4))
        ctk.CTkLabel(ctrl, text="Select algorithms (you can pick many):",
                     font=FONT_SMALL, text_color="#888888").pack(side="left")
        ctk.CTkButton(ctrl, text="All", font=FONT_SMALL, width=50, height=24,
                      command=self._demo_select_all).pack(side="right", padx=3)
        ctk.CTkButton(ctrl, text="None", font=FONT_SMALL, width=50, height=24,
                      command=self._demo_select_none).pack(side="right", padx=3)

        # Checkbox grid grouped by category
        self.demo_checkboxes = {}
        grid = ctk.CTkFrame(f, fg_color="#151530", corner_radius=10)
        grid.pack(fill="x", padx=20, pady=6)
        group_col = 0
        for group in GROUPS:
            panel = ctk.CTkFrame(grid, fg_color="transparent")
            panel.grid(row=0, column=group_col, sticky="n",
                       padx=12, pady=8)
            kind = DEMO_ALGORITHMS[group[0]]
            group_name = {
                "hash": "Hashing (integrity)",
                "symmetric": "Symmetric Encryption",
                "kem": "ML-KEM Key Exchange",
                "sign": "Digital Signatures",
                "encrypt": "RSA Public-Key Encryption",
            }.get(kind, kind)
            ctk.CTkLabel(panel, text=group_name, font=("Segoe UI", 10, "bold"),
                         text_color="#00d2ff").pack(anchor="w", pady=(0, 3))
            for alg in group:
                var = ctk.BooleanVar(value=(alg in ("ML-KEM-768", "ML-DSA-65")))
                cb = ctk.CTkCheckBox(panel, text=alg, variable=var,
                                     font=("Segoe UI", 11), height=22)
                cb.pack(anchor="w")
                self.demo_checkboxes[alg] = var
            group_col += 1

        # Run button + output
        ctk.CTkButton(f, text="▶ Demonstrate Selected Algorithms", font=FONT_BOLD,
                      height=36,
                      command=lambda: threading.Thread(
                          target=self._run_demo, daemon=True).start()
                      ).pack(padx=20, pady=(8, 6))

        # ── Cascade (layered) mode ────────────────────────────
        cascade_card = ctk.CTkFrame(f, fg_color="#151530", corner_radius=10)
        cascade_card.pack(fill="x", padx=20, pady=(4, 6))
        ctk.CTkLabel(cascade_card, text="🔗 Cascade / Layered Mode "
                                        "(onion-style)",
                     font=("Segoe UI", 13, "bold"),
                     text_color="#00d2ff").pack(anchor="w", padx=14,
                                                pady=(10, 2))
        ctk.CTkLabel(cascade_card,
                     text="Chain the selected algorithms: each one encrypts "
                          "the previous output (like Tor's onion routing). "
                          "Decryption unwraps them in reverse order.\n"
                          "Note: only AES / ChaCha20 / RSA / ML-KEM can be "
                          "chained (hashes & signatures are one-way and are "
                          "skipped). Reminder: a chain is only as strong as "
                          "its strongest layer.",
                     font=("Segoe UI", 10), text_color="#aaaaaa",
                     wraplength=800, justify="left").pack(anchor="w",
                                                          padx=14)
        ctrl2 = ctk.CTkFrame(cascade_card, fg_color="transparent")
        ctrl2.pack(fill="x", padx=14, pady=(6, 10))
        ctk.CTkButton(ctrl2, text="🔒 Encrypt Chain", font=FONT,
                      fg_color="#0d47a1", hover_color="#1565c0",
                      command=lambda: threading.Thread(
                          target=self._cascade_encrypt, daemon=True).start()
                      ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(ctrl2, text="🔓 Decrypt Chain", font=FONT,
                      fg_color="#2e7d32", hover_color="#388e3c",
                      command=lambda: threading.Thread(
                          target=self._cascade_decrypt, daemon=True).start()
                      ).pack(side="left", padx=5)
        ctk.CTkLabel(ctrl2, text="(only reversible algorithms are used)",
                     font=("Segoe UI", 10), text_color="#888888").pack(
            side="left", padx=(12, 0))

        self.demo_out = ctk.CTkTextbox(f, font=FONT_MONO, height=300, wrap="word")
        self.demo_out.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        self.demo_out.insert("1.0", "Pick algorithms above, then press "
                                    "Demonstrate, Encrypt Chain, or Decrypt "
                                    "Chain. Output appears here.\n")
        self.cascade_session = None

    def _demo_select_all(self) -> None:
        for var in self.demo_checkboxes.values():
            var.set(True)

    def _demo_select_none(self) -> None:
        for var in self.demo_checkboxes.values():
            var.set(False)

    def _run_demo(self) -> None:
        text = self.demo_text.get("1.0", "end-1c").strip()
        selected = [alg for alg, var in self.demo_checkboxes.items() if var.get()]
        if not selected:
            self.demo_out.delete("1.0", "end")
            self.demo_out.insert("1.0", "⚠ Select at least one algorithm.\n")
            return
        self.demo_out.delete("1.0", "end")
        self.demo_out.insert("end",
                             f"Applying {len(selected)} algorithm(s) to: "
                             f"\"{text}\"\n{'─' * 60}\n\n")
        output = run_multi(selected, text)
        self.demo_out.insert("end", output)

    def _selected_reversible(self) -> List[str]:
        """Return selected algorithms that can actually be chained."""
        return [alg for alg in REVERSIBLE_ALGORITHMS
                if self.demo_checkboxes.get(alg, ctk.BooleanVar()).get()]

    def _cascade_encrypt(self) -> None:
        text = self.demo_text.get("1.0", "end-1c").strip()
        chain = self._selected_reversible()
        if not chain:
            self.demo_out.delete("1.0", "end")
            self.demo_out.insert(
                "1.0", "⚠ Chain needs at least one reversible algorithm "
                       "(AES / ChaCha20 / RSA / ML-KEM). Hashes and "
                       "signatures are one-way and cannot be chained.\n")
            return
        skipped = [alg for alg, var in self.demo_checkboxes.items()
                   if var.get() and alg not in REVERSIBLE_ALGORITHMS]
        try:
            stages, contexts = cascade_encrypt(chain, text.encode())
        except ValueError as e:
            self.demo_out.delete("1.0", "end")
            self.demo_out.insert("1.0", f"⚠ {e}\n")
            return

        self.cascade_session = {"names": chain, "stages": stages,
                                "contexts": contexts}

        lines = [
            f"🔗 ENCRYPT CHAIN  ({len(chain)} layers)  on: \"{text}\"",
            "─" * 60,
        ]
        if skipped:
            lines.append(f"(skipped one-way: {', '.join(skipped)})")
        lines.append(f"Layer 0 (original): \"{text}\" ({len(text.encode())} bytes)")
        current = text.encode()
        for i, (algo, stage) in enumerate(zip(chain, stages)):
            lines.append(
                f"Layer {i + 1} ({algo}): encrypt {len(current)}B "
                f"-> {len(stage)}B  {stage[:16].hex()}...")
            current = stage
        lines.append("")
        lines.append("Session stored. Press 🔓 Decrypt Chain to unwrap "
                     "in reverse order.")
        lines.append("Reminder: a chain is only as strong as its "
                     "strongest layer.")
        self.demo_out.delete("1.0", "end")
        self.demo_out.insert("1.0", "\n".join(lines))

    def _cascade_decrypt(self) -> None:
        if not self.cascade_session:
            self.demo_out.delete("1.0", "end")
            self.demo_out.insert("1.0", "⚠ Nothing to decrypt. Press "
                                        "🔒 Encrypt Chain first.\n")
            return
        names = self.cascade_session["names"]
        stages = self.cascade_session["stages"]
        contexts = self.cascade_session["contexts"]
        try:
            revealed = cascade_decrypt(names, stages, contexts)
            checks = cascade_verify(names, stages, revealed)
        except Exception as e:
            self.demo_out.delete("1.0", "end")
            self.demo_out.insert("1.0", f"⚠ Decrypt failed: {e}\n")
            return

        lines = ["🔓 DECRYPT CHAIN  (reverse order)",
                 "─" * 60]
        for i in range(len(names) - 1, -1, -1):
            before = revealed[i + 1]  # value right after decrypting layer i+1
            src = stages[i]
            label = "original text" if i == 0 else f"intermediate (layer {i})"
            try:
                preview = f"\"{before.decode()}\"" if i == 0 else \
                    f"{len(before)}B {before[:16].hex()}..."
            except UnicodeDecodeError:
                preview = f"{len(before)}B {before[:16].hex()}..."
            lines.append(
                f"  {names[i]:<14} decrypts {len(src)}B -> {preview}")
        lines.append("")
        lines.extend(checks)
        lines.append("")
        lines.append("Chain unwrapped back to the original text.")
        self.demo_out.delete("1.0", "end")
        self.demo_out.insert("1.0", "\n".join(lines))

    # ── PDF report ───────────────────────────────────────────
    def _export_report(self) -> None:
        if not hasattr(self, "result"):
            self.root.after(0, lambda: self._show_popup(
                "⚠ Run ANALYZE first", "Generate a report after analysis.",
                "#ffa500"))
            return
        try:
            path = self._build_pdf(self.result)
            self.root.after(0, lambda: self._show_popup(
                "✅ Report Generated", f"Saved to:\n{path}", "#4caf50"))
        except Exception as e:
            err = str(e)
            self.root.after(0, lambda: self._show_popup(
                "❌ Report Failed", err, "#f44336"))

    @staticmethod
    def _pdf_safe(text) -> str:
        """Strip unicode that the built-in Helvetica (latin-1) font rejects."""
        mapping = {"\u2014": "-", "\u2013": "-", "\u2192": "->", "\u00d7": "x",
                   "\u2713": "OK", "\u2705": "OK", "\u26a0": "!", "\u23f1": "",
                   "\u23ed": "", "\u2193": "|", "\u21a0": "->", "\u2026": "..."}
        out = []
        for ch in str(text):
            if ch in mapping:
                out.append(mapping[ch])
            elif ord(ch) < 256:
                out.append(ch)
            else:
                out.append("?")
        return "".join(out)

    @staticmethod
    def _chart_risk_pie(counts: dict, path: str) -> None:
        """Pie chart of risk-level distribution -> temp PNG."""
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = [k for k in ("Critical", "High", "Medium", "Low", "Safe")
                  if counts.get(k, 0) > 0]
        values = [counts.get(k, 0) for k in labels]
        if not values:
            labels, values, colors = ["No data"], [1], ["#888888"]
        else:
            colors = [RISK_COLORS.get(k, "#888888") for k in labels]
        fig, ax = plt.subplots(figsize=(6.6, 4.2))
        wedges, _, autotexts = ax.pie(
            values, labels=labels, autopct="%1.1f%%", startangle=90,
            colors=colors, wedgeprops={"edgecolor": "white", "linewidth": 1.2},
            textprops={"fontsize": 10, "color": "white"})
        for at in autotexts:
            at.set_fontsize(9)
        ax.set_title("Risk Distribution of Crypto Assets", fontsize=13, pad=14)
        ax.axis("equal")
        fig.tight_layout()
        fig.savefig(path, dpi=150, facecolor="white")
        plt.close(fig)

    @staticmethod
    def _chart_readiness(score: float, color: str, path: str) -> None:
        """Horizontal readiness score bar -> temp PNG."""
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6.6, 1.5))
        ax.barh([0], [100], color="#e9e9f2", height=0.45)
        ax.barh([0], [score], color=color, height=0.45)
        ax.text(score, 0, f"  {score:.0f}%", va="center", ha="left",
                fontsize=13, fontweight="bold", color=color)
        ax.set_xlim(0, 118)
        ax.set_ylim(-0.8, 0.8)
        ax.set_yticks([])
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.tick_params(labelsize=9)
        ax.set_title("Overall PQC Readiness Score", fontsize=12, pad=8)
        ax.spines[["top", "right", "left"]].set_visible(False)
        fig.tight_layout()
        fig.savefig(path, dpi=150, facecolor="white")
        plt.close(fig)

    @staticmethod
    def _chart_categories(assets: list, path: str) -> None:
        """Bar chart of asset counts grouped by category -> temp PNG."""
        import matplotlib
        import matplotlib.pyplot as plt
        cats: dict = {}
        for a in assets:
            cats[a["category"]] = cats.get(a["category"], 0) + a["count"]
        labels = list(cats.keys())
        values = list(cats.values())
        palette = ["#4dabf7", "#69db7c", "#ffa94d", "#9775fa", "#ff6b6b",
                   "#74c0fc", "#63e6be"]
        fig, ax = plt.subplots(figsize=(6.6, 3.6))
        colors = palette[:len(labels)]
        bars = ax.bar(labels, values, color=colors,
                      edgecolor="white", linewidth=1.2)
        for b, v in zip(bars, values):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.3, str(v),
                    ha="center", va="bottom", fontsize=9, fontweight="bold")
        ax.set_title("Crypto Assets by Category", fontsize=12, pad=10)
        ax.set_ylabel("Asset count", fontsize=9)
        ax.set_xlim(-0.8, len(labels) - 0.2)
        ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout()
        fig.savefig(path, dpi=150, facecolor="white")
        plt.close(fig)

    @staticmethod
    def _build_pdf(result) -> str:
        from fpdf import FPDF
        from src.enterprise_assessment import ALGORITHM_KB

        tmp = tempfile.mkdtemp(prefix="pqc_report_")
        chart_pie = os.path.join(tmp, "risk_pie.png")
        chart_readiness = os.path.join(tmp, "readiness.png")
        chart_cats = os.path.join(tmp, "categories.png")
        try:
            AssessmentApp._chart_risk_pie(result["risk_counts"], chart_pie)
            AssessmentApp._chart_readiness(
                result["readiness"], RISK_COLORS.get(result["grade_label"],
                                                     "#4caf50"),
                chart_readiness)
            AssessmentApp._chart_categories(result["assets"], chart_cats)

            class ReportPDF(FPDF):
                def header(self):
                    if self.page_no() <= 1:
                        return
                    self.set_font("Helvetica", "B", 8)
                    self.set_text_color(30, 40, 70)
                    self.cell(0, 5, "ENTERPRISE PQC ASSESSMENT",
                              new_x="LMARGIN", new_y="NEXT")
                    self.set_draw_color(0, 100, 200)
                    self.set_line_width(0.7)
                    self.line(10, 14, 200, 14)
                    self.ln(7)

                def footer(self):
                    self.set_y(-12)
                    self.set_font("Helvetica", "I", 7)
                    self.set_text_color(150, 150, 160)
                    self.cell(0, 8, AssessmentApp._pdf_safe(
                        f"Confidential - PQC Readiness Assessment | Page "
                        f"{self.page_no()}"), align="C")

            pdf = ReportPDF()
            pdf.set_auto_page_break(auto=True, margin=16)

            # ── Cover page ──────────────────────────────────────────
            pdf.add_page()
            pdf.set_fill_color(10, 12, 32)
            pdf.rect(0, 0, 210, 297, "F")
            pdf.set_fill_color(0, 100, 200)
            pdf.rect(0, 0, 210, 6, "F")
            pdf.set_fill_color(0, 180, 255)
            pdf.rect(0, 6, 210, 2, "F")
            pdf.set_y(70)
            pdf.set_font("Helvetica", "B", 15)
            pdf.set_text_color(0, 180, 255)
            pdf.cell(0, 8, "ENTERPRISE SECURITY BRIEF", align="C",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.ln(6)
            pdf.set_font("Helvetica", "B", 28)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 14, "Enterprise PQC Assessment", align="C",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 13)
            pdf.set_text_color(190, 200, 220)
            pdf.cell(0, 8, "Post-Quantum Readiness Executive Report",
                     align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 8, AssessmentApp._pdf_safe(
                f"Organization: {result.get('organization', 'Custom inventory')}"),
                     align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(18)

            score = result["readiness"]
            grade = result["grade_label"]
            grade_color = RISK_COLORS.get(grade, "#4caf50")
            pdf.set_fill_color(*[int(grade_color[i:i + 2], 16)
                                 for i in (1, 3, 5)])
            pdf.rect(55, pdf.get_y(), 100, 30, "F")
            pdf.set_font("Helvetica", "B", 22)
            pdf.set_text_color(255, 255, 255)
            pdf.set_xy(55, pdf.get_y() + 5)
            pdf.cell(100, 10, AssessmentApp._pdf_safe(
                     f"Readiness {score:.0f}%  ({grade})"), align="C",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.ln(14)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(180, 185, 200)
            pdf.cell(0, 7, result["generated_at"], align="C",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 7, AssessmentApp._pdf_safe(
                f"{result['summary']['total_assets']} assets assessed | "
                f"{result['summary']['vulnerable_assets']} quantum-vulnerable"),
                align="C", new_x="LMARGIN", new_y="NEXT")

            def section(title):
                pdf.add_page()
                pdf.set_y(22)
                pdf.set_fill_color(0, 100, 200)
                pdf.rect(0, pdf.get_y(), 210, 18, "F")
                pdf.set_font("Helvetica", "B", 13)
                pdf.set_text_color(255, 255, 255)
                pdf.set_xy(10, pdf.get_y() + 5)
                pdf.cell(0, 8, AssessmentApp._pdf_safe(title))
                pdf.set_y(pdf.get_y() + 18)
                pdf.ln(3)

            def table(headers, rows, widths, header_fill=(0, 100, 200),
                      risk_col=None, col_align=None):
                pdf.set_font("Helvetica", "B", 8.5)
                pdf.set_text_color(255, 255, 255)
                pdf.set_fill_color(*header_fill)
                for i, (h, w) in enumerate(zip(headers, widths)):
                    pdf.cell(w, 7, AssessmentApp._pdf_safe(h), border=1,
                             fill=True, align="C")
                pdf.ln()
                pdf.set_font("Helvetica", "", 8.5)
                for ri, row in enumerate(rows):
                    fill = (243, 246, 252) if ri % 2 == 0 else (255, 255, 255)
                    for ci, (val, w) in enumerate(zip(row, widths)):
                        align = "C" if ci == 0 else "L"
                        if col_align:
                            align = col_align[ci]
                        if risk_col is not None and ci == risk_col:
                            c = RISK_COLORS.get(str(val), "#888888")
                            rgb = [int(c[i:i + 2], 16) for i in (1, 3, 5)]
                            pdf.set_fill_color(*rgb)
                            pdf.set_text_color(255, 255, 255)
                        else:
                            pdf.set_fill_color(*fill)
                            pdf.set_text_color(30, 30, 40)
                        pdf.cell(w, 6.4, AssessmentApp._pdf_safe(str(val)),
                                 border=1, fill=True, align=align)
                    pdf.ln()

            # ── 1. Executive summary ───────────────────────────────
            section("1. Executive Summary")
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(60, 60, 75)
            pdf.multi_cell(0, 5.5, AssessmentApp._pdf_safe(
                "This report assesses the organization's cryptographic "
                "infrastructure and its readiness for post-quantum "
                "cryptography migration. Overall readiness: "
                f"{score:.0f}% ({grade})."))
            pdf.ln(3)
            pdf.image(chart_readiness, x=14, w=182)
            pdf.ln(6)
            s = result["summary"]
            summary_rows = [
                ["Total assets", s["total_assets"], "#4dabf7"],
                ["Quantum vulnerable", s["vulnerable_assets"], "#ff6b6b"],
                ["Quantum safe", s["safe_assets"], "#69db7c"],
                ["Compliance", s["compliance"], "#4dabf7"],
                ["Overall risk", s["overall_risk"], "#ffa94d"],
                ["Migration difficulty", s["migration_difficulty"], "#9775fa"],
            ]
            for label, val, c in summary_rows:
                rgb = [int(c[i:i + 2], 16) for i in (1, 3, 5)]
                pdf.set_fill_color(*rgb)
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(90, 9, AssessmentApp._pdf_safe(label), border=1,
                         fill=True, new_x="RIGHT", new_y="TOP")
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 9, AssessmentApp._pdf_safe(f"  {val}"), border=1,
                         fill=True, new_x="LMARGIN", new_y="NEXT")

            # ── 2. Detected infrastructure ──────────────────────────
            section("2. Detected Infrastructure")
            infra_rows = [[a["category"], a["name"], a["count"],
                           a["key_size"] or "n/a"] for a in result["assets"]]
            table(["Category", "Asset", "Count", "Key size (bits)"],
                  infra_rows, [30, 82, 20, 38], col_align=["L", "L", "C", "C"])
            pdf.ln(4)
            pdf.image(chart_cats, x=14, w=182)

            # ── 3. Risk analysis ────────────────────────────────────
            section("3. Risk Analysis")
            counts = result["risk_counts"]
            pdf.image(chart_pie, x=14, w=182)
            pdf.ln(4)
            risk_rows = []
            for level in ("Critical", "High", "Medium", "Low", "Safe"):
                risk_rows.append([level, counts.get(level, 0)])
            table(["Risk level", "Assets exposed"], risk_rows, [60, 60],
                  header_fill=(40, 45, 70), risk_col=0,
                  col_align=["L", "C"])
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(30, 30, 40)
            pdf.cell(0, 7, "Key findings", new_x="LMARGIN", new_y="NEXT")
            finding_rows = [[f["name"], f["risk"]] for f in result["findings"]]
            table(["Finding", "Risk"], finding_rows, [100, 40],
                  header_fill=(40, 45, 70), risk_col=1, col_align=["L", "C"])
            pdf.ln(2)
            for f in result["findings"]:
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(100, 100, 115)
                pdf.multi_cell(0, 4, AssessmentApp._pdf_safe(
                    f"  {f['name']}: {f['reason']}"),
                    new_x="LMARGIN", new_y="NEXT")

            # ── 4. Migration recommendations ───────────────────────
            section("4. Migration Recommendations")
            rec_rows = [[r["detected"], r["recommended"], r["priority"],
                         r["nist"]] for r in result["recommendations"]]
            table(["Detected", "Recommended", "Priority", "NIST standard"],
                  rec_rows, [45, 45, 30, 50], header_fill=(0, 130, 90),
                  col_align=["L", "L", "C", "L"])

            # ── 5. Migration roadmap ───────────────────────────────
            section("5. Migration Roadmap")
            step_rows = [[p["name"], p["time"], p["risk"], p["downtime"]]
                         for p in result["roadmap"]]
            table(["Phase", "Time", "Risk", "Downtime"], step_rows,
                  [56, 40, 40, 34], header_fill=(130, 90, 0),
                  col_align=["L", "C", "C", "C"])
            pdf.ln(4)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(80, 80, 95)
            for p in result["roadmap"]:
                pdf.multi_cell(0, 4.5, AssessmentApp._pdf_safe(
                    f"  {p['name']}: {p['desc']}"),
                    new_x="LMARGIN", new_y="NEXT")
                pdf.ln(1)

            # ── 6. Conclusions ─────────────────────────────────────
            section("6. Conclusions")
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(60, 60, 75)
            pdf.multi_cell(0, 5.5, AssessmentApp._pdf_safe(
                f"With a readiness score of {score:.0f}%, the organization "
                f"should immediately prioritize replacing "
                f"{s['vulnerable_assets']} quantum-vulnerable assets. "
                f"Follow the recommended roadmap and re-assess after each "
                f"migration phase."))
            pdf.ln(4)
            pdf.set_fill_color(40, 45, 70)
            pdf.rect(10, pdf.get_y(), 190, 22, "F")
            pdf.set_xy(12, pdf.get_y() + 4)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(255, 200, 60)
            pdf.multi_cell(186, 5.5, AssessmentApp._pdf_safe(
                "WARNING: 'Harvest Now, Decrypt Later' is a real, active "
                "threat. Encrypted traffic captured today can be decrypted "
                "by a quantum adversary tomorrow. Migrate now."))
            pdf.ln(8)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(140, 140, 155)
            pdf.multi_cell(0, 4.5, AssessmentApp._pdf_safe(
                "Generated by the Enterprise PQC Assessment tool. "
                "Recommendations follow NIST SP 800-208 / FIPS 203-205 "
                "transition guidance."))

            out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "reports")
            os.makedirs(out_dir, exist_ok=True)
            organization = result.get("organization", "Custom inventory")
            safe_org = "_".join("".join(ch if ch.isalnum() else "_"
                                         for ch in organization).split())
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(out_dir, f"Enterprise_PQC_Assessment_"
                                         f"{safe_org}_{timestamp}.pdf")
            pdf.output(path)
            return path
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ── Utilities ────────────────────────────────────────────
    def _show_popup(self, title, body, color="#00d2ff") -> None:
        win = ctk.CTkToplevel(self.root)
        win.title(title)
        win.geometry("480x160")
        win.transient(self.root)
        win.grab_set()
        ctk.CTkLabel(win, text=title, font=("Segoe UI", 15, "bold"),
                     text_color=color).pack(pady=(14, 4))
        ctk.CTkLabel(win, text=body, font=FONT_SMALL,
                     text_color="#cccccc", wraplength=430).pack(pady=4)
        ctk.CTkButton(win, text="OK", command=win.destroy).pack(pady=8)

    def _toggle_theme(self) -> None:
        if ctk.get_appearance_mode() == "Dark":
            ctk.set_appearance_mode("Light")
            self.theme_btn.configure(text="🌙 Dark")
        else:
            ctk.set_appearance_mode("Dark")
            self.theme_btn.configure(text="☀ Light")

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    AssessmentApp().run()
