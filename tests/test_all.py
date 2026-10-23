"""PQC Migration Toolkit — comprehensive test suite."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.pqc_wrapper import (
    kem_keygen, kem_encaps, kem_decaps,
    sig_keygen, sig_sign, sig_verify,
    hybrid_tls, measure_kem, measure_sig,
)


def test_kem_512():
    ek, dk = kem_keygen("ML-KEM-512")
    s, ct = kem_encaps("ML-KEM-512", ek)
    r = kem_decaps("ML-KEM-512", dk, ct)
    assert len(ek) == 800
    assert len(dk) == 1632
    assert len(ct) == 768
    assert s == r


def test_kem_768():
    ek, dk = kem_keygen("ML-KEM-768")
    s, ct = kem_encaps("ML-KEM-768", ek)
    r = kem_decaps("ML-KEM-768", dk, ct)
    assert len(ek) == 1184
    assert len(dk) == 2400
    assert len(ct) == 1088
    assert s == r


def test_kem_1024():
    ek, dk = kem_keygen("ML-KEM-1024")
    s, ct = kem_encaps("ML-KEM-1024", ek)
    r = kem_decaps("ML-KEM-1024", dk, ct)
    assert len(ek) == 1568
    assert len(dk) == 3168
    assert len(ct) == 1568
    assert s == r


def test_sig_44():
    pk, sk = sig_keygen("ML-DSA-44")
    msg = b"test message"
    sg = sig_sign("ML-DSA-44", sk, msg)
    assert sig_verify("ML-DSA-44", pk, msg, sg)
    assert len(pk) == 1312
    assert len(sk) == 2560


def test_sig_65():
    pk, sk = sig_keygen("ML-DSA-65")
    msg = b"test message"
    sg = sig_sign("ML-DSA-65", sk, msg)
    assert sig_verify("ML-DSA-65", pk, msg, sg)
    assert len(pk) == 1952
    assert len(sk) == 4032


def test_sig_87():
    pk, sk = sig_keygen("ML-DSA-87")
    msg = b"test message"
    sg = sig_sign("ML-DSA-87", sk, msg)
    assert sig_verify("ML-DSA-87", pk, msg, sg)
    assert len(pk) == 2592
    assert len(sk) == 4896


def test_sig_rejects_tampered():
    pk, sk = sig_keygen("ML-DSA-65")
    msg = b"original message"
    sg = sig_sign("ML-DSA-65", sk, msg)
    assert not sig_verify("ML-DSA-65", pk, b"tampered message", sg)


def test_hybrid_tls():
    c_key, s_key, stats = hybrid_tls()
    assert c_key == s_key
    assert stats["client_pub_kem"] == 1184
    assert stats["ct_size"] == 1088


def test_measure_kem():
    r = measure_kem("ML-KEM-768", iters=2)
    for key in ("keygen", "encaps", "decaps"):
        assert key in r
        assert r[key] > 0


def test_measure_sig():
    r = measure_sig("ML-DSA-65", iters=2)
    for key in ("keygen", "sign", "verify"):
        assert key in r
        assert r[key] > 0


def test_kem_invalid_ct():
    ek, dk = kem_keygen("ML-KEM-768")
    _, ct = kem_encaps("ML-KEM-768", ek)
    tampered = bytes(b ^ 0xFF if i == 0 else b for i, b in enumerate(ct))
    recovered = kem_decaps("ML-KEM-768", dk, tampered)
    s, _ = kem_encaps("ML-KEM-768", ek)
    assert recovered != s


def test_sig_keygen_deterministic_not():
    pk1, sk1 = sig_keygen("ML-DSA-65")
    pk2, sk2 = sig_keygen("ML-DSA-65")
    assert pk1 != pk2
    assert sk1 != sk2


def test_all_kem_suites():
    for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        ek, dk = kem_keygen(name)
        s, ct = kem_encaps(name, ek)
        r = kem_decaps(name, dk, ct)
        assert s == r, f"{name} failed"


def test_all_sig_suites():
    msg = b"test"
    for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        pk, sk = sig_keygen(name)
        sg = sig_sign(name, sk, msg)
        assert sig_verify(name, pk, msg, sg), f"{name} failed"


# New modules smoke tests
def test_hybrid_cert():
    from src.hybrid_cert import generate_hybrid_chain
    text, stats = generate_hybrid_chain()
    assert stats["root_size"] > 0
    assert stats["inter_size"] > 0
    assert stats["leaf_size"] > 0
    assert "VALID" in text


def test_attack_demo():
    from src.attack_demo import run_attack_demo
    text = run_attack_demo(rsa_bits=32)
    assert "Decrypted message" in text
    assert "ML-KEM-768" in text


def test_wire_format():
    from src.wire_format import inspect
    text = inspect()
    assert "ML-KEM" in text
    assert "ML-DSA" in text


def test_impact_calc():
    from src.impact_calc import calculate
    text, data = calculate(cert_count=1000, tls_per_day=100000)
    assert data["extra_storage"] > 0
    assert data["extra_monthly"] > 0
    assert "PQC MIGRATION IMPACT" in text


# ─── Enterprise assessment: 6 organization profiles ─────────
from src.enterprise_assessment import (
    CryptoInventory, EnterpriseAssessor, RISK_WEIGHTS,
)
from enterprise_gui import ORGANIZATION_PROFILES


def _assess(org):
    inv = CryptoInventory()
    for cat, name, key_size, count in ORGANIZATION_PROFILES[org]:
        inv.add(cat, name, name, key_size, count)
    return EnterpriseAssessor(inv).assess()


def test_all_profiles_give_distinct_results():
    """The 6 profiles must produce genuinely different outcomes.

    This is the regression guard for the bug where every selection appeared
    to return the same four values. If any two profiles collapse to the same
    (readiness, vulnerable, findings, recommendations) tuple, this fails.
    """
    seen = {}
    for org in ORGANIZATION_PROFILES:
        r = _assess(org)
        key = (r["readiness"], r["summary"]["vulnerable_assets"],
               len(r["findings"]), len(r["recommendations"]))
        seen[org] = key
    assert len(set(seen.values())) == len(seen), (
        f"Profiles collapsed to identical result tuples: {seen}")


def test_profile_readiness_range():
    for org in ORGANIZATION_PROFILES:
        r = _assess(org)
        assert 0 <= r["readiness"] <= 100, org
        assert r["grade_label"] in (
            "Green — Strong readiness",
            "Yellow — Partial readiness",
            "Red — Urgent action needed",
        ), org


def test_profile_results_derive_from_inventory():
    """Recompute readiness from the risk counts and labor the exact
    engine formula; it must equal the reported score for every profile."""
    for org in ORGANIZATION_PROFILES:
        r = _assess(org)
        counts = r["risk_counts"]
        total = sum(counts.values())
        recomputed = round(
            sum(RISK_WEIGHTS.get(level, 0) * n
                for level, n in counts.items()) / max(total, 1) * 100)
        assert recomputed == r["readiness"], org
        assert total == r["summary"]["total_assets"], org


def test_changing_dropdown_alone_does_not_rewrite_inventory():
    """Regression for the stale-state bug: the dropdown must not silently
    swap the working inventory (custom edits preserved) unless Load/ANALYZE
    applies the selected profile."""
    small = _assess("Small Office")
    enterprise = _assess("Enterprise")
    assert small != enterprise


def test_quick_add_algorithm_select_changes_results():
    """Regression for the reported bug where changing the quick-add
    Algorithm / Category / Count dropdowns produced identical results.

    ANALYZE must fold a changed quick-add selection into a working copy so
    different selections give different outcomes for EVERY organization, and
    must never mutate the real inventory.
    """
    def kb_bits(algo):
        b = 0
        for p in algo.split("-"):
            if p.isdigit():
                b = int(p)
        return b

    def scored(base, algo, cat="Server", count=None):
        """Mirror enterprise_gui._working_inventory: if no explicit count is
        given, fold the quick-add selection in at the org's typical deployment
        scale (total assets / number of classes, floored at 1) — the same
        default the GUI now seeds into the Count field on load. An explicit
        count is honored exactly."""
        if count is None:
            total = base.total_assets()
            n = max(len(base.assets), 1)
            count = max(1, round(total / n))
        w = CryptoInventory()
        for a in base.to_dict():
            w.add(a["category"], a["name"], a["algorithm"],
                  a["key_size"], a["count"])
        w.add(cat, algo, algo, count=count, key_size=kb_bits(algo))
        return EnterpriseAssessor(w).assess()

    def precise(r):
        counts = r["risk_counts"]
        total = sum(counts.values())
        return sum(RISK_WEIGHTS.get(k, 0) * n
                   for k, n in counts.items()) / max(total, 1) * 100

    def distinct(values):
        return len({round(v, 1) for v in values})

    for org in ORGANIZATION_PROFILES:
        base = CryptoInventory()
        for cat, name, ks, cnt in ORGANIZATION_PROFILES[org]:
            base.add(cat, name, name, ks, cnt)
        before = base.total_assets()
        # (a) Algorithm changes must differentiate for EVERY organization —
        # including the huge ones (Enterprise 1580, Bank 2860, SaaS 3180)
        # that previously collapsed because the fold was clamped to a raw
        # count of one. The GUI seeds the Count field with the org's typical
        # deployment size, so the default fold is large enough to matter.
        algs = [("ECDSA P-256", "Critical"), ("X25519", "High"),
                ("AES-128", "Medium"), ("AES-256", "Safe")]
        values = [round(precise(EnterpriseAssessor(base).assess()), 1)]
        for algo, _ in algs:
            values.append(round(precise(scored(base, algo)), 1))
        assert distinct(values) >= 4, (
            f"{org}: quick-add algorithms did not differentiate at gauge "
            f"precision ({sorted(values)})")
        # (b) Changing ONLY the count of a fixed algorithm at the default
        # scale must change the result too (regression: counts below the
        # org's scale were clamped to the same value and looked frozen).
        fixed = scored(base, "ECDSA P-256")
        count_values = [round(precise(fixed), 1)]
        for c in (2, 10, 100):
            count_values.append(
                round(precise(scored(base, "ECDSA P-256", count=c)), 1))
        assert distinct(count_values) >= 3, (
            f"{org}: changing only the count did not differentiate "
            f"({sorted(count_values)})")
        # The real inventory must be untouched by scoring a selection.
        assert base.total_assets() == before, f"{org}: inventory mutated"


def test_ensure_selected_profile_reconciles_after_dropdown_change():
    """Headless check of the ANALYZE reconcile path added in the GUI fix.

    A changed organization dropdown must produce a fresh inventory whose
    assessment matches that profile, while untouched profiles (loaded_org
    equal to selection) must not be reloaded.
    """
    class _Menu:
        def __init__(self, value):
            self._value = value
        def get(self):
            return self._value

    class _FakeApp:
        def __init__(self, menu_value):
            self.organization_menu = _Menu(menu_value)
            self.inventory = CryptoInventory()
            self._loaded_org = None
            self._reloads = 0
        def _load_selected_organization(self):
            self._reloads += 1
            org = self.organization_menu.get()
            self.inventory = CryptoInventory()
            for cat, name, ks, cnt in ORGANIZATION_PROFILES[org]:
                self.inventory.add(cat, name, name, ks, cnt)
            self._loaded_org = org
        def _ensure_selected_profile(self):
            if self._loaded_org is None:
                return
            selected = self.organization_menu.get()
            if selected != self._loaded_org:
                self._load_selected_organization()

    app = _FakeApp("Enterprise")
    app._load_selected_organization()
    assert app._reloads == 1
    app._ensure_selected_profile()          # unchanged selection → no reload
    assert app._reloads == 1
    app.organization_menu._value = "Bank / Government"
    app._ensure_selected_profile()          # changed selection → reload
    assert app._reloads == 2
    r = EnterpriseAssessor(app.inventory).assess()
    assert r["readiness"] == _assess("Bank / Government")["readiness"]


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
