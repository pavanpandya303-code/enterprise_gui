"""Enterprise PQC Assessment — analyzes an organization's cryptographic
infrastructure and computes Post-Quantum Cryptography (PQC) readiness.

This module is a PURE analysis engine. It contains NO GUI code, so it can be
used by a desktop app, a CLI, or a future web service. Every scanner
(website, TLS, certificate, OpenSSL, Nmap, Wireshark) added later will simply
produce :class:`Asset` objects and feed them into :class:`EnterpriseAssessor`.

Design goals
------------
* Modular & OOP — each concern lives in its own class.
* Extensible — add a scanner by implementing ``scan() -> list[Asset]``.
* Backward compatible — nothing here touches the existing toolkit modules.
* Production quality — type hints, docstrings, PEP-8, no side effects on import.
"""

from __future__ import annotations

import datetime
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class RiskLevel(str, Enum):
    """Standardized risk levels used across the whole assessment."""

    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ──────────────────────────────────────────────────────────────────────
# Knowledge base: how every algorithm maps to a risk level, an
# explanation, a recommended PQC replacement, and a priority.
# This single dict drives risk analysis, recommendations, and scoring.
# ──────────────────────────────────────────────────────────────────────
ALGORITHM_KB: Dict[str, Dict[str, str]] = {
    "RSA-2048": {
        "risk": RiskLevel.CRITICAL,
        "reason": "Broken by Shor's algorithm on a large enough quantum computer.",
        "replacement": "ML-KEM-768 hybrid (X25519MLKEM768)",
        "priority": "Critical",
    },
    "RSA-4096": {
        "risk": RiskLevel.HIGH,
        "reason": "Bigger key only delays Shor's attack; still not quantum-safe.",
        "replacement": "ML-KEM-768 / ML-KEM-1024 hybrid",
        "priority": "High",
    },
    "ECDSA P-256": {
        "risk": RiskLevel.CRITICAL,
        "reason": "Elliptic-curve discrete log broken by Shor's algorithm.",
        "replacement": "ML-DSA-65 (FIPS 204)",
        "priority": "Critical",
    },
    "ECDSA P-384": {
        "risk": RiskLevel.HIGH,
        "reason": "Same ECC weakness as P-256; slightly larger curve only delays attack.",
        "replacement": "ML-DSA-65 / ML-DSA-87",
        "priority": "High",
    },
    "Ed25519": {
        "risk": RiskLevel.HIGH,
        "reason": "Edwards-curve signatures are ECC-based; broken by Shor.",
        "replacement": "ML-DSA-65 (FIPS 204)",
        "priority": "High",
    },
    "X25519": {
        "risk": RiskLevel.HIGH,
        "reason": "ECC key exchange; the exchange key is broken by Shor.",
        "replacement": "X25519MLKEM768 hybrid",
        "priority": "High",
    },
    "AES-128": {
        "risk": RiskLevel.MEDIUM,
        "reason": "Grover's algorithm halves effective security to ~64-bit.",
        "replacement": "AES-256 (quantum-safe margin)",
        "priority": "Medium",
    },
    "AES-256": {
        "risk": RiskLevel.SAFE,
        "reason": "Grover reduces to ~128-bit — still well above the safe threshold.",
        "replacement": "None (already safe)",
        "priority": "Low",
    },
    "ChaCha20": {
        "risk": RiskLevel.SAFE,
        "reason": "256-bit symmetric cipher; quantum-safe for confidentiality.",
        "replacement": "None (already safe)",
        "priority": "Low",
    },
    "3DES": {
        "risk": RiskLevel.CRITICAL,
        "reason": "Deprecated cipher; weak key size, meets-in-the-middle attacks.",
        "replacement": "AES-256 / ChaCha20",
        "priority": "Critical",
    },
    "MD5": {
        "risk": RiskLevel.CRITICAL,
        "reason": "Broken hash — collision attacks are trivial and practical.",
        "replacement": "SHA-256 / SHA-384",
        "priority": "Critical",
    },
    "SHA-1": {
        "risk": RiskLevel.CRITICAL,
        "reason": "Deprecated (SHA-1 deprecated 2011); collision attacks practical.",
        "replacement": "SHA-256 / SHA-384",
        "priority": "Critical",
    },
    "SHA-256": {
        "risk": RiskLevel.SAFE,
        "reason": "Quantum-resistant hash (Grover preimage ~128-bit effective).",
        "replacement": "None (already safe)",
        "priority": "Low",
    },
    "SHA-384": {
        "risk": RiskLevel.SAFE,
        "reason": "Quantum-resistant hash (Grover preimage ~192-bit effective).",
        "replacement": "None (already safe)",
        "priority": "Low",
    },
    "TLS 1.2": {
        "risk": RiskLevel.HIGH,
        "reason": "No native hybrid PQC key exchange; forces classical-only handshakes.",
        "replacement": "TLS 1.3 with hybrid (X25519MLKEM768)",
        "priority": "High",
    },
    "TLS 1.3": {
        "risk": RiskLevel.SAFE,
        "reason": "Supports hybrid post-quantum key exchange out of the box.",
        "replacement": "None (enable hybrid groups)",
        "priority": "Low",
    },
    "Diffie-Hellman 2048": {
        "risk": RiskLevel.HIGH,
        "reason": "Classical DH discrete log broken by Shor's algorithm.",
        "replacement": "ML-KEM-768 / X25519MLKEM768",
        "priority": "High",
    },
    "DSA-2048": {
        "risk": RiskLevel.HIGH,
        "reason": "Classical DSA signatures rely on discrete log; broken by Shor.",
        "replacement": "ML-DSA-65 (FIPS 204)",
        "priority": "High",
    },
    "HMAC-SHA256": {
        "risk": RiskLevel.SAFE,
        "reason": "Keyed hash is quantum-safe; no change required.",
        "replacement": "None (already safe)",
        "priority": "Low",
    },
}

# Weight of each risk level when computing the readiness score.
RISK_WEIGHTS: Dict[str, float] = {
    RiskLevel.SAFE: 1.0,
    RiskLevel.LOW: 0.75,
    RiskLevel.MEDIUM: 0.50,
    RiskLevel.HIGH: 0.25,
    RiskLevel.CRITICAL: 0.0,
}


# ──────────────────────────────────────────────────────────────────────
# 1. Data model
# ──────────────────────────────────────────────────────────────────────
@dataclass
class Asset:
    """A single discovered cryptographic asset.

    Attributes
    ----------
    category:  where the asset lives (e.g. "Server", "Certificate", "TLS").
    name:      human readable name (e.g. "RSA-2048").
    algorithm: canonical key into :data:`ALGORITHM_KB`.
    key_size:  key length in bits (0 if not applicable).
    count:     how many instances of this asset exist.
    """

    category: str
    name: str
    algorithm: str
    key_size: int = 0
    count: int = 1


class CryptoInventory:
    """Collects assets (from manual input or future scanners) and deduplicates."""

    def __init__(self) -> None:
        self.assets: Dict[str, Asset] = {}

    def add(self, category: str, name: str, algorithm: str = "",
            key_size: int = 0, count: int = 1) -> Asset:
        """Add or merge an asset. Returns the stored :class:`Asset`."""
        key = f"{category}::{name}"
        if key in self.assets:
            self.assets[key].count += count
        else:
            self.assets[key] = Asset(
                category=category, name=name,
                algorithm=algorithm or name, key_size=key_size, count=count,
            )
        return self.assets[key]

    def add_from_scanner(self, assets: List[Asset]) -> None:
        """Future scanners call this — they never need to touch this class."""
        for asset in assets:
            self.add(asset.category, asset.name, asset.algorithm,
                     asset.key_size, asset.count)

    def total_assets(self) -> int:
        """Total number of discrete assets (sum of counts)."""
        return sum(a.count for a in self.assets.values())

    def categories(self) -> List[str]:
        """Unique category names in insertion order."""
        seen: List[str] = []
        for a in self.assets.values():
            if a.category not in seen:
                seen.append(a.category)
        return seen

    def assets_in_category(self, category: str) -> List[Asset]:
        return [a for a in self.assets.values() if a.category == category]

    def to_dict(self) -> List[Dict]:
        return [{"category": a.category, "name": a.name,
                 "algorithm": a.algorithm, "key_size": a.key_size,
                 "count": a.count} for a in self.assets.values()]


# ──────────────────────────────────────────────────────────────────────
# 2. Risk analysis
# ──────────────────────────────────────────────────────────────────────
class RiskAnalyzer:
    """Evaluates every asset against the knowledge base."""

    def analyze(self, inventory: CryptoInventory) -> Dict:
        """Return {risk_level: count} plus per-asset findings.

        Also attaches ``risk``, ``reason`` and ``recommendation`` to each
        asset for downstream rendering.
        """
        counts: Dict[str, int] = {r.value: 0 for r in RiskLevel}
        findings: List[Dict] = []

        for asset in inventory.assets.values():
            kb = ALGORITHM_KB.get(asset.algorithm)
            if kb is None:
                # Unknown asset — treat conservatively as medium risk.
                level, reason = RiskLevel.MEDIUM, "Unknown algorithm — verify its quantum status."
                replacement = "Perform manual assessment"
            else:
                level = kb["risk"]
                reason = kb["reason"]
                replacement = kb["replacement"]
            counts[level.value] += asset.count
            findings.append({
                "category": asset.category,
                "name": asset.name,
                "count": asset.count,
                "risk": level.value,
                "reason": reason,
                "replacement": replacement,
                "priority": kb["priority"] if kb else "Medium",
            })
            # Attach to asset so later classes can reuse.
            asset.risk = level            # type: ignore[attr-defined]
            asset.reason = reason         # type: ignore[attr-defined]
            asset.replacement = replacement  # type: ignore[attr-defined]

        return {"counts": counts, "findings": findings}


# ──────────────────────────────────────────────────────────────────────
# 3. Readiness score
# ──────────────────────────────────────────────────────────────────────
class ReadinessScorer:
    """Computes an overall PQC readiness percentage (0-100)."""

    def score(self, inventory: CryptoInventory,
              risk_counts: Dict[str, int]) -> int:
        total = sum(risk_counts.values())
        if total == 0:
            return 0
        weighted = sum(RISK_WEIGHTS[r] * n
                       for r, n in risk_counts.items()
                       if n > 0)
        return round(weighted / total * 100)

    @staticmethod
    def grade(score: int) -> Tuple[str, str]:
        """Return (color, label) for a readiness score.

        Green 80-100 · Yellow 50-79 · Red <50
        """
        if score >= 80:
            return "#4caf50", "Green — Strong readiness"
        if score >= 50:
            return "#ffa500", "Yellow — Partial readiness"
        return "#f44336", "Red — Urgent action needed"


# ──────────────────────────────────────────────────────────────────────
# 4. Recommendation engine
# ──────────────────────────────────────────────────────────────────────
class RecommendationEngine:
    """Maps every vulnerable asset to a recommended PQC replacement."""

    def recommend(self, inventory: CryptoInventory) -> List[Dict]:
        recs: List[Dict] = []
        order = {RiskLevel.CRITICAL.value: 0, RiskLevel.HIGH.value: 1,
                 RiskLevel.MEDIUM.value: 2, RiskLevel.LOW.value: 3,
                 RiskLevel.SAFE.value: 4}
        risky = [a for a in inventory.assets.values()
                 if getattr(a, "risk", RiskLevel.SAFE) is not RiskLevel.SAFE]
        risky.sort(key=lambda a: order.get(getattr(a, "risk").value, 9))
        for asset in risky:
            recs.append({
                "detected": asset.name,
                "recommended": getattr(asset, "replacement", "Review manually"),
                "reason": getattr(asset, "reason", ""),
                "priority": getattr(asset, "risk", RiskLevel.SAFE).value,
                "nist": self._nist_ref(asset.algorithm),
            })
        return recs

    @staticmethod
    def _nist_ref(algorithm: str) -> str:
        if algorithm.startswith("RSA") or algorithm in ("X25519",):
            return "FIPS 203 (ML-KEM)"
        if algorithm.startswith("ECDSA") or algorithm.startswith("DSA") \
                or algorithm == "Ed25519":
            return "FIPS 204 (ML-DSA)"
        if algorithm in ("SHA-1", "MD5"):
            return "FIPS 180-4 / SP 800-131A"
        if algorithm in ("AES-128", "AES-256", "3DES"):
            return "FIPS 197 (AES)"
        if algorithm in ("TLS 1.2", "TLS 1.3"):
            return "IETF RFC 8446 (TLS 1.3)"
        return "NIST CNSA 2.0 guidance"


# ──────────────────────────────────────────────────────────────────────
# 5. Migration roadmap
# ──────────────────────────────────────────────────────────────────────
class MigrationRoadmap:
    """Generates the 5-phase enterprise migration roadmap."""

    PHASES: List[Dict] = [
        {
            "name": "Phase 1 — Inventory",
            "desc": "Discover all crypto assets: keys, certs, TLS, hashes.",
            "time": "1-2 months",
            "risk": "Low",
            "downtime": "None",
        },
        {
            "name": "Phase 2 — Pilot Hybrid Deployment",
            "desc": "Run hybrid (X25519 + ML-KEM) on a small pilot group.",
            "time": "2-3 months",
            "risk": "Medium",
            "downtime": "Minimal (staged)",
        },
        {
            "name": "Phase 3 — Certificate Migration",
            "desc": "Issue hybrid X.509 certs (RSA + ML-DSA) via your CA.",
            "time": "3-6 months",
            "risk": "High",
            "downtime": "Scheduled per-cert rotation",
        },
        {
            "name": "Phase 4 — TLS Migration",
            "desc": "Enable TLS 1.3 + hybrid key exchange on all services.",
            "time": "6-12 months",
            "risk": "High",
            "downtime": "Rolling, per-service windows",
        },
        {
            "name": "Phase 5 — Production Rollout",
            "desc": "Full PQC/hybrid rollout, monitor, then deprecate classical.",
            "time": "12-18 months",
            "risk": "Medium",
            "downtime": "Planned maintenance windows",
        },
    ]

    def build(self) -> List[Dict]:
        return [dict(p) for p in self.PHASES]


# ──────────────────────────────────────────────────────────────────────
# 6. Orchestrator
# ──────────────────────────────────────────────────────────────────────
class EnterpriseAssessor:
    """Top-level facade: run every step and produce a result dict.

    Usage::

        inv = CryptoInventory()
        inv.add("Server", "RSA-2048", "RSA-2048", 2048, 12)
        result = EnterpriseAssessor(inv).assess()
    """

    def __init__(self, inventory: CryptoInventory) -> None:
        self.inventory = inventory

    def assess(self) -> Dict:
        analyzer = RiskAnalyzer()
        risk_data = analyzer.analyze(self.inventory)
        counts = risk_data["counts"]

        scorer = ReadinessScorer()
        score = scorer.score(self.inventory, counts)
        grade_color, grade_label = scorer.grade(score)

        recommendations = RecommendationEngine().recommend(self.inventory)
        roadmap = MigrationRoadmap().build()

        vulnerable = sum(counts[r] for r in
                         (RiskLevel.HIGH.value, RiskLevel.CRITICAL.value))
        safe = counts[RiskLevel.SAFE.value]

        return {
            "risk_counts": counts,
            "findings": risk_data["findings"],
            "readiness": score,
            "grade_color": grade_color,
            "grade_label": grade_label,
            "recommendations": recommendations,
            "roadmap": roadmap,
            "summary": self._summary(score, vulnerable, safe),
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "assets": self.inventory.to_dict(),
        }

    def _summary(self, score: int, vulnerable: int, safe: int) -> Dict:
        total = self.inventory.total_assets()
        difficulty = "Hard" if vulnerable > 0 and safe / max(total, 1) < 0.5 \
            else "Moderate"
        if score >= 80:
            compliance = "Strong (CNSA 2.0 aligned)"
        elif score >= 50:
            compliance = "Partial — gaps remain"
        else:
            compliance = "Non-compliant — urgent"
        return {
            "total_assets": total,
            "vulnerable_assets": vulnerable,
            "safe_assets": safe,
            "compliance": compliance,
            "overall_risk": "High" if vulnerable > 0 else "Low",
            "migration_difficulty": difficulty,
        }

    def to_json(self) -> str:
        """Serialize the full result for logs or future web dashboards."""
        import json
        result = self.assess()
        return json.dumps(result, indent=2, default=str)


# ──────────────────────────────────────────────────────────────────────
# Self-test (no GUI): `python -m src.enterprise_assessment`
# ──────────────────────────────────────────────────────────────────────
def run_demo() -> Dict:
    """Build a sample inventory and run a full assessment."""
    inv = CryptoInventory()
    inv.add("Server", "RSA-2048", "RSA-2048", 2048, 12)
    inv.add("Server", "ECDSA P-256", "ECDSA P-256", 256, 8)
    inv.add("Server", "X25519", "X25519", 256, 30)
    inv.add("Certificate", "RSA-2048", "RSA-2048", 2048, 40)
    inv.add("Certificate", "SHA-256", "SHA-256", 0, 40)
    inv.add("TLS", "TLS 1.2", "TLS 1.2", 0, 50)
    inv.add("TLS", "TLS 1.3", "TLS 1.3", 0, 50)
    inv.add("Hash", "SHA-1", "SHA-1", 0, 15)
    inv.add("Symmetric", "AES-256", "AES-256", 256, 100)
    return EnterpriseAssessor(inv).assess()


if __name__ == "__main__":
    result = run_demo()
    print("=" * 62)
    print("  ENTERPRISE PQC ASSESSMENT — CLI SELF-TEST")
    print("=" * 62)
    print(f"  Readiness score : {result['readiness']}%  "
          f"({result['grade_label']})")
    print(f"  Risk breakdown  : "
          f"{dict(result['risk_counts'])}")
    print(f"  Total assets    : {result['summary']['total_assets']}")
    print(f"  Vulnerable      : {result['summary']['vulnerable_assets']}")
    print(f"  Compliance      : {result['summary']['compliance']}")
    print("-" * 62)
    print("  Recommendations:")
    for r in result["recommendations"]:
        print(f"    {r['detected']}  ->  {r['recommended']}"
              f"  [{r['priority']}]")
    print("-" * 62)
    print("  Roadmap:")
    for p in result["roadmap"]:
        print(f"    {p['name']:<32} {p['time']:<14} risk={p['risk']}")
    print("=" * 62)
