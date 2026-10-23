"""Migration Impact Calculator — estimates storage/bandwidth costs of PQC migration.
Input: number of certificates, daily TLS connections, bandwidth limits.
Output: extra storage in MB, extra bandwidth in GB/month."""

from src.pqc_wrapper import kem_keygen, sig_keygen, sig_sign

CLASSICAL_SIZES = {
    "RSA-2048 cert": 900,
    "RSA-4096 cert": 1700,
    "ECDSA P-256 cert": 700,
    "Ed25519 cert": 600,
    "X25519 key": 32,
    "ECDSA signature": 70,
}

def _get_pqc_sizes():
    kem_ek, _ = kem_keygen("ML-KEM-768")
    pk, sk = sig_keygen("ML-DSA-65")
    sig = sig_sign("ML-DSA-65", sk, b"test")
    return {
        "ML-KEM-768 pubkey": len(kem_ek),
        "ML-DSA-65 pubkey": len(pk),
        "ML-DSA-65 privkey": len(sk),
        "ML-DSA-65 signature": len(sig),
    }

def _fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b/1024:.1f} KB"
    else:
        return f"{b/(1024*1024):.1f} MB"

def _fmt_bits_per_sec(b_per_day):
    return f"{b_per_day * 8 / 86400:.1f} Kbps"

def calculate(cert_count=10000, tls_per_day=1000000, hybrid_ratio=0.5, years=5):
    pqc = _get_pqc_sizes()
    lines = []
    lines.append("=" * 65)
    lines.append("  PQC MIGRATION IMPACT CALCULATOR")
    lines.append("=" * 65)
    lines.append(f"")
    lines.append(f"  Input Parameters")
    lines.append(f"  {'Active certificates:':30s} {cert_count:>10,}")
    lines.append(f"  {'TLS handshakes/day:':30s} {tls_per_day:>10,}")
    lines.append(f"  {'Hybrid cert ratio:':30s} {hybrid_ratio*100:>9.0f}%")
    lines.append(f"  {'Migration window:':30s} {years:>10} years")
    lines.append(f"")

    classical_cert_size = CLASSICAL_SIZES["RSA-2048 cert"]
    pqc_cert_size = classical_cert_size + pqc["ML-DSA-65 pubkey"] + pqc["ML-DSA-65 signature"]
    hybrid_cert_size = classical_cert_size + pqc_cert_size

    lines.append(f"  Certificate Sizes")
    lines.append(f"  {'Classical RSA-2048 cert:':30s} {_fmt_bytes(classical_cert_size):>15s}")
    lines.append(f"  {'PQC-only cert (est.):':30s} {_fmt_bytes(pqc_cert_size):>15s}")
    lines.append(f"  {'Hybrid cert (RSA+ML-DSA):':30s} {_fmt_bytes(hybrid_cert_size):>15s}")
    lines.append(f"")

    # Storage impact
    classical_storage = classical_cert_size * cert_count
    hybrid_storage = hybrid_cert_size * cert_count
    pqc_storage = pqc_cert_size * cert_count
    extra_hybrid = hybrid_storage - classical_storage
    extra_pqc = pqc_storage - classical_storage

    lines.append(f"  Storage Impact (all {cert_count:,} certs)")
    lines.append(f"  {'Classical storage:':30s} {_fmt_bytes(classical_storage):>15s}")
    lines.append(f"  {'Hybrid storage:':30s} {_fmt_bytes(hybrid_storage):>15s}  (+{_fmt_bytes(extra_hybrid)})")
    lines.append(f"  {'PQC-only storage:':30s} {_fmt_bytes(pqc_storage):>15s}  (+{_fmt_bytes(extra_pqc)})")
    lines.append(f"")

    # TLS bandwidth impact
    classical_handshake = CLASSICAL_SIZES["X25519 key"] * 2 + CLASSICAL_SIZES["ECDSA signature"] * 2
    hybrid_handshake = classical_handshake + pqc["ML-KEM-768 pubkey"] + pqc["ML-DSA-65 signature"]
    classical_daily = classical_handshake * tls_per_day
    hybrid_daily = hybrid_handshake * tls_per_day
    pqc_daily = (pqc["ML-KEM-768 pubkey"] + pqc["ML-DSA-65 signature"]) * tls_per_day

    lines.append(f"  Bandwidth Impact ({tls_per_day:,} TLS/day)")
    lines.append(f"  {'Classical handshake:':30s} {_fmt_bytes(classical_handshake):>15s}")
    lines.append(f"  {'Hybrid handshake:':30s} {_fmt_bytes(hybrid_handshake):>15s}")
    lines.append(f"  {'Handshake overhead:':30s} {_fmt_bytes(hybrid_handshake - classical_handshake):>15s}")
    lines.append(f"")
    lines.append(f"  {'Classical daily bw:':30s} {_fmt_bytes(classical_daily):>15s}  ({_fmt_bits_per_sec(classical_daily)})")
    lines.append(f"  {'Hybrid daily bw:':30s} {_fmt_bytes(hybrid_daily):>15s}  ({_fmt_bits_per_sec(hybrid_daily)})")
    lines.append(f"  {'Extra daily bw:':30s} {_fmt_bytes(hybrid_daily - classical_daily):>15s}")
    lines.append(f"")

    # Monthly and yearly
    extra_monthly = (hybrid_daily - classical_daily) * 30
    extra_yearly = extra_monthly * 12
    extra_5year = extra_yearly * years

    lines.append(f"  Cumulative Extra Bandwidth Cost")
    lines.append(f"  {'Extra per month:':30s} {_fmt_bytes(extra_monthly):>15s}")
    lines.append(f"  {'Extra per year:':30s} {_fmt_bytes(extra_yearly):>15s}")
    lines.append(f"  {'Extra over {years} years:':30s} {_fmt_bytes(extra_5year):>15s}")
    lines.append(f"")

    lines.append(f"  Summary")
    lines.append(f"  Migrating {cert_count:,} certs to hybrid adds")
    lines.append(f"  {_fmt_bytes(extra_hybrid)} in storage and {_fmt_bytes(extra_monthly)}/month in TLS bandwidth.")
    lines.append(f"  For {tls_per_day:,} TLS/day ({hybrid_ratio*100:.0f}% hybrid):")
    lines.append(f"  ~{_fmt_bytes(extra_monthly)} extra bandwidth/month.")
    lines.append(f"")
    lines.append(f"  This is the cost of quantum-safety — generally acceptable")
    lines.append(f"  for most enterprises (modern networks handle it easily).")
    lines.append(f"  The real cost is in software updates and CA coordination.")
    lines.append("=" * 65)

    return "\n".join(lines), dict(
        classical_cert=classical_cert_size, hybrid_cert=hybrid_cert_size, pqc_cert=pqc_cert_size,
        classical_storage=classical_storage, hybrid_storage=hybrid_storage, pqc_storage=pqc_storage,
        classical_daily_bw=classical_daily, hybrid_daily_bw=hybrid_daily,
        extra_storage=extra_hybrid, extra_monthly=extra_monthly,
    )

def enterprise_plan(users=10000, servers=500, cert_count=5000, tls_per_day=500000,
                    traffic_gb_per_day=100, algo="ML-KEM-768", hybrid_ratio=0.5):
    pqc = _get_pqc_sizes()
    lines = []
    lines.append("=" * 70)
    lines.append("  ENTERPRISE PQC MIGRATION PLAN")
    lines.append("=" * 70)
    lines.append("")
    lines.append("  Input Parameters")
    lines.append(f"  {'Employees/Users:':35s} {users:>12,}")
    lines.append(f"  {'Servers:':35s} {servers:>12,}")
    lines.append(f"  {'Active certificates:':35s} {cert_count:>12,}")
    lines.append(f"  {'TLS handshakes/day:':35s} {tls_per_day:>12,}")
    lines.append(f"  {'Avg traffic/day:':35s} {traffic_gb_per_day:>12} GB")
    lines.append(f"  {'Target algorithm:':35s} {algo}")
    lines.append(f"  {'Hybrid cert ratio:':35s} {hybrid_ratio*100:.0f}%")
    lines.append("")

    classical_cert_sz = CLASSICAL_SIZES["RSA-2048 cert"]
    pqc_cert_sz = classical_cert_sz + pqc["ML-DSA-65 pubkey"] + pqc["ML-DSA-65 signature"]
    hybrid_cert_sz = classical_cert_sz + pqc_cert_sz
    classical_handshake = CLASSICAL_SIZES["X25519 key"] * 2 + CLASSICAL_SIZES["ECDSA signature"] * 2
    hybrid_handshake = classical_handshake + pqc["ML-KEM-768 pubkey"] + pqc["ML-DSA-65 signature"]

    current_storage = classical_cert_sz * cert_count
    future_storage = hybrid_cert_sz * cert_count
    extra_storage = future_storage - current_storage

    current_bw_day = classical_handshake * tls_per_day
    future_bw_day = hybrid_handshake * tls_per_day
    extra_bw_day = future_bw_day - current_bw_day
    extra_bw_month = extra_bw_day * 30
    extra_bw_year = extra_bw_month * 12

    risk_score = min(100, 30 + (users // 1000) + (cert_count // 500))
    risk_level = "High" if risk_score > 70 else "Medium" if risk_score > 40 else "Low"
    migration_cost = users * 5 + servers * 200 + cert_count * 2 + int(traffic_gb_per_day * 50)
    timeline_years = 3 if risk_score > 70 else 5 if risk_score > 40 else 7

    lines.append("  ── Storage Impact ──")
    lines.append(f"  {'Current classical storage:':35s} {_fmt_bytes(current_storage):>15s}")
    lines.append(f"  {'Hybrid (RSA+ML-DSA) storage:':35s} {_fmt_bytes(future_storage):>15s}")
    lines.append(f"  {'Extra storage required:':35s} {_fmt_bytes(extra_storage):>15s}")
    lines.append("")

    lines.append("  ── Bandwidth Impact ──")
    lines.append(f"  {'Classical handshake:':35s} {_fmt_bytes(classical_handshake):>15s}")
    lines.append(f"  {'Hybrid handshake:':35s} {_fmt_bytes(hybrid_handshake):>15s}")
    lines.append(f"  {'Extra per day:':35s} {_fmt_bytes(extra_bw_day):>15s}")
    lines.append(f"  {'Extra per month:':35s} {_fmt_bytes(extra_bw_month):>15s}")
    lines.append(f"  {'Extra per year:':35s} {_fmt_bytes(extra_bw_year):>15s}")
    lines.append("")

    lines.append("  ── Risk Assessment ──")
    lines.append(f"  {'Risk score:':35s} {risk_score}/100 ({risk_level})")
    if risk_level == "High":
        lines.append(f"  {'Assessment:':35s} Immediate action required. Quantum threat critical.")
    elif risk_level == "Medium":
        lines.append(f"  {'Assessment:':35s} Plan migration within 2 years. Moderate risk.")
    else:
        lines.append(f"  {'Assessment:':35s} Low current risk. Monitor and plan.")

    if "ML-KEM" in algo or "ML-DSA" in algo:
        lines.append(f"  {'PQC readiness:':35s} ✅ Already evaluating PQC algorithms")
    else:
        lines.append(f"  {'PQC readiness:':35s} ❌ Not yet evaluating PQC")
    lines.append("")

    lines.append("  ── Migration Cost Estimate ──")
    lines.append(f"  {'Estimated budget:':35s} ${migration_cost:,}")
    lines.append(f"  {'Recommended timeline:':35s} {timeline_years} years")
    lines.append("")

    lines.append("  ── Recommended Strategy ──")
    lines.append(f"  1. Inventory all cryptographic assets (keys, certs, protocols)")
    lines.append(f"  2. Prioritize critical systems and long-lived secrets")
    lines.append(f"  3. Deploy hybrid certificates (RSA + ML-DSA) in pilot")
    lines.append(f"  4. Test compatibility with legacy systems")
    lines.append(f"  5. Roll out hybrid TLS to all services")
    lines.append(f"  6. Monitor for PQC-ready CA certificates")
    lines.append(f"  7. Deprecate classical-only crypto by Year {timeline_years}")
    lines.append("")
    lines.append("=" * 70)

    return "\n".join(lines), dict(
        extra_storage=extra_storage, extra_bw_month=extra_bw_month,
        risk_score=risk_score, risk_level=risk_level,
        migration_cost=migration_cost, timeline_years=timeline_years,
    )

def run():
    return calculate()
