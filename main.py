import os, sys, time, datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.pqc_wrapper import *
from src.hybrid_cert import generate_hybrid_chain
from src.attack_demo import run_attack_demo
from src.wire_format import inspect as wire_inspect
from src.impact_calc import calculate as impact_calc

BASE = os.path.dirname(os.path.abspath(__file__))
CHART_DIR = os.path.join(BASE, "benchmarks")
os.makedirs(CHART_DIR, exist_ok=True)

def _cls(): os.system("cls" if os.name == "nt" else "clear")
def _pause(): input("\n  Press Enter to return to menu...")
def _header(t):
    _cls()
    print("=" * 58)
    print(f"  PQC MIGRATION TOOLKIT - {t}")
    print("=" * 58)

# ─── MODULE 1: KEM ───
def module_kem():
    _header("MODULE 1: ML-KEM KEY ENCAPSULATION (FIPS 203)")
    for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        print(f"\n  [{name}]")
        ek, dk = kem_keygen(name)
        shared, ct = kem_encaps(name, ek)
        recovered = kem_decaps(name, dk, ct)
        ok = "PASS" if shared == recovered else "FAIL"
        print(f"    Public key:     {len(ek):>5} bytes")
        print(f"    Private key:    {len(dk):>5} bytes")
        print(f"    Ciphertext:     {len(ct):>5} bytes")
        print(f"    Shared secret:  {len(shared):>5} bytes")
        print(f"    Result:         [{ok}]")
    _pause()

# ─── MODULE 2: SIGNATURE ───
def module_sign():
    _header("MODULE 2: ML-DSA DIGITAL SIGNATURES (FIPS 204)")
    msg = b"This is a test document for post-quantum signing."
    for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        print(f"\n  [{name}]")
        pk, sk = sig_keygen(name)
        signature = sig_sign(name, sk, msg)
        valid = sig_verify(name, pk, msg, signature)
        ok = "PASS" if valid else "FAIL"
        print(f"    Public key:     {len(pk):>5} bytes")
        print(f"    Private key:    {len(sk):>5} bytes")
        print(f"    Signature:      {len(signature):>5} bytes")
        print(f"    Valid:          [{ok}]")
    _pause()

# ─── MODULE 3: HYBRID TLS ───
def module_tls():
    _header("MODULE 3: HYBRID TLS 1.3 HANDSHAKE (X25519 + ML-KEM-768)")
    print("\n  [Client] Generates X25519 + ML-KEM-768 keypairs...")
    c_key, s_key, stats = hybrid_tls()
    print(f"    X25519 pubkey:     {stats['client_pub_x25519']} bytes")
    print(f"    ML-KEM pubkey:     {stats['client_pub_kem']} bytes")
    print(f"    Total sent:        {stats['client_pub_x25519'] + stats['client_pub_kem']} bytes")
    print("\n  [Server] Encapsulates + derives hybrid key...")
    print(f"    Ciphertext size:   {stats['ct_size']} bytes")
    match = "MATCH" if c_key == s_key else "MISMATCH"
    print(f"\n    Keys: [{match}]")
    print(f"    Session key: {c_key[:8].hex()}...")
    print("\n    Security: Hybrid protects against both quantum and lattice breaks.")
    _pause()

# ─── MODULE 4: CERT MIGRATION ───
def module_cert():
    _header("MODULE 4: CERTIFICATE MIGRATION ANALYSIS")
    print("\n  -- Classical Certificates (PEM) --")
    for algo, label in [
        (lambda: rsa.generate_private_key(65537, 2048), "RSA-2048"),
        (lambda: rsa.generate_private_key(65537, 4096), "RSA-4096"),
        (lambda: ec.generate_private_key(ec.SECP256R1()), "ECDSA P-256"),
    ]:
        key = algo()
        cert = make_self_signed_cert(key)
        sz = len(cert.public_bytes(serialization.Encoding.PEM))
        print(f"    {label:20s}  {sz:>5} bytes")
    print(f"\n  -- Post-Quantum Keys --")
    for name in ["ML-DSA-65", "ML-DSA-87"]:
        pk, sk = sig_keygen(name)
        print(f"    {name:20s}  pk={len(pk):>4}B, sk={len(sk):>4}B")
    _pause()

# ─── MODULE 5: BENCHMARK ───
def module_bench():
    _header("MODULE 5: PERFORMANCE BENCHMARKS")
    results = {}
    print("\n  -- ML-KEM (Key Encapsulation) --")
    for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        print(f"\n    [{name}]")
        r = measure_kem(name)
        for op, t in r.items():
            print(f"      {op:10s}  {t:8.2f} ms")
        results.update({f"{name}_{k}": v for k, v in r.items()})
    print("\n  -- ML-DSA (Digital Signatures) --")
    for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        print(f"\n    [{name}]")
        r = measure_sig(name)
        for op, t in r.items():
            print(f"      {op:10s}  {t:8.2f} ms")
        results.update({f"{name}_{k}": v for k, v in r.items()})
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    x = np.arange(3); w = 0.25
    for ax, labels, ops in [
        (axes[0], ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"], ["keygen", "encaps", "decaps"]),
        (axes[1], ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"], ["keygen", "sign", "verify"]),
    ]:
        for i, op in enumerate(ops):
            vals = [results.get(f"{l}_{op}", 0) for l in labels]
            ax.bar(x + (i - 1) * w, vals, w, label=op.capitalize())
        ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylabel("Time (ms)"); ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
    axes[0].set_title("ML-KEM Performance"); axes[1].set_title("ML-DSA Performance")
    plt.tight_layout()
    chart_path = os.path.join(CHART_DIR, "pqc_benchmark.png")
    plt.savefig(chart_path, dpi=150); plt.close()
    print(f"\n  Chart saved to: {chart_path}")
    _pause()

# ─── MODULE 6: HYBRID CERT CHAIN ───
def module_hybrid_chain():
    _header("MODULE 6: HYBRID CERTIFICATE CHAIN")
    text, stats = generate_hybrid_chain()
    for line in text.split("\n"):
        print(f"  {line.strip()}")
    _pause()

# ─── MODULE 7: ATTACK DEMO ───
def module_attack():
    _header("MODULE 7: HARVEST NOW DECRYPT LATER ATTACK DEMO")
    print(run_attack_demo(rsa_bits=32))
    _pause()

# ─── MODULE 8: WIRE FORMAT ───
def module_wire():
    _header("MODULE 8: PQC WIRE FORMAT INSPECTION")
    print(wire_inspect())
    _pause()

# ─── MODULE 9: IMPACT CALC ───
def module_impact():
    _header("MODULE 9: MIGRATION IMPACT CALCULATOR")
    text, data = impact_calc()
    print(text)
    _pause()

# ─── MENU ───
MENU = """
  +------------------------------------------------------+
  |          PQC MIGRATION TOOLKIT - MAIN MENU           |
  +------------------------------------------------------+
  |  1.  ML-KEM Key Encapsulation Demo   (FIPS 203)      |
  |  2.  ML-DSA Digital Signature Demo   (FIPS 204)      |
  |  3.  Hybrid TLS 1.3 Handshake Demo                   |
  |  4.  Certificate Migration Analysis                   |
  |  5.  Performance Benchmarks + Charts                 |
  |  6.  Hybrid Certificate Chain (RSA + ML-DSA)         |
  |  7.  Attack Demo: Harvest Now Decrypt Later          |
  |  8.  Wire-Format Inspection (hex dump)               |
  |  9.  Migration Impact Calculator                     |
  |                                                      |
  |  10. Run ALL modules sequentially                    |
  |                                                      |
  |  0.  Exit                                            |
  +------------------------------------------------------+
"""

MODULES = [module_kem, module_sign, module_tls, module_cert, module_bench,
           module_hybrid_chain, module_attack, module_wire, module_impact]

def main():
    while True:
        _cls()
        print(MENU)
        choice = input("  Enter your choice [0-10]: ").strip()
        if choice == "0":
            print("\n  Exiting. Thank you!\n"); break
        elif choice == "10":
            for i, mod in enumerate(MODULES, 1):
                if i > 1: _cls()
                print(f"\n  Launching Module {i}...\n"); time.sleep(1)
                mod()
            _pause()
        elif choice.isdigit() and 1 <= int(choice) <= 9:
            MODULES[int(choice) - 1]()
        else:
            print("\n  Invalid choice."); time.sleep(1)

if __name__ == "__main__":
    main()
