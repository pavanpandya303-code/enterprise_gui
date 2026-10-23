import time, statistics, os, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from kyber_py.ml_kem.default_parameters import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44, ML_DSA_65, ML_DSA_87

ITERS = 5
RESULTS_DIR = os.path.join(os.path.dirname(__file__) or ".", "..", "benchmarks")

def _measure(label, fn):
    times = []
    for _ in range(ITERS):
        t0 = time.perf_counter()
        r = fn()
        times.append((time.perf_counter() - t0) * 1000)
    avg = statistics.mean(times)
    print(f"  {label:30s} {avg:8.2f} ms")
    return avg, r

def run_benchmark():
    print("=" * 60)
    print("PQC BENCHMARK SUITE - Performance Comparison")
    print("=" * 60)
    results = {}
    print("\n--- ML-KEM (Key Encapsulation) ---")
    for name, kem in [("ML-KEM-512", ML_KEM_512), ("ML-KEM-768", ML_KEM_768), ("ML-KEM-1024", ML_KEM_1024)]:
        print(f"\n  [{name}]")
        t_kgen, (ek, dk) = _measure("KeyGen", lambda: kem.keygen())
        t_enc, (shared, ct) = _measure("Encaps", lambda: kem.encaps(ek))
        t_dec, (recovered,) = _measure("Decaps", lambda: (kem.decaps(dk, ct),))
        results[f"{name}_keygen"] = t_kgen
        results[f"{name}_encaps"] = t_enc
        results[f"{name}_decaps"] = t_dec
    print("\n--- ML-DSA (Digital Signatures) ---")
    msg = b"Benchmark test message for post-quantum signatures."
    for name, signer in [("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
        print(f"\n  [{name}]")
        t_kgen, (pk, sk) = _measure("KeyGen", lambda: signer.keygen())
        t_sig, (sig,) = _measure("Sign", lambda: (signer.sign(sk, msg),))
        t_ver, (valid,) = _measure("Verify", lambda: (signer.verify(pk, msg, sig),))
        results[f"{name}_keygen"] = t_kgen
        results[f"{name}_sign"] = t_sig
        results[f"{name}_verify"] = t_ver
    _plot_charts(results)
    _size_table()
    print(f"\nCharts saved to: {RESULTS_DIR}")

def _plot_charts(results):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    kem_labels = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    sig_labels = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    x = np.arange(len(kem_labels))
    width = 0.25
    ax = axes[0]
    ax.bar(x - width, [results[f"{l}_keygen"] for l in kem_labels], width, label="KeyGen")
    ax.bar(x, [results[f"{l}_encaps"] for l in kem_labels], width, label="Encaps")
    ax.bar(x + width, [results[f"{l}_decaps"] for l in kem_labels], width, label="Decaps")
    ax.set_ylabel("Time (ms)"); ax.set_title("ML-KEM Performance (lower is better)")
    ax.set_xticks(x); ax.set_xticklabels(kem_labels, fontsize=9)
    ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
    x2 = np.arange(len(sig_labels))
    ax2 = axes[1]
    ax2.bar(x2 - width, [results[f"{l}_keygen"] for l in sig_labels], width, label="KeyGen")
    ax2.bar(x2, [results[f"{l}_sign"] for l in sig_labels], width, label="Sign")
    ax2.bar(x2 + width, [results[f"{l}_verify"] for l in sig_labels], width, label="Verify")
    ax2.set_ylabel("Time (ms)"); ax2.set_title("ML-DSA Performance (lower is better)")
    ax2.set_xticks(x2); ax2.set_xticklabels(sig_labels, fontsize=9)
    ax2.legend(fontsize=8); ax2.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "pqc_benchmark.png"), dpi=150)
    plt.close()

def _size_table():
    print("\n--- Key & Signature Sizes ---")
    print(f"{'Algorithm':20s} {'Pubkey':>8s} {'Privkey':>8s} {'Ct/Sig':>8s}")
    print("-" * 48)
    for name, kem in [("ML-KEM-512", ML_KEM_512), ("ML-KEM-768", ML_KEM_768), ("ML-KEM-1024", ML_KEM_1024)]:
        ek, dk = kem.keygen()
        _, ct = kem.encaps(ek)
        print(f"{name:20s} {len(ek):>8d} {len(dk):>8d} {len(ct):>8d}")
    for name, signer in [("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
        pk, sk = signer.keygen()
        sig = signer.sign(sk, b"test")
        print(f"{name:20s} {len(pk):>8d} {len(sk):>8d} {len(sig):>8d}")

if __name__ == "__main__":
    run_benchmark()
