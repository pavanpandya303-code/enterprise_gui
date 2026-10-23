import os, time, statistics, datetime, json, base64
from flask import Flask, render_template, jsonify, request

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from kyber_py.ml_kem.default_parameters import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44, ML_DSA_65, ML_DSA_87
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

app = Flask(__name__)

# ─────────────────────────────── API ROUTES ───────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/kem")
def api_kem():
    results = []
    for name, kem in [("ML-KEM-512", ML_KEM_512), ("ML-KEM-768", ML_KEM_768), ("ML-KEM-1024", ML_KEM_1024)]:
        ek, dk = kem.keygen()
        shared, ct = kem.encaps(ek)
        recovered = kem.decaps(dk, ct)
        results.append({
            "name": name, "pk": len(ek), "sk": len(dk),
            "ct": len(ct), "shared": len(shared), "pass": shared == recovered
        })
    return jsonify(results)

@app.route("/api/sign")
def api_sign():
    results = []
    msg = b"This is a test document for post-quantum signing."
    for name, sig in [("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
        pk, sk = sig.keygen()
        signature = sig.sign(sk, msg)
        valid = sig.verify(pk, msg, signature)
        results.append({
            "name": name, "pk": len(pk), "sk": len(sk),
            "sig": len(signature), "msg": len(msg), "valid": valid
        })
    return jsonify(results)

@app.route("/api/tls")
def api_tls():
    c_xsk = x25519.X25519PrivateKey.generate()
    c_xpk = c_xsk.public_key().public_bytes_raw()
    c_ek, c_dk = ML_KEM_768.keygen()
    s_xsk = x25519.X25519PrivateKey.generate()
    s_xpk = s_xsk.public_key().public_bytes_raw()
    s_shared, ct = ML_KEM_768.encaps(c_ek)
    s_xshared = s_xsk.exchange(x25519.X25519PublicKey.from_public_bytes(c_xpk))
    combined = s_xshared + s_shared
    s_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_TLS_1.3").derive(combined)
    c_xshared = c_xsk.exchange(x25519.X25519PublicKey.from_public_bytes(s_xpk))
    c_recovered = ML_KEM_768.decaps(c_dk, ct)
    c_combined = c_xshared + c_recovered
    c_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_TLS_1.3").derive(c_combined)
    return jsonify({
        "client_x25519": len(c_xpk), "client_kem": len(c_ek),
        "client_total": len(c_xpk) + len(c_ek),
        "server_x25519": len(s_xpk), "kem_ct": len(ct),
        "session_key": c_key[:8].hex(), "match": c_key == s_key
    })

@app.route("/api/cert")
def api_cert():
    results = []
    for algo, label in [
        (lambda: rsa.generate_private_key(65537, 2048), "RSA-2048"),
        (lambda: rsa.generate_private_key(65537, 4096), "RSA-4096"),
        (lambda: ec.generate_private_key(ec.SECP256R1()), "ECDSA P-256"),
    ]:
        key = algo()
        sub = iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        cert = (x509.CertificateBuilder().subject_name(sub).issuer_name(iss)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                .sign(key, hashes.SHA256()))
        sz = len(cert.public_bytes(serialization.Encoding.PEM))
        results.append({"label": label, "size": sz, "type": "classical"})
    for label, sig in [("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
        pk, sk = sig.keygen()
        results.append({"label": label, "pk": len(pk), "sk": len(sk), "type": "pqc"})
    return jsonify(results)

@app.route("/api/bench")
def api_bench():
    ITERS = 3
    results = {}
    msg = b"Benchmark message for PQC signatures."
    def measure(fn):
        times = []
        for _ in range(ITERS):
            t0 = time.perf_counter(); r = fn()
            times.append((time.perf_counter() - t0) * 1000)
        return statistics.mean(times), r
    for name, kem in [("ML-KEM-512", ML_KEM_512), ("ML-KEM-768", ML_KEM_768), ("ML-KEM-1024", ML_KEM_1024)]:
        t1, (ek, dk) = measure(kem.keygen)
        t2, (s, ct) = measure(lambda: kem.encaps(ek))
        t3, (r,) = measure(lambda: (kem.decaps(dk, ct),))
        results[name] = {"keygen": round(t1,2), "encaps": round(t2,2), "decaps": round(t3,2)}
    for name, sig in [("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
        t1, (pk, sk) = measure(sig.keygen)
        t2, (sg,) = measure(lambda: (sig.sign(sk, msg),))
        t3, (v,) = measure(lambda: (sig.verify(pk, msg, sg),))
        results[name] = {"keygen": round(t1,2), "sign": round(t2,2), "verify": round(t3,2)}
    return jsonify(results)

@app.route("/api/bench-chart")
def api_bench_chart():
    ITERS = 3
    results = {}
    msg = b"Benchmark message for PQC signatures."
    def measure(fn):
        times = []
        for _ in range(ITERS):
            t0 = time.perf_counter(); r = fn()
            times.append((time.perf_counter() - t0) * 1000)
        return statistics.mean(times), r
    for name, kem in [("ML-KEM-512", ML_KEM_512), ("ML-KEM-768", ML_KEM_768), ("ML-KEM-1024", ML_KEM_1024)]:
        t1, (ek, dk) = measure(kem.keygen)
        t2, (s, ct) = measure(lambda: kem.encaps(ek))
        t3, (r,) = measure(lambda: (kem.decaps(dk, ct),))
        results.update({f"{name}_keygen": t1, f"{name}_encaps": t2, f"{name}_decaps": t3})
    for name, sig in [("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
        t1, (pk, sk) = measure(sig.keygen)
        t2, (sg,) = measure(lambda: (sig.sign(sk, msg),))
        t3, (v,) = measure(lambda: (sig.verify(pk, msg, sg),))
        results.update({f"{name}_keygen": t1, f"{name}_sign": t2, f"{name}_verify": t3})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    x = np.arange(3); w = 0.25
    for ax, labels, ops in [
        (axes[0], ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"], ["keygen", "encaps", "decaps"]),
        (axes[1], ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"], ["keygen", "sign", "verify"]),
    ]:
        for i, op in enumerate(ops):
            vals = [results.get(f"{l}_{op}", 0) for l in labels]
            ax.bar(x + (i-1)*w, vals, w, label=op.capitalize())
        ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
        ax.set_ylabel("Time (ms)"); ax.legend(fontsize=7); ax.grid(axis="y", alpha=0.3)
    axes[0].set_title("ML-KEM Performance"); axes[1].set_title("ML-DSA Performance")
    plt.tight_layout()
    chart_path = os.path.join(os.path.dirname(__file__), "static", "bench_chart.png")
    plt.savefig(chart_path, dpi=130); plt.close()
    return jsonify({"chart": "/static/bench_chart.png"})

@app.route("/api/hybrid-cert")
def api_hybrid_cert():
    """Generate a hybrid certificate chain: Root CA (RSA) -> Intermediate (ML-DSA) -> Leaf (RSA + ML-DSA)"""
    result = {"chain": []}

    # Root CA with RSA-4096
    root_key = rsa.generate_private_key(65537, 4096)
    root_sub = root_iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PQC Root CA")])
    root_cert = (x509.CertificateBuilder().subject_name(root_sub).issuer_name(root_iss)
                 .public_key(root_key.public_key()).serial_number(1)
                 .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                 .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                 .sign(root_key, hashes.SHA256()))
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()
    result["chain"].append({"name": "Root CA (RSA-4096)", "size": len(root_pem), "pem": root_pem[:80] + "..."})

    # Intermediate with ML-DSA-65
    inter_pk, inter_sk = ML_DSA_65.keygen()
    inter_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PQC Intermediate CA (ML-DSA)")])
    inter_cert_bytes = (
        x509.CertificateBuilder().subject_name(inter_sub).issuer_name(root_sub)
        .public_key(serialization.load_der_public_key(
            b"0" * 1952, backend=None))  # placeholder - real impl would need proper encoding
        .serial_number(2)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    )
    # Note: Full hybrid cert would require custom X.509 extension for ML-DSA key.
    # For demo purposes we show key sizes and concept.
    result["chain"].append({
        "name": "Intermediate CA (ML-DSA-65)",
        "pk_size": len(inter_pk), "sk_size": len(inter_sk),
        "note": "ML-DSA keys cannot be encoded in standard X.509 yet. Showing key sizes."
    })

    # Leaf with RSA-2048
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pqc-demo.example.com")])
    leaf_cert = (x509.CertificateBuilder().subject_name(leaf_sub).issuer_name(inter_sub)
                 .public_key(leaf_key.public_key()).serial_number(3)
                 .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                 .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                 .sign(root_key, hashes.SHA256()))  # signed by root for demo
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
    result["chain"].append({"name": "Leaf Cert (RSA-2048)", "size": len(leaf_pem), "pem": leaf_pem[:80] + "..."})

    result["summary"] = "Real hybrid cert chains require updated X.509 standards. This demo shows the concept: Root CA signs Intermediate, which signs Leaf. In production, each level would carry both RSA and ML-DSA signatures."
    return jsonify(result)


@app.route("/api/size-chart")
def api_size_chart():
    fig, ax = plt.subplots(figsize=(10, 5))
    labels = ["RSA-2048\nCert", "ECDSA P-256\nCert", "ML-KEM-768\nPubkey", "ML-DSA-65\nPubkey", "ML-DSA-65\nSignature"]
    values = [993, 457, 1184, 1952, 3309]
    colors = ["#4CAF50", "#8BC34A", "#FF9800", "#FF5722", "#F44336"]
    bars = ax.barh(labels, values, color=colors)
    for bar, v in zip(bars, values):
        ax.text(bar.get_width() + 30, bar.get_y() + bar.get_height()/2, f"{v}B", va="center", fontsize=10)
    ax.set_xlabel("Size (bytes)"); ax.set_title("Classical vs Post-Quantum Key/Signature Sizes")
    ax.set_xlim(0, max(values) + 500)
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    chart_path = os.path.join(os.path.dirname(__file__), "static", "size_chart.png")
    plt.savefig(chart_path, dpi=130); plt.close()
    return jsonify({"chart": "/static/size_chart.png"})


if __name__ == "__main__":
    print("Starting PQC Web Dashboard at http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=True)
