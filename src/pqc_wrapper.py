"""Unified PQC wrapper — swap implementations without changing client code.
Currently backed by kyber-py (ML-KEM) and dilithium-py (ML-DSA).
Drop-in for liboqs-python when available — just change the import here."""

from kyber_py.ml_kem.default_parameters import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from dilithium_py.ml_dsa.default_parameters import ML_DSA_44, ML_DSA_65, ML_DSA_87
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime, time, statistics

KEM_SUITES = {
    "ML-KEM-512":  ML_KEM_512,
    "ML-KEM-768":  ML_KEM_768,
    "ML-KEM-1024": ML_KEM_1024,
}
SIG_SUITES = {
    "ML-DSA-44": ML_DSA_44,
    "ML-DSA-65": ML_DSA_65,
    "ML-DSA-87": ML_DSA_87,
}

def kem_keygen(name):
    suite = KEM_SUITES[name]
    ek, dk = suite.keygen()
    return ek, dk

def kem_encaps(name, pubkey):
    suite = KEM_SUITES[name]
    shared, ct = suite.encaps(pubkey)
    return shared, ct

def kem_decaps(name, privkey, ct):
    suite = KEM_SUITES[name]
    return suite.decaps(privkey, ct)

def sig_keygen(name):
    suite = SIG_SUITES[name]
    return suite.keygen()

def sig_sign(name, sk, msg):
    suite = SIG_SUITES[name]
    return suite.sign(sk, msg)

def sig_verify(name, pk, msg, sig):
    suite = SIG_SUITES[name]
    return suite.verify(pk, msg, sig)

def hybrid_tls():
    c_xsk = x25519.X25519PrivateKey.generate()
    c_xpk = c_xsk.public_key().public_bytes_raw()
    c_ek, c_dk = ML_KEM_768.keygen()
    s_xsk = x25519.X25519PrivateKey.generate()
    s_xpk = s_xsk.public_key().public_bytes_raw()
    s_shared, ct = ML_KEM_768.encaps(c_ek)
    s_xshared = s_xsk.exchange(x25519.X25519PublicKey.from_public_bytes(c_xpk))
    s_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_TLS_1.3").derive(s_xshared + s_shared)
    c_xshared = c_xsk.exchange(x25519.X25519PublicKey.from_public_bytes(s_xpk))
    c_recovered = ML_KEM_768.decaps(c_dk, ct)
    c_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_TLS_1.3").derive(c_xshared + c_recovered)
    return c_key, s_key, dict(client_pub_x25519=len(c_xpk), client_pub_kem=len(c_ek),
                              server_pub_x25519=len(s_xpk), ct_size=len(ct))

def measure_kem(name, iters=3):
    ek, dk = kem_keygen(name)
    times = {"keygen": [], "encaps": [], "decaps": []}
    for _ in range(iters):
        t0 = time.perf_counter()
        kem_keygen(name)
        times["keygen"].append((time.perf_counter() - t0) * 1000)
    for _ in range(iters):
        t0 = time.perf_counter()
        kem_encaps(name, ek)
        times["encaps"].append((time.perf_counter() - t0) * 1000)
    for _ in range(iters):
        t0 = time.perf_counter()
        kem_decaps(name, dk, kem_encaps(name, ek)[1])
        times["decaps"].append((time.perf_counter() - t0) * 1000)
    return {k: round(statistics.mean(v), 2) for k, v in times.items()}

def measure_sig(name, iters=3):
    pk, sk = sig_keygen(name)
    msg = b"Benchmark message."
    times = {"keygen": [], "sign": [], "verify": []}
    for _ in range(iters):
        t0 = time.perf_counter()
        sig_keygen(name)
        times["keygen"].append((time.perf_counter() - t0) * 1000)
    for _ in range(iters):
        t0 = time.perf_counter()
        sig_sign(name, sk, msg)
        times["sign"].append((time.perf_counter() - t0) * 1000)
    for _ in range(iters):
        t0 = time.perf_counter()
        sig_verify(name, pk, msg, sig_sign(name, sk, msg))
        times["verify"].append((time.perf_counter() - t0) * 1000)
    return {k: round(statistics.mean(v), 2) for k, v in times.items()}

def _bench_op(iters, fn):
    """Run fn iters times, return list of ms timings."""
    vals = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        vals.append((time.perf_counter() - t0) * 1000)
    return vals

def measure_full_kem(name, iters=5):
    """Return dict of {op: [times_ms]} for full stats (min/max/stddev)."""
    ek, dk = kem_keygen(name)
    r = {}
    r["keygen"] = _bench_op(iters, lambda: kem_keygen(name))
    r["encaps"] = _bench_op(iters, lambda: kem_encaps(name, ek))
    r["decaps"] = _bench_op(iters, lambda: kem_decaps(name, dk, kem_encaps(name, ek)[1]))
    return r

def measure_full_sig(name, iters=5):
    pk, sk = sig_keygen(name)
    msg = b"Benchmark message."
    r = {}
    r["keygen"] = _bench_op(iters, lambda: sig_keygen(name))
    r["sign"] = _bench_op(iters, lambda: sig_sign(name, sk, msg))
    r["verify"] = _bench_op(iters, lambda: sig_verify(name, pk, msg, sig_sign(name, sk, msg)))
    return r

def measure_full_rsa(iters=5):
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    key = rsa.generate_private_key(65537, 2048)
    return {
        "keygen": _bench_op(iters, lambda: rsa.generate_private_key(65537, 2048)),
        "sign": _bench_op(iters, lambda: key.sign(b"msg", asym_padding.PKCS1v15(), hashes.SHA256())),
    }

def measure_full_ecc(iters=5):
    key = ec.generate_private_key(ec.SECP256R1())
    return {
        "keygen": _bench_op(iters, lambda: ec.generate_private_key(ec.SECP256R1())),
        "sign": _bench_op(iters, lambda: key.sign(b"msg", ec.ECDSA(hashes.SHA256()))),
    }

def describe_stats(values):
    """Return (avg, mini, maxi, std) as rounded floats."""
    avg = statistics.mean(values)
    mini = min(values)
    maxi = max(values)
    std = statistics.stdev(values) if len(values) > 1 else 0
    return round(avg, 2), round(mini, 2), round(maxi, 2), round(std, 2)

def generate_classical_key(algo):
    if algo == "RSA-2048":
        return rsa.generate_private_key(65537, 2048)
    elif algo == "RSA-4096":
        return rsa.generate_private_key(65537, 4096)
    elif algo == "ECDSA P-256":
        return ec.generate_private_key(ec.SECP256R1())

def make_self_signed_cert(key, cn="test.example.com", days=365, ca=False):
    sub = iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(sub).issuer_name(iss)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
               .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(key, hashes.SHA256())
