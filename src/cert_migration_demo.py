from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from dilithium_py.ml_dsa.default_parameters import ML_DSA_65, ML_DSA_87
import datetime

def run_cert_migration_demo():
    print("=" * 60)
    print("PQC MIGRATION TOOLKIT - CERTIFICATE MIGRATION DEMO")
    print("Classical vs Post-Quantum Certificate Size Comparison")
    print("=" * 60)
    print("\n--- Classical Certificates ---")
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
        print(f"  {label:25s} {sz:>6} bytes")
    pk_ed = ed25519.Ed25519PrivateKey.generate()
    print(f"  Ed25519 raw pubkey:      {len(pk_ed.public_key().public_bytes_raw()):>6} bytes")
    print("\n--- Post-Quantum Keys ---")
    for name, signer, level in [
        ("ML-DSA-65 (FIPS 204 Level 3)", ML_DSA_65, "192-bit"),
        ("ML-DSA-87 (FIPS 204 Level 5)", ML_DSA_87, "256-bit"),
    ]:
        pk, sk = signer.keygen()
        print(f"  {name:35s} pk={len(pk):>4}B, sk={len(sk):>4}B, security={level}")
    print("\n--- Key Takeaways ---")
    print("  1. PQC certs are 3-10x larger than classical certs")
    print("  2. TLS handshake size increases significantly")
    print("  3. Migration requires: larger MTU, more bandwidth")
    print("  4. Hybrid certs (RSA + ML-DSA) solve transition")
    print("=" * 60)

if __name__ == "__main__":
    run_cert_migration_demo()
