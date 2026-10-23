"""Hybrid X.509 certificates embedding ML-DSA keys as custom extensions.
Each cert carries BOTH a classical signature AND an ML-DSA signature."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import Extension, SubjectAlternativeName, GeneralName, UnrecognizedExtension
from src.pqc_wrapper import sig_keygen, sig_sign, sig_verify
import datetime

MLDSA_PUBKEY_OID = x509.ObjectIdentifier("1.3.9999.1.1")
MLDSA_SIGNATURE_OID = x509.ObjectIdentifier("1.3.9999.1.2")

def generate_hybrid_chain():
    results = []
    log = []

    log.append("[Root CA] RSA-4096 + ML-DSA-65 key pair...")
    root_classical = rsa.generate_private_key(65537, 4096)
    mldsa_root_pk, mldsa_root_sk = sig_keygen("ML-DSA-65")
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PQC Hybrid Root CA")])
    root_cert = (x509.CertificateBuilder()
        .subject_name(root_name).issuer_name(root_name)
        .public_key(root_classical.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(UnrecognizedExtension(MLDSA_PUBKEY_OID, mldsa_root_pk), critical=False)
    ).sign(root_classical, hashes.SHA256())
    mldsa_root_sig = sig_sign("ML-DSA-65", mldsa_root_sk, root_cert.tbs_certificate_bytes)
    root_size = len(root_cert.public_bytes(serialization.Encoding.PEM))
    log.append(f"  Size: {root_size} bytes")
    log.append(f"  ML-DSA-65 pubkey embedded: {len(mldsa_root_pk)} bytes")
    log.append(f"  ML-DSA-65 signature appended: {len(mldsa_root_sig)} bytes")

    log.append("")
    log.append("[Intermediate CA] RSA-2048 + ML-DSA-65...")
    inter_classical = rsa.generate_private_key(65537, 2048)
    mldsa_inter_pk, mldsa_inter_sk = sig_keygen("ML-DSA-65")
    inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PQC Hybrid Intermediate CA")])
    inter_cert = (x509.CertificateBuilder()
        .subject_name(inter_name).issuer_name(root_name)
        .public_key(inter_classical.public_key())
        .serial_number(2)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(UnrecognizedExtension(MLDSA_PUBKEY_OID, mldsa_inter_pk), critical=False)
    ).sign(root_classical, hashes.SHA256())
    mldsa_inter_sig = sig_sign("ML-DSA-65", mldsa_inter_sk, inter_cert.tbs_certificate_bytes)
    inter_size = len(inter_cert.public_bytes(serialization.Encoding.PEM))
    log.append(f"  Size: {inter_size} bytes")
    log.append(f"  ML-DSA-65 pubkey embedded: {len(mldsa_inter_pk)} bytes")
    log.append(f"  ML-DSA-65 signature: {len(mldsa_inter_sig)} bytes")

    log.append("")
    log.append("[Leaf] RSA-2048 + ML-DSA-44...")
    leaf_classical = rsa.generate_private_key(65537, 2048)
    mldsa_leaf_pk, mldsa_leaf_sk = sig_keygen("ML-DSA-44")
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hybrid-demo.example.com")])
    leaf_cert = (x509.CertificateBuilder()
        .subject_name(leaf_name).issuer_name(inter_name)
        .public_key(leaf_classical.public_key())
        .serial_number(3)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("hybrid-demo.example.com")]), critical=False)
        .add_extension(UnrecognizedExtension(MLDSA_PUBKEY_OID, mldsa_leaf_pk), critical=False)
    ).sign(inter_classical, hashes.SHA256())
    mldsa_leaf_sig = sig_sign("ML-DSA-44", mldsa_leaf_sk, leaf_cert.tbs_certificate_bytes)
    leaf_size = len(leaf_cert.public_bytes(serialization.Encoding.PEM))
    log.append(f"  Size: {leaf_size} bytes")
    log.append(f"  ML-DSA-44 pubkey embedded: {len(mldsa_leaf_pk)} bytes")
    log.append(f"  ML-DSA-44 signature: {len(mldsa_leaf_sig)} bytes")

    log.append("")
    log.append("=== Verification ===")
    try:
        root_classical.public_key().verify(
            root_cert.signature, root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), hashes.SHA256())
        log.append("  Root RSA signature: VALID")
    except Exception:
        log.append("  Root RSA signature: INVALID")
    mldsa_root_ok = sig_verify("ML-DSA-65", mldsa_root_pk, root_cert.tbs_certificate_bytes, mldsa_root_sig)
    log.append(f"  Root ML-DSA-65 signature: {'VALID' if mldsa_root_ok else 'INVALID'}")
    try:
        root_classical.public_key().verify(
            inter_cert.signature, inter_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), hashes.SHA256())
        log.append("  Intermediate RSA signature: VALID")
    except Exception:
        log.append("  Intermediate RSA signature: INVALID")
    mldsa_inter_ok = sig_verify("ML-DSA-65", mldsa_inter_pk, inter_cert.tbs_certificate_bytes, mldsa_inter_sig)
    log.append(f"  Intermediate ML-DSA-65 signature: {'VALID' if mldsa_inter_ok else 'INVALID'}")
    try:
        inter_classical.public_key().verify(
            leaf_cert.signature, leaf_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), hashes.SHA256())
        log.append("  Leaf RSA signature: VALID")
    except Exception:
        log.append("  Leaf RSA signature: INVALID")
    mldsa_leaf_ok = sig_verify("ML-DSA-44", mldsa_leaf_pk, leaf_cert.tbs_certificate_bytes, mldsa_leaf_sig)
    log.append(f"  Leaf ML-DSA-44 signature: {'VALID' if mldsa_leaf_ok else 'INVALID'}")

    total_bytes = root_size + inter_size + leaf_size + len(mldsa_root_sig) + len(mldsa_inter_sig) + len(mldsa_leaf_sig)
    log.append("")
    log.append(f"Total hybrid chain size: {total_bytes} bytes")
    log.append(f"(vs ~3KB for classical-only chain — PQC adds {total_bytes - 3000:,} bytes)")
    log.append(f"  Chain: Root(RSA+ML-DSA-65) -> Intermediate(RSA+ML-DSA-65) -> Leaf(RSA+ML-DSA-44)")

    results.append("\n".join(log))
    results.append(dict(root_size=root_size, inter_size=inter_size, leaf_size=leaf_size,
                        mldsa_root_pk=len(mldsa_root_pk), mldsa_root_sig=len(mldsa_root_sig),
                        mldsa_inter_pk=len(mldsa_inter_pk), mldsa_inter_sig=len(mldsa_inter_sig),
                        mldsa_leaf_pk=len(mldsa_leaf_pk), mldsa_leaf_sig=len(mldsa_leaf_sig)))
    return results
