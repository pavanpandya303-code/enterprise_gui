"""Certificate Builder — generate self-signed X.509 certificates.
Supports RSA, ECDSA, Ed25519 algorithms. Outputs PEM format."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

ALGORITHMS = ["RSA-2048", "RSA-4096", "ECDSA P-256", "ECDSA P-384", "Ed25519"]

def _make_key(algo):
    if algo == "RSA-2048":
        return rsa.generate_private_key(65537, 2048)
    elif algo == "RSA-4096":
        return rsa.generate_private_key(65537, 4096)
    elif algo == "ECDSA P-256":
        return ec.generate_private_key(ec.SECP256R1())
    elif algo == "ECDSA P-384":
        return ec.generate_private_key(ec.SECP384R1())
    elif algo == "Ed25519":
        return ed25519.Ed25519PrivateKey.generate()

def _hash_for_key(key):
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return None
    return hashes.SHA256()

def generate_cert(cn="example.com", org="My Organization", country="US",
                  algo="RSA-2048", validity_days=365):
    key = _make_key(algo)
    sub = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(sub).issuer_name(sub)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False))
    hash_algo = _hash_for_key(key)
    cert = builder.sign(key, hash_algo) if hash_algo else builder.sign(key)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, pem, key
