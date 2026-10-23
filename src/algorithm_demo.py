"""Algorithm Demonstration Engine — applies user-selected cryptographic
algorithms to arbitrary user text.

Purely computational, no GUI. Used by the "Crypto Playground" tab in
enterprise_gui.py, but kept here so it is testable and reusable.

Supported algorithm kinds:
  * hash       — SHA-1, SHA-256, SHA-384, MD5
  * symmetric  — AES-128, AES-256, ChaCha20 (authenticated encryption)
  * encrypt    — RSA-2048, RSA-4096 (public-key encryption, OAEP)
  * kem        — ML-KEM-512/768/1024 (key exchange + AES-GCM text encryption)
  * sign       — ECDSA P-256, ECDSA P-384, Ed25519, ML-DSA-44/65/87
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.pqc_wrapper import (kem_keygen, kem_encaps, kem_decaps,
                             sig_keygen, sig_sign, sig_verify)


# ──────────────────────────────────────────────────────────────────────
# Registry: algorithm name -> (kind, group label)
# ──────────────────────────────────────────────────────────────────────
ALGORITHMS: Dict[str, str] = {
    # name -> kind
    "SHA-1": "hash",
    "SHA-256": "hash",
    "SHA-384": "hash",
    "MD5": "hash",
    "AES-128": "symmetric",
    "AES-256": "symmetric",
    "ChaCha20": "symmetric",
    "RSA-2048": "encrypt",
    "RSA-4096": "encrypt",
    "ML-KEM-512": "kem",
    "ML-KEM-768": "kem",
    "ML-KEM-1024": "kem",
    "ECDSA P-256": "sign",
    "ECDSA P-384": "sign",
    "Ed25519": "sign",
    "ML-DSA-44": "sign",
    "ML-DSA-65": "sign",
    "ML-DSA-87": "sign",
}

GROUPS: List[List[str]] = [
    ["SHA-1", "SHA-256", "SHA-384", "MD5"],
    ["AES-128", "AES-256", "ChaCha20"],
    ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    ["ECDSA P-256", "ECDSA P-384", "Ed25519"],
    ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    ["RSA-2048", "RSA-4096"],
]

GROUP_NAMES: Dict[str, str] = {
    "hash": "Hashing (integrity)",
    "symmetric": "Symmetric Encryption",
    "encrypt": "RSA Public-Key Encryption",
    "kem": "ML-KEM Key Exchange",
    "sign": "Digital Signatures",
}


def _hex(b: bytes) -> str:
    return b.hex()


# ── Individual demonstrations ─────────────────────────────────────────
def demo_hash(name: str, text: str) -> str:
    """Compute a digest of the text and show the raw byte length."""
    algo = name.lower().replace("-", "").replace(" ", "")
    try:
        digest = hashlib.new(algo, text.encode()).digest()
    except ValueError:
        return f"{name}: not available in this Python build (FIPS mode)."
    hexdigest = digest.hex()
    return (f"  Hash ({name}):\n"
            f"    Output : {hexdigest}\n"
            f"    Length : {len(hexdigest)} hex chars / {len(digest)} bytes")


def demo_symmetric(name: str, text: str) -> str:
    """AES-128/256 or ChaCha20 authenticated encryption roundtrip."""
    key_len = 16 if "128" in name else 32
    key = os.urandom(key_len)
    nonce = os.urandom(12)
    if "ChaCha" in name:
        cipher = ChaCha20Poly1305(key)
    else:
        cipher = AESGCM(key)
    ct = cipher.encrypt(nonce, text.encode(), None)
    recovered = cipher.decrypt(nonce, ct, None).decode()
    match = "MATCH" if recovered == text else "MISMATCH"
    return (f"  {name} (symmetric):\n"
            f"    Key      : {_hex(key)}\n"
            f"    Nonce    : {_hex(nonce)}\n"
            f"    Ciphertxt: {_hex(ct)} ({len(ct)} bytes)\n"
            f"    Decrypted: \"{recovered}\"  [{match}]")


def demo_encrypt_rsa(name: str, text: str) -> str:
    """RSA public-key encryption (OAEP-SHA256) roundtrip."""
    bits = 2048 if "2048" in name else 4096
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    try:
        ct = key.public_key().encrypt(
            text.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(), label=None))
    except ValueError as e:
        return (f"  {name}: text too long for one RSA block "
                f"(max ~{bits//8 - 66} bytes). Got: {e.__class__.__name__}")
    recovered = key.decrypt(ct, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
        label=None)).decode()
    match = "MATCH" if recovered == text else "MISMATCH"
    return (f"  {name} (public-key encryption, OAEP):\n"
            f"    Pubkey   : {bits}-bit RSA\n"
            f"    Ciphertxt: {_hex(ct)} ({len(ct)} bytes)\n"
            f"    Decrypted: \"{recovered}\"  [{match}]")


def demo_kem(name: str, text: str) -> str:
    """ML-KEM: establish a shared secret, then AES-GCM-encrypt the text."""
    ek, dk = kem_keygen(name)
    shared_sender, ct_kem = kem_encaps(name, ek)

    def _aes_key(shared: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"KEM-DEMO-AES").derive(shared)

    nonce = os.urandom(12)
    enc_text = AESGCM(_aes_key(shared_sender)).encrypt(
        nonce, text.encode(), None)

    shared_recovered = kem_decaps(name, dk, ct_kem)
    plaintext = AESGCM(_aes_key(shared_recovered)).decrypt(
        nonce, enc_text, None).decode()

    match = "MATCH" if plaintext == text else "MISMATCH"
    return (f"  {name} (key exchange + AES-256-GCM):\n"
            f"    Pubkey     : {len(ek)} bytes\n"
            f"    KEM ct     : {len(ct_kem)} bytes\n"
            f"    Shared     : {_hex(shared_sender[:8])}...\n"
            f"    Encrypted  : \"{_hex(enc_text)}\" ({len(enc_text)} bytes)\n"
            f"    Decrypted  : \"{plaintext}\"  [{match}]")


def demo_sign(name: str, text: str) -> str:
    """Sign and verify the text using the selected signature scheme."""
    data = text.encode()

    if name == "Ed25519":
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sig = sk.sign(data)
        valid = _verify_ok(pk.verify, data, sig)
        sig_size = len(sig)
    elif name.startswith("ECDSA"):
        curve = ec.SECP384R1() if "P-384" in name else ec.SECP256R1()
        sk = ec.generate_private_key(curve)
        pk = sk.public_key()
        sig = sk.sign(data, ec.ECDSA(hashes.SHA256()))
        valid = _verify_ok(lambda d, s: pk.verify(s, d, ec.ECDSA(hashes.SHA256())),
                           data, sig)
        sig_size = len(sig)
    elif name.startswith("ML-DSA"):
        pk, sk = sig_keygen(name)
        sig = sig_sign(name, sk, data)
        valid = sig_verify(name, pk, data, sig)
        sig_size = len(sig)
    else:
        return f"  {name}: unsupported signature scheme."

    status = "VALID ✓" if valid else "INVALID ✗"
    return (f"  {name} (signature):\n"
            f"    Signed msg : \"{text}\"\n"
            f"    Signature  : {_hex(sig[:24])}... ({sig_size} bytes)\n"
            f"    Verify     : {status}")


def _verify_ok(fn, data, sig) -> bool:
    try:
        fn(data, sig)
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────────────────────────────
def run_demo(name: str, text: str) -> str:
    """Run the demonstration for one algorithm and return a result string."""
    kind = ALGORITHMS.get(name)
    if kind is None:
        return f"  {name}: not a demonstrable algorithm."
    if not text:
        return f"  {name}: please enter some text first."
    try:
        if kind == "hash":
            return demo_hash(name, text)
        if kind == "symmetric":
            return demo_symmetric(name, text)
        if kind == "encrypt":
            return demo_encrypt_rsa(name, text)
        if kind == "kem":
            return demo_kem(name, text)
        if kind == "sign":
            return demo_sign(name, text)
        return f"  {name}: unsupported kind."
    except Exception as e:  # noqa: BLE001 — show any crypto error to user
        return f"  {name}: error → {e.__class__.__name__}: {e}"


def run_multi(names: List[str], text: str) -> str:
    """Run several algorithms in sequence and join the output."""
    blocks = []
    for name in names:
        blocks.append(run_demo(name, text))
    return "\n\n".join(blocks)


# ──────────────────────────────────────────────────────────────────────
# Cascade (chaining) mode — each algorithm encrypts the previous output,
# decryption runs in reverse order. Only reversible algorithms can be
# chained: symmetric ciphers, RSA, and ML-KEM.
# ──────────────────────────────────────────────────────────────────────
REVERSIBLE_KINDS = ("symmetric", "encrypt", "kem")
REVERSIBLE_ALGORITHMS = [name for name, kind in ALGORITHMS.items()
                         if kind in REVERSIBLE_KINDS]


def _step_encrypt(algo: str, data: bytes) -> tuple[bytes, dict]:
    """Encrypt ``data`` with one algorithm.

    Returns ``(output_bytes, context)`` where ``context`` holds everything
    needed to decrypt (keys / private keys), kept out of the ciphertext.
    """
    kind = ALGORITHMS[algo]
    if kind == "symmetric":
        key_len = 16 if "128" in algo else 32
        key = os.urandom(key_len)
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key) if "ChaCha" in algo else AESGCM(key)
        ct = cipher.encrypt(nonce, data, None)
        return nonce + ct, {"kind": "symmetric", "key": key}
    if kind == "encrypt":
        bits = 2048 if "2048" in algo else 4096
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        ct = priv.public_key().encrypt(
            data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                               algorithm=hashes.SHA256(), label=None))
        return ct, {"kind": "rsa", "priv": priv}
    if kind == "kem":
        ek, dk = kem_keygen(algo)
        shared, ct_kem = kem_encaps(algo, ek)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"CASCADE-AES").derive(shared)
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, data, None)
        return ct_kem + nonce + ct, {"kind": "kem", "dk": dk,
                                     "ct_len": len(ct_kem)}
    raise ValueError(f"{algo} is not reversible (cannot be chained).")


def _step_decrypt(algo: str, data: bytes, ctx: dict) -> bytes:
    """Reverse one cascade step using its stored context."""
    kind = ctx["kind"]
    if kind == "symmetric":
        cipher = ChaCha20Poly1305(ctx["key"]) if "ChaCha" in algo \
            else AESGCM(ctx["key"])
        return cipher.decrypt(data[:12], data[12:], None)
    if kind == "rsa":
        return ctx["priv"].decrypt(
            data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                               algorithm=hashes.SHA256(), label=None))
    if kind == "kem":
        ct_len = ctx["ct_len"]
        shared = kem_decaps(algo, ctx["dk"], data[:ct_len])
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"CASCADE-AES").derive(shared)
        return AESGCM(aes_key).decrypt(data[ct_len:ct_len + 12],
                                       data[ct_len + 12:], None)
    raise ValueError("Unknown cascade context.")


def cascade_encrypt(names: List[str], data: bytes
                    ) -> tuple[List[bytes], List[dict]]:
    """Chain-encrypt ``data`` through each algorithm in ``names``.

    Returns ``(stages, contexts)`` where ``stages[i]`` is the ciphertext
    after applying algorithm ``names[i]`` to the previous stage (stages[0]
    encrypts the original data). ``contexts[i]`` holds the keys needed to
    decrypt stage ``i``.
    """
    stages: List[bytes] = []
    contexts: List[dict] = []
    current = data
    for algo in names:
        try:
            out, ctx = _step_encrypt(algo, current)
        except ValueError as e:
            raise ValueError(
                f"Chain stopped at {algo}: {e} "
                f"(input was {len(current)} bytes).") from e
        stages.append(out)
        contexts.append(ctx)
        current = out
    return stages, contexts


def cascade_decrypt(names: List[str], stages: List[bytes],
                    contexts: List[dict]) -> List[bytes]:
    """Reverse the chain.

    Returns a list starting with the outermost ciphertext and ending with
    the fully decrypted original data.
    """
    revealed = [stages[-1]]
    current = stages[-1]
    for i in range(len(names) - 1, -1, -1):
        current = _step_decrypt(names[i], current, contexts[i])
        revealed.append(current)
    return revealed


def cascade_verify(names: List[str], stages: List[bytes],
                   revealed: List[bytes]) -> List[str]:
    """Check each revealed intermediate matches the stored stage.

    ``revealed`` runs from outermost ciphertext down to the original data,
    while ``stages`` runs from the first layer outward, so stage ``i`` must
    equal ``revealed[n - 1 - i]``. Returns per-layer messages.
    """
    checks = []
    n = len(stages)
    for i, stage in enumerate(stages):
        ok = revealed[n - 1 - i] == stage
        checks.append(f"Layer {i + 1} ({names[i]}): "
                      f"{'MATCH ✓' if ok else 'MISMATCH ✗'}")
    return checks


if __name__ == "__main__":
    # Self-test
    sample = "Hello, post-quantum world!"
    for alg in ["SHA-256", "AES-256", "ML-KEM-768", "ML-DSA-65", "RSA-2048"]:
        print(run_demo(alg, sample))
        print("=" * 60)
