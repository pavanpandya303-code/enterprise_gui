"""Harvest Now, Decrypt Later attack simulation.
Demonstrates why quantum-safe migration is urgent:
1. Encrypt data with small RSA (factorizable) to show the vulnerability
2. Record ciphertext now, factor the key, decrypt later
3. Show that PQC prevents this attack entirely"""

from src.pqc_wrapper import kem_keygen, kem_encaps, kem_decaps
import time, random

def _generate_small_rsa(bits=64):
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e != 0:
            d = pow(e, -1, phi)
            return (n, e, d), (n, e)

def _gen_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n

def _is_prime(n, k=5):
    if n < 2:
        return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _factor_rsa(n):
    i = 2
    while i * i <= n:
        if n % i == 0:
            return i, n // i
        i += 1 if i == 2 else 2
    return None, None

def _simple_pad(msg, n_bytes):
    """Simple padding: 0x00 0x02 <random> 0x00 <message>, for tiny RSA demo."""
    if len(msg) > n_bytes - 3:
        return msg[:n_bytes - 3]
    pad_len = n_bytes - len(msg) - 3
    padding = bytes([0xFF] * pad_len)
    return b"\x00\x02" + padding + b"\x00" + msg

def run_attack_demo(rsa_bits=32):
    lines = []
    lines.append("=" * 65)
    lines.append("  HARVEST NOW, DECRYPT LATER — Attack Simulation")
    lines.append("=" * 65)
    lines.append("")
    lines.append("  Alice sends a secret message to Bob.")
    lines.append("  Eve (attacker) records the encrypted traffic NOW.")
    lines.append("  Later, when Eve gains the ability to break RSA,")
    lines.append("  she decrypts the message she recorded earlier.")
    lines.append("")

    msg = b"SECRET: Launch codes 2026-07-18 12:00 UTC"
    lines.append(f"  Alice's secret message:")
    lines.append(f"    \"{msg.decode()}\"")
    lines.append("")

    lines.append(f"─── Step 1: Alice encrypts with SMALL RSA ({rsa_bits}-bit) ───")
    t0 = time.perf_counter()
    priv, pub = _generate_small_rsa(rsa_bits)
    keygen_time = (time.perf_counter() - t0) * 1000
    n, e, d = priv
    lines.append(f"  Alice generates RSA-{rsa_bits} keypair ({keygen_time:.1f}ms)")
    lines.append(f"  Public key (n={n}, e={e})")
    lines.append(f"  n bits = {n.bit_length()}")
    n_bytes = (n.bit_length() + 7) // 8
    short_msg = b"TOP SECRET"[:n_bytes - 3]
    padded_msg = _simple_pad(short_msg, n_bytes)
    ciphertext_int = pow(int.from_bytes(padded_msg, 'big'), e, n)
    ciphertext = ciphertext_int.to_bytes(n_bytes, 'big')
    lines.append(f"")
    lines.append(f"  Encrypted message (RSA direct, {n_bytes}B block): {ciphertext.hex()}")
    lines.append(f"")
    lines.append(f"  Eve records the ciphertext and wrapped AES key NOW.")
    lines.append(f"  She cannot yet decrypt (RSA-{rsa_bits} is small, but the PRINCIPLE")
    lines.append(f"  is the same as RSA-2048 against quantum computers).")
    lines.append("")

    lines.append(f"─── Step 2: Later — Eve factors the RSA modulus ───")
    lines.append(f"  With a quantum computer (Shor's algorithm),")
    lines.append(f"  RSA-2048 can be factored in MINUTES instead of")
    lines.append(f"  millions of years on a classical computer.")
    lines.append(f"")
    lines.append(f"  Demonstrating with classical factoring (trial division):")
    t0 = time.perf_counter()
    p, q = _factor_rsa(n)
    factor_time = (time.perf_counter() - t0) * 1000
    if p and q:
        lines.append(f"  Factored n = {p} x {q} ({factor_time:.1f}ms)")
        phi = (p - 1) * (q - 1)
        recovered_d = pow(e, -1, phi)
        recovered_int = pow(ciphertext_int, recovered_d, n)
        recovered_bytes = recovered_int.to_bytes(n_bytes, 'big')
        null_idx = recovered_bytes.rfind(b'\x00')
        recovered_msg = recovered_bytes[null_idx + 1:] if null_idx >= 0 else recovered_bytes
        lines.append(f"  Decrypted message: \"{recovered_msg.decode()}\"")
        lines.append(f"  Eve successfully decrypted the recorded traffic!")
        lines.append(f"")
        lines.append(f"  This demonstrates the Harvest Now Decrypt Later threat.")
    else:
        lines.append(f"  Could not factor (key too large for simple trial division).")
    lines.append("")

    lines.append("─── Step 3: What if Alice had used PQC? ───")
    lines.append(f"  Alice uses ML-KEM-768 instead of RSA.")
    lines.append(f"  Even with a quantum computer, Eve could NOT decrypt")
    lines.append(f"  the recorded traffic — lattice problems are hard for")
    lines.append(f"  both classical and quantum computers.")
    lines.append(f"")
    ek, dk = kem_keygen("ML-KEM-768")
    ss, ct = kem_encaps("ML-KEM-768", ek)
    recovered = kem_decaps("ML-KEM-768", dk, ct)
    lines.append(f"  ML-KEM-768 key exchange: {'PASS' if ss == recovered else 'FAIL'}")
    lines.append(f"  Ciphertext: {ct.hex()[:48]}...")
    lines.append(f"  Shared secret: {ss.hex()[:32]}...")
    lines.append(f"")
    lines.append(f"  With PQC, even if Eve records everything now,")
    lines.append(f"  she will NEVER be able to decrypt it.")
    lines.append(f"  This is why migration is urgent.")
    lines.append("")
    lines.append("=" * 65)
    lines.append("  Summary")
    lines.append("=" * 65)
    lines.append(f"  • Hackers record encrypted traffic TODAY")
    lines.append(f"  • They wait for quantum computers to decrypt it LATER")
    lines.append(f"  • PQC prevents this by using quantum-hard math")
    lines.append(f"  • Hybrid (classical + PQC) protects both ways")
    lines.append("=" * 65)

    return "\n".join(lines)
