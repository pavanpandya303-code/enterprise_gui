"""Wire-format inspection — byte-level hex dump with annotation.
Shows the internal structure of PQC keys, ciphertexts, and signatures."""

from src.pqc_wrapper import kem_keygen, kem_encaps, sig_keygen, sig_sign

def _hexdump(label, data, width=32):
    lines = [f"  ┌─ {label} ({len(data)} bytes) ─{'─' * (width * 3 + 6)}"]
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        addr = f"{i:04x}"
        lines.append(f"  │{addr}  {hex_part:<{width*3}}{'  ' + ascii_part}")
    lines.append(f"  └{'─' * (len(lines[0]) - 2)}")
    return "\n".join(lines)

def _annotate(label, data, annotations):
    lines = [f"  ┌─ {label} ({len(data)} bytes)"]
    pos = 0
    for field_name, field_len in annotations:
        chunk = data[pos:pos+field_len]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"  │{field_name:20s}  [{hex_part}] ({field_len} bytes)")
        pos += field_len
        if pos >= len(data):
            break
    lines.append(f"  └{'─' * 50}")
    return "\n".join(lines)

def view_binary(label, data, width=8):
    """Return binary representation of data (0/1 bits)."""
    lines = [f"  ┌─ {label} ({len(data)} bytes, {len(data)*8} bits)"]
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        bits = " ".join(f"{b:08b}" for b in chunk)
        addr = f"{i:04x}"
        lines.append(f"  │{addr}  {bits}")
    lines.append(f"  │")
    return "\n".join(lines)

def inspect_all():
    """Return dict with hex, annotate, binary, size_table strings."""
    ek, dk = kem_keygen("ML-KEM-768")
    _, ct = kem_encaps("ML-KEM-768", ek)
    pk, sk = sig_keygen("ML-DSA-65")
    sig = sig_sign("ML-DSA-65", sk, b"Inspected message")

    result = {"hex": [], "annotate": [], "binary": [], "sizes": []}

    for section, data, anno_fields in [
        ("ML-KEM-768 public key", ek, [("Seed/params", 32), ("Polynomial coefs", len(ek) - 32)]),
        ("ML-KEM-768 ciphertext", ct, [("c1 (polynomial)", len(ct) // 2), ("c2 (polynomial)", len(ct) - len(ct) // 2)]),
    ]:
        result["hex"].append(_hexdump(section, data))
        result["annotate"].append(_annotate(section, data, anno_fields))
        result["binary"].append(view_binary(section, data))

    sig_z_len = len(sig) // 2
    sig_hint_len = len(sig) - sig_z_len - 32
    for section, data, anno_fields in [
        ("ML-DSA-65 public key", pk, [("Seed rho (A matrix)", 32), ("t1 vector compressed", len(pk) - 32)]),
        ("ML-DSA-65 signature", sig, [("Challenge c (hash)", 32), ("z vector", sig_z_len), ("hint", sig_hint_len)]),
    ]:
        result["hex"].append(_hexdump(section, data))
        result["annotate"].append(_annotate(section, data, anno_fields))
        result["binary"].append(view_binary(section, data))

    result["sizes"].append(f"  {'Artifact':30s} {'Size':>8s}")
    result["sizes"].append(f"  {'-'*30} {'-'*8}")
    for name, data in [
        ("RSA-2048 public key", b"\x00" * 256),
        ("X25519 public key", b"\x00" * 32),
        ("ML-KEM-512 public key", kem_keygen("ML-KEM-512")[0]),
        ("ML-KEM-768 public key", ek),
        ("ML-KEM-1024 public key", kem_keygen("ML-KEM-1024")[0]),
        ("ML-KEM-768 ciphertext", ct),
        ("ML-DSA-65 public key", pk),
        ("ML-DSA-65 signature", sig),
        ("ML-DSA-44 signature", sig_sign("ML-DSA-44", sig_keygen("ML-DSA-44")[1], b"test")),
        ("ML-DSA-87 signature", sig_sign("ML-DSA-87", sig_keygen("ML-DSA-87")[1], b"test")),
    ]:
        result["sizes"].append(f"  {name:30s} {len(data):>8} bytes")

    return result

def inspect():
    return "\n".join(inspect_all()["hex"])
