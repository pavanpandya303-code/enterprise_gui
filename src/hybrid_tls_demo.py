from kyber_py.ml_kem.default_parameters import ML_KEM_768
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def run_hybrid_tls_demo():
    print("=" * 60)
    print("PQC MIGRATION TOOLKIT - HYBRID TLS HANDSHAKE DEMO")
    print("(X25519 + ML-KEM-768 - same model as Chrome's X25519MLKEM768)")
    print("=" * 60)
    print("\n[Client] Generates X25519 keypair + ML-KEM-768 keypair...")
    client_x25519_sk = x25519.X25519PrivateKey.generate()
    client_x25519_pk = client_x25519_sk.public_key().public_bytes_raw()
    client_kem = ML_KEM_768
    client_kem_ek, client_kem_dk = client_kem.keygen()
    print(f"  X25519 pubkey: {len(client_x25519_pk)} bytes")
    print(f"  ML-KEM-768 pubkey (ek): {len(client_kem_ek)} bytes")
    print(f"  Total client payload: {len(client_x25519_pk) + len(client_kem_ek)} bytes")
    print("\n[Server] Receives both public keys.")
    print("[Server] Generates X25519 keypair + ML-KEM encaps...")
    server_x25519_sk = x25519.X25519PrivateKey.generate()
    server_x25519_pk = server_x25519_sk.public_key().public_bytes_raw()
    server_kem_shared, server_kem_ct = client_kem.encaps(client_kem_ek)
    print(f"  ML-KEM ciphertext: {len(server_kem_ct)} bytes")
    print("\n[Server] Computes X25519 shared secret...")
    server_x25519_shared = server_x25519_sk.exchange(
        x25519.X25519PublicKey.from_public_bytes(client_x25519_pk)
    )
    print("\n[Server] Combines both shared secrets via HKDF...")
    combined = server_x25519_shared + server_kem_shared
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_TLS_1.3")
    server_final_key = hkdf.derive(combined)
    print("\n[Client] Computes X25519 shared secret...")
    client_x25519_shared = client_x25519_sk.exchange(
        x25519.X25519PublicKey.from_public_bytes(server_x25519_pk)
    )
    print("[Client] Decaps ML-KEM to recover KEM shared secret...")
    client_kem_shared = client_kem.decaps(client_kem_dk, server_kem_ct)
    print("[Client] Combines both shared secrets via HKDF...")
    combined_client = client_x25519_shared + client_kem_shared
    hkdf_client = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_TLS_1.3")
    client_final_key = hkdf_client.derive(combined_client)
    assert client_final_key == server_final_key, "Hybrid keys do not match!"
    print(f"\n  Hybrid session key (first 8 bytes hex): {client_final_key[:8].hex()}")
    print(f"  Keys match: {client_final_key == server_final_key}")
    print(f"\n  Security property: Even if quantum computer breaks")
    print(f"  X25519, the ML-KEM-768 key still protects the session.")
    print(f"  If ML-KEM is broken, X25519 still protects it.")
    print(f"  This is the SAME model Chrome uses since 2024!")
    print("\n" + "=" * 60)

if __name__ == "__main__":
    run_hybrid_tls_demo()
