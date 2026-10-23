from kyber_py.ml_kem.default_parameters import ML_KEM_512, ML_KEM_768, ML_KEM_1024

def run_kem_demo():
    print("=" * 60)
    print("PQC MIGRATION TOOLKIT - KEM DEMO (ML-KEM / FIPS 203)")
    print("=" * 60)
    for name, kem in [("ML-KEM-512", ML_KEM_512), ("ML-KEM-768", ML_KEM_768), ("ML-KEM-1024", ML_KEM_1024)]:
        print(f"\n--- {name} ---")
        ek, dk = kem.keygen()
        shared_key, ct = kem.encaps(ek)
        recovered_key = kem.decaps(dk, ct)
        assert shared_key == recovered_key, "Shared secrets do not match!"
        print(f"  Public key size:     {len(ek)} bytes")
        print(f"  Private key size:    {len(dk)} bytes")
        print(f"  Ciphertext size:     {len(ct)} bytes")
        print(f"  Shared secret size:  {len(shared_key)} bytes")
        print(f"  Shared secrets match: {shared_key == recovered_key}")
        print(f"  Comparison vs RSA-2048 pubkey (256 bytes): PQC pubkey is {len(ek)/256:.1f}x larger")
    print("\n" + "=" * 60)
    print("All KEM operations passed successfully.")
    print("=" * 60)

if __name__ == "__main__":
    run_kem_demo()
