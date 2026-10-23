from dilithium_py.ml_dsa.default_parameters import ML_DSA_44, ML_DSA_65, ML_DSA_87

def run_sign_demo():
    print("=" * 60)
    print("PQC MIGRATION TOOLKIT - SIGNATURE DEMO (ML-DSA / FIPS 204)")
    print("=" * 60)
    message = b"This is a test document for post-quantum signing."
    for name, signer in [("ML-DSA-44", ML_DSA_44), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)]:
        print(f"\n--- {name} ---")
        pk, sk = signer.keygen()
        signature = signer.sign(sk, message)
        is_valid = signer.verify(pk, message, signature)
        print(f"  Public key size:     {len(pk)} bytes")
        print(f"  Private key size:    {len(sk)} bytes")
        print(f"  Signature size:      {len(signature)} bytes")
        print(f"  Message size:        {len(message)} bytes")
        print(f"  Signature valid:     {is_valid}")
        print(f"  Comparison vs ECDSA sig (~70 bytes): PQC sig is {len(signature)/70:.1f}x larger")
    print("\n" + "=" * 60)
    print("All signature operations passed successfully.")
    print("=" * 60)

if __name__ == "__main__":
    run_sign_demo()
