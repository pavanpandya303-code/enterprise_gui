"""PQC knowledge base — local explanations for common questions.
No internet required. Used by the Ask PQC Assistant sidebar."""

EXPLANATIONS = {
    "ml-kem": (
        "ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) is NIST FIPS 203, "
        "formerly known as Kyber. It is a post-quantum key agreement scheme that lets "
        "two parties establish a shared secret key over an untrusted network. Unlike RSA "
        "or ECDH, its security is based on the Module-LWE (Learning With Errors) problem, "
        "which is believed to be hard for both classical and quantum computers. ML-KEM has "
        "three security levels: 512 (128-bit), 768 (192-bit), and 1024 (256-bit). Google "
        "Chrome uses X25519MLKEM768, a hybrid combining X25519 with ML-KEM-768."
    ),
    "pqc-key-size": (
        "Post-quantum keys are significantly larger than classical keys because lattice-based "
        "cryptography works with mathematical structures called lattices — grids of points in "
        "high-dimensional space. Instead of storing a single large number (like RSA's modulus), "
        "PQC stores entire vectors and matrices of coefficients. For example:\n"
        "  - RSA-2048 public key: 256 bytes\n"
        "  - ML-KEM-768 public key: 1,184 bytes (~4.6x larger)\n"
        "  - ML-DSA-65 signature: 3,309 bytes (~47x larger than ECDSA)\n"
        "This size increase impacts TLS handshake bandwidth, certificate storage, and "
        "network MTU configurations, but is generally manageable for modern infrastructure."
    ),
    "tls-handshake": (
        "A TLS 1.3 handshake proceeds in these steps:\n"
        "1. ClientHello — Client generates keypairs (X25519 + ML-KEM) and sends public keys\n"
        "2. ServerHello — Server generates its own keypair and sends its public key + KEM ciphertext\n"
        "3. Certificate — Server sends its X.509 certificate (classical or hybrid) to prove identity\n"
        "4. Key Exchange — Both sides run HKDF-SHA256 over both shared secrets to get a single session key\n"
        "5. Finished — Both sides confirm the handshake succeeded; session key is now ready\n"
        "6. Application Data — Encrypted communication begins using AES-256-GCM\n"
        "Hybrid mode means classical AND PQC key exchanges happen in parallel. If either is broken, "
        "the other still protects the session."
    ),
    "hybrid-tls": (
        "Hybrid TLS combines a classical algorithm (like X25519 or ECDH) with a post-quantum "
        "algorithm (like ML-KEM) during the TLS handshake. Both key agreements run "
        "independently, and their outputs are combined using a Key Derivation Function (KDF) "
        "like HKDF. The result: even if quantum computers later break the classical algorithm, "
        "the PQC layer still protects the session. Conversely, if the PQC algorithm is found "
        "to have a vulnerability, the classical layer still protects it. Google Chrome has "
        "deployed X25519MLKEM768 since 2024, and Apple iMessage uses a similar hybrid "
        "approach with Kyber. This is the industry-standard migration strategy."
    ),
    "verification-fail": (
        "Signature verification can fail for several reasons:\n"
        "1. The message was tampered with after signing (most common)\n"
        "2. The wrong public key is being used to verify\n"
        "3. The signature bytes were corrupted or truncated\n"
        "4. The wrong algorithm parameters were specified (e.g., verifying an "
        "ML-DSA-65 signature against an ML-DSA-44 public key)\n"
        "5. The keypair used for signing is different from the one used for verification\n"
        "In a well-functioning system, verification always succeeds. If you see FAIL or "
        "INVALID in this toolkit, something is intentionally wrong (like a tampered "
        "message test) or there is an implementation bug."
    ),
    "wire-format": (
        "Wire format inspection shows the raw byte layout of cryptographic keys, "
        "ciphertexts, and signatures at the memory level. ML-KEM public keys start "
        "with a 32-byte seed (used to generate the matrix A) followed by a compressed "
        "vector of polynomial coefficients. ML-DSA signatures contain a 32-byte challenge "
        "hash, a large z-vector (the actual signature proof), and a hint vector for "
        "decompression. Hex view shows raw bytes, ASCII view shows printable characters, "
        "and binary view shows the individual 0/1 bits. Understanding wire format is "
        "important for protocol implementers and debugging interoperability issues."
    ),
    "what-is-quantum": (
        "A quantum computer uses quantum mechanics (superposition and entanglement) to "
        "perform certain calculations exponentially faster than classical computers. In 1994, "
        "Peter Shor discovered an algorithm that can factor large numbers and compute discrete "
        "logarithms in polynomial time — meaning it would break RSA, ECDH, and ECDSA. A "
        "sufficiently large quantum computer could factor a 2048-bit RSA key in minutes, "
        "while the best classical algorithms would take trillions of years. This is why the "
        "world is migrating to post-quantum cryptography."
    ),
    "harvest-now": (
        "Harvest Now, Decrypt Later (HNDL) is an attack strategy where adversaries collect "
        "encrypted data today and store it until quantum computers become powerful enough "
        "to decrypt it. Even if RSA-2048 is secure now, encrypted messages recorded today "
        "could be decrypted in 5-10 years when quantum computers mature. This is why "
        "long-lived secrets (like classified documents, trade secrets, or personal data) "
        "need post-quantum protection TODAY, not tomorrow. PQC algorithms like ML-KEM and "
        "ML-DSA are designed to resist both classical and quantum attacks."
    ),
    "fips-203": (
        "FIPS 203 is the official NIST standard for ML-KEM (Module-Lattice-Based Key "
        "Encapsulation Mechanism), published August 2024. It specifies three parameter sets:\n"
        "  - ML-KEM-512: 128-bit security level\n"
        "  - ML-KEM-768: 192-bit security level (recommended)\n"
        "  - ML-KEM-1024: 256-bit security level\n"
        "FIPS 203 was selected after an 8-year worldwide competition run by NIST. It is "
        "based on the CRYSTALS-Kyber algorithm submitted by a team of researchers from "
        "Europe and the US."
    ),
    "fips-204": (
        "FIPS 204 is the official NIST standard for ML-DSA (Module-Lattice-Based Digital "
        "Signature Algorithm), also published August 2024. It is based on CRYSTALS-Dilithium. "
        "Three parameter sets:\n"
        "  - ML-DSA-44: 128-bit security (smallest signatures: 2.4KB)\n"
        "  - ML-DSA-65: 192-bit security (balanced: 3.3KB signatures)\n"
        "  - ML-DSA-87: 256-bit security (largest: 4.6KB signatures)\n"
        "ML-DSA signatures are significantly larger than ECDSA signatures (~70B) or RSA "
        "signatures (~256B), which is one of the main challenges of PQC migration."
    ),
    "certificate-sizes": (
        "Certificate sizes matter because TLS handshakes include the server's certificate "
        "chain. Larger certificates mean slower connections, especially on mobile networks:\n"
        "  - RSA-2048 certificate (PEM): ~900 bytes\n"
        "  - RSA-4096 certificate (PEM): ~1,700 bytes\n"
        "  - ECDSA P-256 certificate (PEM): ~700 bytes\n"
        "  - ML-DSA-65 public key alone: 1,952 bytes\n"
        "  - ML-DSA-65 signature: 3,309 bytes\n"
        "Adding PQC keys to certificates increases handshake size by 3-5KB, which is "
        "generally acceptable on broadband but may impact IoT or satellite links."
    ),
    "ml-dsa": (
        "ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is NIST FIPS 204, "
        "formerly known as Dilithium. It generates digital signatures that are secure against "
        "quantum computers. Unlike RSA or ECDSA, ML-DSA is based on the Module-LWE lattice "
        "problem. Signatures are significantly larger than classical ones: ML-DSA-65 signatures "
        "are ~3,309 bytes vs ~70 bytes for ECDSA and ~256 bytes for RSA. ML-DSA offers three "
        "security levels: 44 (128-bit), 65 (192-bit), and 87 (256-bit)."
    ),
    "digital-signatures": (
        "A digital signature proves that a message came from a specific sender and was not "
        "tampered with. The sender uses their private key to sign the message, producing a "
        "unique signature. Anyone with the corresponding public key can verify that the "
        "signature matches the message. If even one byte of the message changes, verification "
        "fails — this is called 'malleability detection.' Digital signatures are used for "
        "code signing, document signing, TLS certificates, software updates, and more. PQC "
        "signatures like ML-DSA (FIPS 204) are quantum-safe replacements for RSA and ECDSA."
    ),
    "attack-demo": (
        "The Harvest Now, Decrypt Later attack demonstrates why organizations must migrate "
        "to PQC before quantum computers arrive. In this simulation, a message is encrypted "
        "using a small RSA key that can be factored by trial division. The ciphertext is "
        "'recorded' and then 'years later' the key is factored and the message is recovered. "
        "This shows the same threat: hackers record RSA-2048 traffic today and wait for "
        "quantum computers to factor the keys in the future. PQC algorithms like ML-KEM "
        "prevent this because lattice problems are hard for both classical and quantum computers."
    ),
    "benchmarks": (
        "Benchmarks measure how long each cryptographic operation takes. In this toolkit, "
        "operations are measured in milliseconds (ms). For reference, a human eye blink is "
        "about 300ms. All operations in this toolkit complete within that time.\n"
        "Key observations:\n"
        "  - Key generation is typically fast for both ML-KEM and ML-DSA\n"
        "  - Signing is the slowest ML-DSA operation (~30-70ms)\n"
        "  - Verification is also relatively slow for ML-DSA\n"
        "  - Pure Python implementations are about 50-100x slower than optimized C (liboqs)\n"
        "  - Higher security levels (1024, 87) take longer than lower levels (512, 44)"
    ),
    "kem-encryption": (
        "ML-KEM is a Key Encapsulation Mechanism (KEM), not a direct encryption algorithm. "
        "To encrypt a custom message with ML-KEM:\n"
        "1. Generate a KEM keypair (public + private)\n"
        "2. Encapsulate: the sender calls encaps(public_key) → (shared_secret, ciphertext)\n"
        "3. The shared_secret is then used as the key for a symmetric cipher (like AES-GCM)\n"
        "4. The sender encrypts the message using AES-GCM with the shared secret\n"
        "5. The receiver decapsulates: decaps(private_key, ciphertext) → recovered_shared_secret\n"
        "6. The receiver decrypts the AES-GCM payload using the recovered shared secret\n"
        "This two-step approach (KEM + symmetric encryption) is exactly how modern TLS works."
    ),
    "aes-gcm": (
        "AES-GCM (Galois/Counter Mode) is a symmetric authenticated encryption algorithm. "
        "It provides both confidentiality (encryption) and integrity (authentication) in a "
        "single operation. GCM uses a 12-byte random nonce (number used once) which must be "
        "unique for every encryption with the same key. AES-GCM is widely used in TLS 1.3, "
        "SSH, and IPsec. In this toolkit, the shared secret from ML-KEM is used as the AES "
        "key — this is how post-quantum key agreement translates into real message encryption."
    ),
}

TOPICS = {
    "What is ML-KEM?": "ml-kem",
    "Why are PQC keys larger?": "pqc-key-size",
    "What is Hybrid TLS?": "hybrid-tls",
    "Why does verification fail?": "verification-fail",
    "What is a quantum computer?": "what-is-quantum",
    "What is Harvest Now Decrypt Later?": "harvest-now",
    "What is FIPS 203?": "fips-203",
    "What is FIPS 204?": "fips-204",
    "Certificate sizes?": "certificate-sizes",
    "Performance benchmarks?": "benchmarks",
    "How does KEM encryption work?": "kem-encryption",
    "What is AES-GCM?": "aes-gcm",
    "What is ML-DSA?": "ml-dsa",
    "How do digital signatures work?": "digital-signatures",
    "How does TLS handshake work?": "tls-handshake",
    "What is wire format?": "wire-format",
}

def get_answer(question):
    question_lower = question.lower().strip()
    for key, topic_id in TOPICS.items():
        if any(word in question_lower for word in key.lower().replace("?", "").split()):
            return EXPLANATIONS.get(topic_id, "")
    for _, topic_id in TOPICS.items():
        explanation = EXPLANATIONS.get(topic_id, "")
        if explanation and any(word in question_lower for word in topic_id.replace("-", " ").split()):
            return explanation
    return None
