from fpdf import FPDF
import os

PDF_PATH = r"E:\pqc-migration-toolkit\PQC_Migration_Toolkit.pdf"
CHART_PATH = r"E:\pqc-migration-toolkit\benchmarks\pqc_benchmark.png"

WHITE = (255, 255, 255)
DARK = (20, 20, 50)
ACCENT = (0, 200, 255)
GRAY = (150, 150, 150)

class PDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*GRAY)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")
    def sec(self, title):
        self.set_fill_color(*DARK)
        self.set_text_color(*ACCENT)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 12, title, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(3)
    def txt(self, text, sz=10):
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "", sz)
        self.multi_cell(0, 5.5, text)
        self.ln(1)
    def code(self, lines, sz=8):
        self.set_fill_color(30, 30, 50)
        self.set_text_color(*GRAY)
        self.set_font("Courier", "", sz)
        if isinstance(lines, list):
            lines = "\n".join(lines)
        self.multi_cell(0, 4.5, lines, fill=True)
        self.ln(2)
    def add_section(self, title, body, code=None):
        self.add_page()
        self.sec(title)
        for line in body:
            self.txt(line, sz=10)
        if code:
            self.code(code)

pdf = PDF(orientation="L", unit="mm", format="A4")
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()
pdf.set_fill_color(*DARK)
pdf.rect(0, 0, 300, 210, "F")
pdf.set_y(55)
pdf.set_text_color(*ACCENT)
pdf.set_font("Helvetica", "B", 26)
pdf.cell(0, 14, "Post-Quantum Cryptography Migration Toolkit", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(8)
pdf.set_text_color(*WHITE)
pdf.set_font("Helvetica", "", 13)
pdf.cell(0, 7, "A beginner-friendly guide to the new encryption standards that will protect us from quantum computers", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(12)
pdf.set_font("Helvetica", "", 11)
pdf.set_text_color(*GRAY)
pdf.cell(0, 6, "No technical background needed - everything explained from scratch", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 6, "Made with Python  |  kyber-py  |  dilithium-py  |  matplotlib", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 6, "100% free and open-source", align="C", new_x="LMARGIN", new_y="NEXT")

# Content pages
pages = [
    ("What is Encryption?", [
        "Imagine sending a secret message across a crowded room. Everyone can see it, so you LOCK it.",
        "That's what encryption does - it LOCKS your data so only the right person can read it.",
        "",
        "Public Key  = A lock anyone can use to lock a message",
        "Private Key = The unique key that opens that specific lock",
        "Signature   = Like a wax seal - proves the message is really from you",
        "",
        "Real-world examples:",
        "  When you visit https://google.com, your browser uses encryption",
        "  When you send a WhatsApp message, it's encrypted",
        "  When you sign into a website, encryption protects your password",
        "",
        "Current encryption uses math that is HARD for normal computers.",
        "But quantum computers will solve it EASILY. We need NEW math!"
    ]),
    ("Why Quantum Computers Break Encryption", [
        "Regular computers use BITS (0s and 1s). Quantum computers use QUBITS -",
        "they can be 0 and 1 AT THE SAME TIME. This lets them solve certain",
        "problems MILLIONS of times faster.",
        "",
        "In 1994, mathematician Peter Shor discovered quantum computers could break:",
        "  RSA encryption (used for securing websites)",
        "  ECDH/ECDSA (used in cryptocurrencies, secure messaging)",
        "",
        "Think of it like this:",
        "  Current encryption = A giant maze that takes years to solve",
        "  Quantum computer   = A helicopter that flies OVER the maze in seconds",
        "",
        "Hackers are ALREADY collecting encrypted data today, waiting for",
        "quantum computers so they can decrypt it later.",
        "This is called 'Harvest Now, Decrypt Later.'"
    ]),
    ("The Solution: Post-Quantum Cryptography (PQC)", [
        "New math problems that are hard for BOTH regular AND quantum computers.",
        "",
        "From 2016 to 2024, NIST ran a worldwide competition. After 8 years",
        "of testing, they chose the winners. In August 2024, NIST released THREE standards:",
        "",
        "1. ML-KEM (Kyber) - For SECRET KEY EXCHANGE",
        "   Replaces: RSA and ECDH. Use: secure connection to a website.",
        "",
        "2. ML-DSA (Dilithium) - For DIGITAL SIGNATURES",
        "   Replaces: RSA signatures and ECDSA.",
        "   Use: proving who sent a message or signed a document.",
        "",
        "3. SLH-DSA (SPHINCS+) - Backup signature method.",
        "   Different math in case ML-DSA is broken later.",
        "",
        "Think of ML-KEM as a NEW type of lock, and ML-DSA as a NEW type of wax seal."
    ]),
    ("Understanding PQC Through Analogies", [
        "ML-KEM = A Special Lock: Old lock breaks under quantum computers.",
        "  New lock: Even quantum computers can't break it.",
        "  You give out copies of this lock (public key) to everyone.",
        "  Only your private key can open messages locked with it.",
        "",
        "ML-DSA = A Tamper-Proof Wax Seal:",
        "  Old seal: Quantum computers can forge it.",
        "  New seal: Impossible to forge, even with quantum computers.",
        "",
        "The problem: These new locks and seals are BIGGER:",
        "  Old RSA key = 256 bytes (small padlock)",
        "  New ML-KEM key = 1184 bytes (large suitcase lock)",
        "  Old signature = ~70 bytes (postage stamp)",
        "  New signature = 3309 bytes (full letter!)"
    ]),
    ("Meet the PQC Migration Toolkit", [
        "A Python program that demonstrates how the new PQC standards work.",
        "You don't need to understand complex math - it shows you the RESULTS.",
        "",
        "Main Menu:",
    ], [
        "+------------------------------------------------------+",
        "|          PQC MIGRATION TOOLKIT - MAIN MENU           |",
        "+------------------------------------------------------+",
        "|  1.  ML-KEM Key Encapsulation Demo   (FIPS 203)      |",
        "|  2.  ML-DSA Digital Signature Demo   (FIPS 204)      |",
        "|  3.  Hybrid TLS 1.3 Handshake Demo                   |",
        "|  4.  Certificate Migration Analysis                   |",
        "|  5.  Performance Benchmarks + Charts                 |",
        "|  6.  Run ALL modules sequentially                    |",
        "|  0.  Exit                                            |",
        "+------------------------------------------------------+"
    ]),
    ("Module 1: ML-KEM Key Exchange", [
        "WHAT IT DOES: Two people (Alice and Bob) share a secret key.",
        "",
        "HOW IT WORKS:",
        "  1. Alice creates a lock (public key) and keeps the only key (private)",
        "  2. Alice gives Bob a copy of her lock",
        "  3. Bob uses that lock to lock a secret message (shared secret)",
        "  4. Bob sends the locked box (ciphertext) back to Alice",
        "  5. Alice uses her private key to open the box and read the secret",
        "",
        "KEY INSIGHT: This works even if someone is watching the conversation!",
        "That's why it's called 'public key' cryptography."
    ]),
    ("Module 2: ML-DSA Digital Signatures", [
        "WHAT IT DOES: Prove that YOU wrote a message and nobody changed it.",
        "Like signing a check, but much more secure.",
        "",
        "HOW IT WORKS:",
        "  1. You create a signing key (private) and verification key (public)",
        "  2. You 'sign' your message with your private key - creates a signature",
        "  3. Anyone can VERIFY the signature using your public key",
        "  4. Change even ONE letter - signature becomes invalid",
        "",
        "REAL WORLD: When you download software, the developer signs it.",
        "Your computer checks the signature before installing.",
        "With PQC, this check stays secure even against quantum computers."
    ]),
    ("Module 3: Hybrid TLS Handshake", [
        "Simulates how Chrome connects to websites using BOTH old AND new encryption.",
        "",
        "WHY BOTH? Nobody knows when quantum computers arrive.",
        "If we switch ONLY to PQC and it has a bug, we're unprotected.",
        "Solution: Use BOTH and COMBINE them.",
        "",
        "GUARANTEE: If quantum breaks X25519 -> ML-KEM protects you.",
        "If someone breaks ML-KEM -> X25519 protects you.",
        "You're safe either way!",
        "",
        "This is EXACTLY what Google Chrome has been doing since 2024."
    ]),
    ("Module 4: Certificate Migration", [
        "Compares sizes of old certificates vs new PQC keys.",
        "Shows the REAL challenge of upgrading the internet.",
        "",
        "Old RSA-2048 certificate:      ~993 bytes (fits in one packet)",
        "New ML-DSA-65 public key:     ~1952 bytes",
        "New ML-DSA-65 signature:      ~3309 bytes",
        "",
        "WHY SIZE MATTERS: Internet packets max at 1500 bytes.",
        "Bigger certs = multiple packets = slower loading.",
        "Mobile phones suffer the most.",
        "",
        "HYBRID SOLUTION: Certs with BOTH old RSA AND new PQC keys."
    ]),
    ("Module 5: Performance Benchmarks", [
        "Measures how fast each PQC operation runs on your computer.",
        "",
        "KeyGen = Create a new key pair",
        "Encaps = Lock a secret with a public key",
        "Decaps = Unlock with the private key",
        "Sign   = Sign a message",
        "Verify = Check a signature",
        "",
        "ML-KEM-512:  KeyGen 1.6ms | Encaps 2.4ms | Decaps 3.2ms",
        "ML-KEM-768:  KeyGen 2.7ms | Encaps 3.6ms | Decaps 4.6ms",
        "ML-KEM-1024: KeyGen 4.0ms | Encaps 5.0ms | Decaps 6.8ms",
        "",
        "ML-DSA-44:  KeyGen 5.6ms | Sign 28ms  | Verify 5.8ms",
        "ML-DSA-65:  KeyGen 7.8ms | Sign 43ms  | Verify 8.9ms",
        "ML-DSA-87:  KeyGen 12ms  | Sign 46ms  | Verify 14ms",
        "",
        "Blinking takes ~300ms. All these are faster than a blink!"
    ]),
    ("Who Already Uses PQC?", [
        "GOOGLE CHROME (2024+) - X25519 + ML-KEM for all TLS connections",
        "SIGNAL MESSENGER (2023+) - Kyber in their secure messaging protocol",
        "APPLE iMESSAGE (2024+) - Kyber for post-quantum security",
        "AMAZON WEB SERVICES (2020+) - AWS KMS supports PQC for TLS",
        "CLOUDFLARE - PQC offered to all customers (20% of websites)",
        "OPENSSL 3.5 (April 2025) - Most used crypto library, now has native PQC",
        "",
        "PQC is happening NOW, not in the distant future."
    ]),
    ("Challenges of Switching to PQC", [
        "Like replacing all locks in all buildings at once:",
        "",
        "1. BIGGER KEYS - 3-10x larger, more data to send",
        "2. SLOWER OPERATIONS - 5-10x slower than classical crypto",
        "3. HARDWARE UPGRADES - Banks need new hardware security modules",
        "4. BACKWARD COMPATIBILITY - Old devices need to work alongside new",
        "5. STANDARDS TAKE TIME - Every protocol needs updating (years)",
        "",
        "That's why organizations need to START PLANNING NOW."
    ]),
    ("How to Run This Program", [
        "Step 1: Install Python 3.9+ from python.org",
        "Step 2: pip install kyber-py dilithium-py matplotlib cryptography",
        "Step 3: python main.py",
        "Step 4: Pick a number from the menu and press Enter",
        "",
        "No cloud accounts, no API keys, no setup needed.",
        "",
        "Individual modules:",
        "  python src/kem_demo.py",
        "  python src/sign_demo.py",
        "  python src/hybrid_tls_demo.py",
        "  python src/cert_migration_demo.py",
        "  python src/benchmark.py"
    ]),
    ("Why Should YOU Care About PQC?", [
        "PERSONAL: Your bank, WhatsApp, and emails are encrypted.",
        "Hackers collect encrypted data NOW to decrypt LATER.",
        "Your medical records and tax returns could be exposed.",
        "",
        "PROFESSIONAL: Companies need people who understand PQC.",
        "Governments are mandating PQC adoption (US, EU, India).",
        "This is a NEW SKILL in high demand.",
        "",
        "ACADEMIC (for students): Standards finalized in 2024.",
        "Most engineers haven't learned this yet.",
        "A PQC project stands out in college and job interviews.",
        "",
        "Encryption keeps the digital world safe.",
        "Quantum computers will break today's locks.",
        "PQC is the new locks protecting us tomorrow."
    ]),
    ("Key Takeaways", [
        "1. Quantum computers threaten all current encryption",
        "2. NIST standardized new PQC algorithms in August 2024",
        "3. ML-KEM (Kyber) = New way to exchange secret keys",
        "4. ML-DSA (Dilithium) = New way to sign and verify",
        "5. PQC keys are 3-10x larger - the main challenge",
        "6. Chrome, Signal, Apple, AWS already use PQC",
        "7. Hybrid (old + new) is safer during transition",
        "8. OpenSSL 3.5 has PQC built-in - production ready",
        "9. This toolkit lets you EXPERIENCE PQC on your laptop",
        "10. Start learning NOW - it's the future of security"
    ]),
    ("References", [
        "FOR BEGINNERS:",
        "  NIST PQC: nist.gov/pqc",
        "  Cloudflare PQC Guide: cloudflare.com/learning/ssl/post-quantum-cryptography",
        "",
        "FOR STUDENTS/DEVELOPERS:",
        "  [1] FIPS 203 - ML-KEM Standard: csrc.nist.gov/pubs/fips/203/final",
        "  [2] FIPS 204 - ML-DSA Standard: csrc.nist.gov/pubs/fips/204/final",
        "  [3] Open Quantum Safe: openquantumsafe.org",
        "  [4] kyber-py: github.com/GiacomoPope/kyber-py",
        "  [5] dilithium-py: github.com/GiacomoPope/dilithium-py",
        "  [6] OpenSSL 3.5: github.com/openssl/openssl",
        "",
        "THIS PROJECT: E:\\pqc-migration-toolkit\\  |  python main.py"
    ]),
]

for title, body, *rest in pages:
    code = rest[0] if rest else None
    pdf.add_section(title, body, code)

if os.path.exists(CHART_PATH):
    pdf.add_page()
    pdf.sec("Benchmark Chart")
    pdf.image(CHART_PATH, x=15, y=25, w=270, h=130)

pdf.output(PDF_PATH)
print(f"PDF saved to: {PDF_PATH}")
print(f"Total pages: {pdf.page_no()}")
