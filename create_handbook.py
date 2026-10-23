from fpdf import FPDF

PDF_PATH = r"E:\pqc-migration-toolkit\PQC_Handbook.pdf"

WHITE = (255, 255, 255)
DARK = (20, 20, 50)
TEXT = (35, 35, 45)        # readable dark body text on white bg
LIGHT = (180, 180, 195)     # light code text on dark bg
ACCENT = (0, 180, 255)
GRAY = (130, 130, 140)

class PDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*GRAY)
        self.cell(0, 10, f"PQC Migration Toolkit Handbook - Page {self.page_no()}/{{nb}}", align="C")
    def ch(self, title):
        self.set_fill_color(*DARK)
        self.set_text_color(*ACCENT)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 11, title, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(3)
    def t(self, text, sz=10):
        self.set_text_color(*TEXT)
        self.set_font("Helvetica", "", sz)
        self.multi_cell(0, 5.5, text)
        self.ln(1)
    def b(self, text, sz=10):
        self.set_text_color(*ACCENT)
        self.set_font("Helvetica", "B", sz)
        self.multi_cell(0, 5.5, text)
        self.ln(1)
    def code(self, text, sz=8):
        self.set_fill_color(22, 24, 38)
        self.set_text_color(*LIGHT)
        self.set_font("Courier", "", sz)
        self.multi_cell(0, 4.5, text.strip('\n'), fill=True)
        self.ln(2)
    def note(self, text):
        self.set_fill_color(0, 35, 55)
        self.set_text_color(*ACCENT)
        self.set_font("Helvetica", "I", 9)
        self.multi_cell(0, 5, "Note: " + text, fill=True)
        self.ln(2)
    def li(self, text):
        self.set_text_color(*TEXT)
        self.set_font("Helvetica", "", 10)
        self.cell(0, 7, text, ln=True)

pdf = PDF(orientation="P", unit="mm", format="A4")
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=18)

# ═══════════════ COVER PAGE ═══════════════
pdf.add_page()
pdf.set_fill_color(*DARK)
pdf.rect(0, 0, 210, 297, "F")
pdf.set_y(60)
pdf.set_text_color(*ACCENT)
pdf.set_font("Helvetica", "B", 28)
pdf.cell(0, 14, "PQC Migration Toolkit", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "", 18)
pdf.cell(0, 12, "User Handbook", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(15)
pdf.set_text_color(*WHITE)
pdf.set_font("Helvetica", "", 12)
pdf.cell(0, 7, "A complete guide to understanding and using the", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 7, "Post-Quantum Cryptography Migration Toolkit", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(20)
pdf.set_text_color(*GRAY)
pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 6, "Written for students, developers and anyone curious about", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 6, "the future of encryption", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)
pdf.cell(0, 6, "No technical background required", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(40)
pdf.set_text_color(*GRAY)
pdf.set_font("Helvetica", "", 9)
pdf.cell(0, 5, "Built with Python  |  kyber-py  |  dilithium-py  |  cryptography  |  matplotlib", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 5, "100% free and open-source", align="C", new_x="LMARGIN", new_y="NEXT")

# ═══════════════ TABLE OF CONTENTS ═══════════════
pdf.add_page()
pdf.ch("Table of Contents")
toc = [
    "1.  What is This Project?",
    "2.  Why Should You Care About Quantum Computers?",
    "3.  Understanding Encryption (Simple Explanation)",
    "4.  What Are Post-Quantum Cryptography Standards?",
    "5.  Project Structure - Where Everything Lives",
    "6.  How to Install and Run",
    "7.  Using the GUI Desktop App (Recommended)",
    "8.  Using the Command Line (main.py)",
    "9.  Module Guide: ML-KEM Key Exchange",
    "10. Module Guide: ML-DSA Digital Signatures",
    "11. Module Guide: Hybrid TLS Handshake",
    "12. Module Guide: Certificate Migration",
    "13. Module Guide: Performance Benchmarks",
    "14. Module Guide: Hybrid Certificate Chain",
    "15. Module Guide: Attack Demo (Harvest Now Decrypt Later)",
    "16. Module Guide: Wire-Format Inspection",
    "17. Module Guide: Migration Impact Calculator",
    "18. Understanding the Results",
    "19. Frequently Asked Questions",
    "20. Troubleshooting Common Issues",
    "21. Glossary of Terms",
    "22. References and Further Reading",
]
for t in toc:
    pdf.li(t)

# ═══════════════ 1. WHAT IS THIS PROJECT ═══════════════
pdf.add_page()
pdf.ch("1. What is This Project?")
pdf.t("The PQC Migration Toolkit is a hands-on educational software package that lets you explore the new encryption standards designed to protect against quantum computers. Think of it as a playground where you can experiment with the future of internet security.")
pdf.t("The project contains six interactive modules that demonstrate different aspects of post-quantum cryptography (PQC). You can run them either through a Windows desktop application with buttons and tables, or through a command-line menu.")
pdf.t("Everything is built using Python and runs entirely on your own computer. No internet connection, cloud accounts or API keys are needed. All the cryptographic operations happen locally.")

# ═══════════════ 2. WHY CARE ABOUT QUANTUM ═══════════════
pdf.add_page()
pdf.ch("2. Why Should You Care About Quantum Computers?")
pdf.t("Most people do not realize this but the encryption that protects your bank transactions, WhatsApp messages, emails and passwords is based on math problems that quantum computers will be able to solve easily.")
pdf.t("Here is a simple way to understand it. Current encryption is like a giant maze that would take a normal computer thousands of years to solve. A quantum computer is like a helicopter that can fly straight over the maze and reach the center in seconds.")
pdf.t("The scary part is that hackers are already collecting encrypted data today. They are waiting for quantum computers to become powerful enough so they can decrypt everything later. This is called Harvest Now Decrypt Later. Your messages that you send today could be read years from now.")
pdf.t("That is why the world needs to upgrade its encryption before quantum computers arrive. The new standards are called Post-Quantum Cryptography or PQC for short.")

# ═══════════════ 3. ENCRYPTION BASICS ═══════════════
pdf.add_page()
pdf.ch("3. Understanding Encryption (Simple Explanation)")
pdf.t("Imagine you want to send a secret message to your friend across a crowded room. Everyone can see the message so you put it inside a locked box. Only your friend has the key to open it.")
pdf.t("That is exactly what encryption does. It locks your data so that only the person with the right key can read it.")
pdf.t("There are three main concepts you need to understand:")
pdf.b("Public Key")
pdf.t("This is like a lock that anyone can use. You can make many copies and give them to everyone. Anyone can use this lock to lock a message for you.")
pdf.b("Private Key")
pdf.t("This is the unique key that opens the lock. You keep this secret. Only you have it. When someone sends you a locked message you use your private key to open it.")
pdf.b("Digital Signature")
pdf.t("This is like a wax seal on an envelope. It proves that the message really came from you and that nobody tampered with it on the way.")

# ═══════════════ 4. PQC STANDARDS ═══════════════
pdf.add_page()
pdf.ch("4. What Are Post-Quantum Cryptography Standards?")
pdf.t("Post-Quantum Cryptography refers to new mathematical problems that are hard for both regular computers AND quantum computers to solve. These are the replacement for today's RSA and ECDH algorithms.")
pdf.t("In August 2024 after an eight-year worldwide competition the National Institute of Standards and Technology (NIST) finalized three new standards:")
pdf.b("FIPS 203 - ML-KEM (Key Encapsulation)")
pdf.t("Also known as Kyber. This is a new way for two parties to exchange a secret key securely. It replaces RSA and ECDH key exchange. It comes in three security levels: ML-KEM-512 (128-bit), ML-KEM-768 (192-bit) and ML-KEM-1024 (256-bit).")
pdf.b("FIPS 204 - ML-DSA (Digital Signatures)")
pdf.t("Also known as Dilithium. This is a new way to sign and verify digital messages. It replaces RSA and ECDSA signatures. It comes in three levels: ML-DSA-44 (128-bit), ML-DSA-65 (192-bit) and ML-DSA-87 (256-bit).")
pdf.b("FIPS 205 - SLH-DSA (Backup Signatures)")
pdf.t("Also known as SPHINCS+. This is a backup standard in case the lattice-based algorithms (ML-KEM and ML-DSA) are broken in the future. It uses a completely different mathematical approach.")

# ═══════════════ 5. PROJECT STRUCTURE ═══════════════
pdf.add_page()
pdf.ch("5. Project Structure - Where Everything Lives")
pdf.t("All project files are located in the E:/pqc-migration-toolkit folder. Here is what each file does:")
pdf.code(
"E:pqc-migration-toolkit/\n"
"  gui_app.py        The Windows desktop app (recommended)\n"
"  main.py           Command-line version with 9 modules\n"
"  app.py            Web dashboard version (requires Flask)\n"
"  build_exe.py      Build standalone .exe with PyInstaller\n"
"  requirements.txt  Package dependencies\n"
"  src/pqc_wrapper.py        Unified PQC API wrapper\n"
"  src/hybrid_cert.py        Real hybrid X.509 certs\n"
"  src/attack_demo.py        Harvest Now Decrypt Later demo\n"
"  src/wire_format.py        Hex dump with annotations\n"
"  src/impact_calc.py        Storage/bandwidth calculator\n"
"  src/kem_demo.py           Standalone ML-KEM demo\n"
"  src/sign_demo.py          Standalone ML-DSA demo\n"
"  src/hybrid_tls_demo.py    Standalone hybrid TLS demo\n"
"  src/cert_migration_demo.py  Certificate analysis\n"
"  src/benchmark.py          Performance benchmark suite\n"
"  tests/test_all.py   pytest test suite (18 tests)\n"
"  .github/workflows/ci.yml  GitHub Actions CI\n"
"  PQC_Handbook.pdf   This handbook you are reading\n"
"  PQC_Migration_Toolkit.pptx  Presentation slides\n"
"  PQC_Migration_Toolkit.pdf   Presentation in PDF format\n"
"  benchmarks/        Contains generated charts")

# ═══════════════ 6. INSTALL ═══════════════
pdf.add_page()
pdf.ch("6. How to Install and Run")
pdf.t("Follow these steps to get the toolkit running on your computer.")
pdf.b("Step 1 - Check Python")
pdf.t("Open a Command Prompt or Terminal and type: python --version. You need Python version 3.9 or higher. If you do not have Python installed download it from python.org.")
pdf.b("Step 2 - Install Dependencies")
pdf.t("Type the following command and press Enter:")
pdf.code("pip install kyber-py dilithium-py matplotlib cryptography")
pdf.t("This will download and install all the required libraries. The process usually takes less than a minute.")
pdf.b("Step 3 - Navigate to the Project Folder")
pdf.code("cd E:pqc-migration-toolkit")
pdf.b("Step 4 - Launch the App")
pdf.t("For the desktop app (recommended):")
pdf.code("python gui_app.py")
pdf.t("For the command-line version:")
pdf.code("python main.py")

# ═══════════════ 7. GUI APP ═══════════════
pdf.add_page()
pdf.ch("7. Using the GUI Desktop App (Recommended)")
pdf.t("The GUI desktop app is the easiest way to use this toolkit. It looks and feels like a normal Windows program with buttons and tables.")
pdf.t("When you run python gui_app.py a window will open with six tabs at the top:")
pdf.b("How to use each module:")
pdf.t("1. Click on a tab to select the module you want to explore.")
pdf.t("2. Click the Run button that appears in that tab.")
pdf.t("3. Wait a few seconds for the results to appear in tables or text boxes.")
pdf.t("4. Read the output. Each module shows key sizes, timing and pass/fail status.")
pdf.b("Tips:")
pdf.t("- The app runs everything on your computer so it may take a few seconds for benchmarks.")
pdf.t("- You can switch between tabs anytime. Each tab remembers its results.")
pdf.t("- If the app freezes wait a moment. Heavy operations like key generation take a second.")
pdf.t("- Close the window or press Ctrl+C in the terminal to exit.")

# ═══════════════ 8. CLI ═══════════════
pdf.add_page()
pdf.ch("8. Using the Command Line (main.py)")
pdf.t("If you prefer a simple text interface you can use the command-line version instead.")
pdf.t("Run the program:")
pdf.code("python main.py")
pdf.t("You will see a menu like this:")
pdf.code(
"+------------------------------------------------------+\n"
"|          PQC MIGRATION TOOLKIT - MAIN MENU           |\n"
"+------------------------------------------------------+\n"
"|  1.  ML-KEM Key Encapsulation Demo   (FIPS 203)      |\n"
"|  2.  ML-DSA Digital Signature Demo   (FIPS 204)      |\n"
"|  3.  Hybrid TLS 1.3 Handshake Demo                   |\n"
"|  4.  Certificate Migration Analysis                   |\n"
"|  5.  Performance Benchmarks + Charts                 |\n"
"|  6.  Hybrid Certificate Chain (RSA + ML-DSA)         |\n"
"|  7.  Attack Demo: Harvest Now Decrypt Later          |\n"
"|  8.  Wire-Format Inspection (hex dump)               |\n"
"|  9.  Migration Impact Calculator                     |\n"
"|  10. Run ALL modules sequentially                    |\n"
"|                                                      |\n"
"|  0.  Exit                                            |\n"
"+------------------------------------------------------+")
pdf.t("Simply type the number of the module you want to run and press Enter. Option 7 runs all six modules one after another which is useful for demonstrations.")

# ═══════════════ 9-14: MODULE GUIDES ═══════════════
modules = [
    ("9", "Module Guide: ML-KEM Key Exchange",
     "This module demonstrates how two parties can establish a shared secret key using quantum-safe cryptography. It runs all three security levels (ML-KEM-512, 768, 1024) and displays the key sizes.",
     "1. Open the app and click the ML-KEM Key Exchange tab.\n2. Click the Run button.\n3. A table appears showing public key size, private key size, ciphertext size and PASS/FAIL status.\n4. If all three rows show PASS then key exchange is working correctly.\n5. Notice that higher security levels have larger keys."),
    ("10", "Module Guide: ML-DSA Digital Signatures",
     "This module generates quantum-safe digital signatures at three security levels. It signs a test message and verifies the signature to confirm authenticity.",
     "1. Open the ML-DSA Signatures tab.\n2. Click Run.\n3. The table shows public key, private key and signature sizes for each level.\n4. All three should show VALID status.\n5. Compare the signature sizes. ML-DSA-87 signatures are about 4.6KB which is much larger than classical signatures."),
    ("11", "Module Guide: Hybrid TLS Handshake",
     "This module simulates how modern browsers (like Google Chrome) establish a secure connection using both classical and quantum-safe cryptography together. This is called the hybrid approach.",
     "1. Open the Hybrid TLS tab.\n2. Click Run.\n3. Read through the step-by-step output in the text box.\n4. Look for the MATCH status at the end.\n5. The output explains why using both algorithms together is safer than using just one."),
    ("12", "Module Guide: Certificate Migration",
     "This module compares the sizes of classical certificates (RSA, ECDSA) with post-quantum key sizes. It helps you understand one of the biggest challenges of upgrading the internet.",
     "1. Open the Certificate Migration tab.\n2. Click Run.\n3. The table shows RSA-2048, RSA-4096 and ECDSA P-256 certificate sizes in bytes.\n4. Below that you see ML-DSA-65 and ML-DSA-87 key sizes.\n5. Notice that PQC keys are 3 to 10 times larger than classical keys."),
    ("13", "Module Guide: Performance Benchmarks",
     "This module measures how fast each cryptographic operation runs on your computer. It runs each operation three times and shows the average time in milliseconds.",
     "1. Open the Benchmarks tab.\n2. Click Run.\n3. Two tables appear. One for ML-KEM timing and one for ML-DSA timing.\n4. KeyGen is the time to create a key pair.\n5. Sign is the time to sign a message (usually the slowest operation).\n6. For reference a human blink takes about 300 milliseconds."),
    ("14", "Module Guide: Hybrid Certificate Chain",
     "This module generates a three-level certificate chain Root CA to Intermediate to Leaf using REAL X.509 certificates with ML-DSA public keys embedded as custom extensions. Each certificate carries BOTH a classical RSA signature AND an ML-DSA signature.",
     "1. Open the Hybrid Cert Chain tab.\n2. Click Run.\n3. Read the step-by-step output showing each certificate.\n4. Each cert has an RSA signature AND an ML-DSA signature embedded.\n5. Both signatures are verified independently showing VALID status.\n6. This is the exact model enterprises will use for PQC migration."),
    ("15", "Module Guide: Attack Demo (Harvest Now Decrypt Later)",
     "This module demonstrates why PQC migration is urgent. It simulates the Harvest Now Decrypt Later attack: hackers record encrypted traffic today, wait for quantum computers, and decrypt it later.",
     "1. Open the Attack Demo tab.\n2. Click Run.\n3. Alice sends a secret message encrypted with small RSA.\n4. Eve records the ciphertext now (Harvest Now).\n5. Later Eve factors the RSA modulus and decrypts (Decrypt Later).\n6. The demo then shows that ML-KEM-768 prevents this attack entirely.\n7. The message is recovered successfully showing the vulnerability."),
    ("16", "Module Guide: Wire-Format Inspection",
     "This module shows the actual bytes of PQC keys, ciphertexts, and signatures in a hex dump with annotations. You can see the internal structure of each cryptographic artifact.",
     "1. Open the Wire Format tab.\n2. Click Run.\n3. A hex dump of ML-KEM-768 public key appears with byte offsets.\n4. Below that is the ciphertext, ML-DSA public key, and signature.\n5. Each section shows the internal structure (seed, polynomials, challenge, vector).\n6. A size comparison table shows all PQC artifacts side by side."),
    ("17", "Module Guide: Migration Impact Calculator",
     "This module estimates the real-world cost of switching to post-quantum cryptography. You can see how much extra storage and bandwidth PQC migration will require.",
     "1. Open the Impact Calc tab.\n2. Click Run.\n3. The calculator shows certificate sizes for classical, hybrid, and PQC-only.\n4. Storage impact for all certificates is calculated.\n5. Bandwidth impact per TLS handshake is shown.\n6. Cumulative extra bandwidth over months and years is estimated.\n7. The conclusion: the bandwidth cost is generally acceptable for modern networks."),
]
for num, title, desc, steps in modules:
    pdf.add_page()
    pdf.ch(f"{num}. {title}")
    pdf.t(desc)
    pdf.b("What you will see:")
    for s in steps.split("\n"):
        pdf.t("  " + s.strip())

# ═══════════════ 15. RESULTS ═══════════════
pdf.add_page()
pdf.ch("18. Understanding the Results")
pdf.t("Here is what the different statuses and numbers mean:")
pdf.b("PASS / VALID / MATCH")
pdf.t("The operation completed successfully. For KEM this means both parties derived the same secret key. For signatures this means the signature was verified correctly. For TLS this means the client and server computed the same session key.")
pdf.b("FAIL / INVALID / MISMATCH")
pdf.t("Something went wrong. This should never happen in normal operation. If you see this restart the module and try again.")
pdf.b("Key Sizes (bytes)")
pdf.t("One byte is roughly one character of text. An RSA-2048 public key is 256 bytes or about the length of a tweet. An ML-KEM-1024 public key is 1568 bytes or about half a page of text.")
pdf.b("Timing (milliseconds)")
pdf.t("One millisecond is one thousandth of a second. A blink takes about 300 milliseconds. Most PQC operations complete in 2 to 50 milliseconds which is faster than a blink. Signing is usually the slowest operation.")

# ═══════════════ 16. FAQ ═══════════════
pdf.add_page()
pdf.ch("19. Frequently Asked Questions")
pdf.b("Is this safe to use for real encryption?")
pdf.t("No. The pure Python libraries used in this toolkit are for educational purposes only. They are not constant-time and may have side-channel vulnerabilities. For real security use liboqs (the C library) or OpenSSL 3.5.")
pdf.b("Why are PQC keys so much larger than RSA keys?")
pdf.t("PQC algorithms are based on different mathematics (lattice problems) that require more data to achieve the same security level. RSA-2048 has 256-byte keys while ML-KEM-1024 has 1568-byte keys. This is one of the main challenges of migration.")
pdf.b("Can I use this on Mac or Linux?")
pdf.t("Yes. The Python code is cross-platform. Run the same commands on any operating system. The GUI app uses tkinter which works on all platforms.")
pdf.b("Do I need internet to run this?")
pdf.t("No. Once you install the dependencies everything runs locally on your computer. No internet connection is required.")
pdf.b("What if I see errors about missing modules?")
pdf.t("Run the install command again: pip install kyber-py dilithium-py matplotlib cryptography. Make sure you have Python 3.9 or newer.")
pdf.b("How long does each module take to run?")
pdf.t("KEM and Signature modules take about 2-3 seconds. TLS and Certificate modules take about 5 seconds. Benchmarks take about 30 seconds because they run each operation multiple times.")

# ═══════════════ 17. TROUBLESHOOTING ═══════════════
pdf.add_page()
pdf.ch("20. Troubleshooting Common Issues")
pdf.b("'pip' is not recognized as a command")
pdf.t("Python is not installed or not added to PATH. Download and install Python from python.org. During installation check the box that says Add Python to PATH.")
pdf.b("'No module named kyber-py' error")
pdf.t("You forgot to install the dependencies. Run: pip install kyber-py dilithium-py matplotlib cryptography")
pdf.b("GUI window opens but is blank")
pdf.t("Wait a few seconds for the interface to load. If it stays blank try running python gui_app.py from a terminal to see any error messages.")
pdf.b("The app freezes when I click Run")
pdf.t("This is normal. Cryptographic operations take a moment to compute especially benchmarks. Wait 5-10 seconds for the results to appear. The app will unfreeze once the operation completes.")
pdf.b("I see a DeprecationWarning in the terminal")
pdf.t("These warnings are harmless and do not affect functionality. They come from the Python libraries and can be ignored.")
pdf.b("Permission denied when installing packages")
pdf.t("Try adding --user to the pip command: pip install --user kyber-py dilithium-py matplotlib cryptography")

# ═══════════════ 18. GLOSSARY ═══════════════
pdf.add_page()
pdf.ch("21. Glossary of Terms")
glossary = [
    ("Certificate",     "A digital document that proves the identity of a website or organization. Contains a public key and is signed by a trusted authority."),
    ("Ciphertext",      "The encrypted output. The locked box that contains the secret message."),
    ("Decapsulation",   "The process of unlocking a shared secret using a private key in a KEM scheme."),
    ("Digital Signature","A cryptographic proof that a message was created by a specific sender and has not been altered."),
    ("Encapsulation",   "The process of locking a shared secret using a public key in a KEM scheme."),
    ("FIPS",            "Federal Information Processing Standards. Official US government standards for cryptography."),
    ("KEM",             "Key Encapsulation Mechanism. A method for two parties to establish a shared secret key."),
    ("KeyGen",          "The process of generating a new cryptographic key pair (public and private)."),
    ("Lattice",         "A mathematical structure used in PQC algorithms. Think of it as a grid of points in multi-dimensional space."),
    ("ML-KEM",          "Module-Lattice-Based Key Encapsulation Mechanism. The NIST standard for quantum-safe key exchange."),
    ("ML-DSA",          "Module-Lattice-Based Digital Signature Algorithm. The NIST standard for quantum-safe signatures."),
    ("NIST",            "National Institute of Standards and Technology. The US agency that standardized PQC algorithms."),
    ("PQC",             "Post-Quantum Cryptography. Cryptographic algorithms designed to resist quantum computer attacks."),
    ("Public Key",      "A key that can be shared openly. Used to encrypt messages or verify signatures."),
    ("Private Key",     "A secret key that must be kept confidential. Used to decrypt messages or create signatures."),
    ("Quantum Computer","A computer that uses quantum mechanics to solve certain problems exponentially faster than classical computers."),
    ("RSA",             "A classical encryption algorithm based on the difficulty of factoring large numbers. Vulnerable to quantum computers."),
    ("TLS",             "Transport Layer Security. The protocol that secures HTTPS websites and encrypted communications."),
]
for term, defn in glossary:
    pdf.b(term)
    pdf.t(defn, sz=9)

# ═══════════════ 19. REFERENCES ═══════════════
pdf.add_page()
pdf.ch("22. References and Further Reading")
pdf.b("Beginner-Friendly Resources:")
pdf.t("NIST PQC Website: nist.gov/pqc")
pdf.t("Cloudflare PQC Learning Center: cloudflare.com/learning/ssl/post-quantum-cryptography")
pdf.t("YouTube: Post-Quantum Cryptography in 5 Minutes")
pdf.t("YouTube: Quantum Computers Explained by Kurzgesagt")
pdf.ln(5)
pdf.b("Official Standards Documents:")
pdf.t("NIST FIPS 203 ML-KEM Standard: csrc.nist.gov/pubs/fips/203/final")
pdf.t("NIST FIPS 204 ML-DSA Standard: csrc.nist.gov/pubs/fips/204/final")
pdf.t("NIST FIPS 205 SLH-DSA Standard: csrc.nist.gov/pubs/fips/205/final")
pdf.ln(5)
pdf.b("Libraries Used in This Project:")
pdf.t("kyber-py (pure Python ML-KEM): github.com/GiacomoPope/kyber-py")
pdf.t("dilithium-py (pure Python ML-DSA): github.com/GiacomoPope/dilithium-py")
pdf.t("Open Quantum Safe (liboqs C library): openquantumsafe.org")
pdf.t("OpenSSL 3.5 (PQC support in production): openssl.org")
pdf.ln(5)
pdf.b("Who Already Uses PQC:")
pdf.t("- Google Chrome (2024+) - X25519MLKEM768 hybrid key exchange")
pdf.t("- Signal Messenger (2023+) - PQXDH protocol with Kyber")
pdf.t("- Apple iMessage (2024+) - Post-quantum encryption")
pdf.t("- Amazon Web Services (2020+) - PQC in AWS KMS")
pdf.t("- Cloudflare - PQC available to all customers")
pdf.ln(10)
pdf.set_text_color(*TEXT)
pdf.set_font("Helvetica", "I", 10)
pdf.cell(0, 6, "Thank you for using the PQC Migration Toolkit.", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 6, "The future of encryption starts with understanding it today.", align="C", new_x="LMARGIN", new_y="NEXT")

pdf.output(PDF_PATH)
print(f"Handbook saved to: {PDF_PATH}")
print(f"Total pages: {pdf.page_no()}")
