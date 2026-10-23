from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
import os

PPT_PATH = r"E:\pqc-migration-toolkit\PQC_Migration_Toolkit.pptx"
CHART_PATH = r"E:\pqc-migration-toolkit\benchmarks\pqc_benchmark.png"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

BG = RGBColor(0x1A, 0x1A, 0x2E)
ACCENT = RGBColor(0x00, 0xD2, 0xFF)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
GRAY = RGBColor(0xBB, 0xBB, 0xBB)

def slide():
    s = prs.slides.add_slide(prs.slide_layouts[6])
    bg = s.background.fill; bg.solid(); bg.fore_color.rgb = BG
    return s

def tb(s, text, top=0.3, left=0.5, w=12, h=1, sz=36, clr=ACCENT):
    t = s.shapes.add_textbox(Inches(left), Inches(top), Inches(w), Inches(h))
    p = t.text_frame.paragraphs[0]; p.text = text; p.font.size = Pt(sz)
    p.font.color.rgb = clr; p.font.bold = True; return t

def bx(s, text, top=1.5, left=0.7, w=11.5, h=5.5, sz=16):
    t = s.shapes.add_textbox(Inches(left), Inches(top), Inches(w), Inches(h))
    tf = t.text_frame; tf.word_wrap = True
    for i, line in enumerate(text.split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line; p.font.size = Pt(sz); p.font.color.rgb = WHITE; p.space_after = Pt(4)
    return t

# Slide 1 - Title
s = slide(); tb(s, "Post-Quantum Cryptography Migration Toolkit", top=1.5, sz=44)
bx(s, "A beginner-friendly guide to the new encryption standards that will\nprotect us from quantum computers\n\nNo technical background needed - everything explained from scratch\n\nMade with Python  |  kyber-py  |  dilithium-py  |  matplotlib\n\n100% free and open-source", top=3.2, sz=20)

# Slide 2 - What is Encryption
s = slide(); tb(s, "First: What is Encryption? (Simple Explanation)")
bx(s, "Imagine you want to send a secret message across a crowded room.\nEveryone can see it, so you need to LOCK it so only your friend can open it.\n\nThat's what encryption does - it LOCKS your data so only the person with the RIGHT KEY can read it.\n\n  Public Key  = A lock anyone can use to lock a message\n  Private Key = The unique key that opens that specific lock\n  Signature   = Like a wax seal - proves the message is really from you\n\nReal-world examples:\n  When you visit https://google.com, your browser uses encryption\n  When you send a WhatsApp message, it's encrypted\n  When you sign into a website, encryption protects your password\n\nCurrent encryption uses math that is HARD for normal computers.\nBut quantum computers will solve it EASILY. We need NEW math!", sz=15)

# Slide 3 - The Problem
s = slide(); tb(s, "The Problem: Why Quantum Computers Break Encryption")
bx(s, "Regular computers use BITS (0s and 1s). Quantum computers use QUBITS -\nthey can be 0 and 1 AT THE SAME TIME. This lets them solve certain\nproblems MILLIONS of times faster.\n\nIn 1994, mathematician Peter Shor discovered quantum computers could break:\n  RSA encryption (used for securing websites)\n  ECDH/ECDSA (used in cryptocurrencies, secure messaging)\n\nThink of it like this:\n  Current encryption = A giant maze that takes years to solve\n  Quantum computer   = A helicopter that flies OVER the maze in seconds\n\nThe scary part: Hackers are ALREADY collecting encrypted data today,\nwaiting for quantum computers so they can decrypt it later.\nThis is called 'Harvest Now, Decrypt Later.'", sz=15)

# Slide 4 - NIST Standards
s = slide(); tb(s, "The Solution: Post-Quantum Cryptography (PQC)")
bx(s, "Post-Quantum Cryptography = New math problems hard for BOTH regular AND quantum computers.\n\nFrom 2016 to 2024, NIST ran a worldwide competition. After 8 years of\ntesting, they chose the winners. In August 2024, NIST released THREE standards:\n\n  1. ML-KEM (Kyber) - For SECRET KEY EXCHANGE\n     Replaces: RSA and ECDH\n     Use case: Establishing a secure connection to a website\n\n  2. ML-DSA (Dilithium) - For DIGITAL SIGNATURES\n     Replaces: RSA signatures and ECDSA\n     Use case: Proving who sent a message or signed a document\n\n  3. SLH-DSA (SPHINCS+) - Backup signature method\n     Different math approach, in case ML-DSA is broken later\n\nThink of ML-KEM as a NEW type of lock, and ML-DSA as a NEW type of wax seal.", sz=15)

# Slide 5 - Analogies
s = slide(); tb(s, "Understanding PQC Through Everyday Analogies")
bx(s, "ML-KEM (Key Exchange) = A Special Lock\n"
      "  Old lock (RSA/ECDH): Quantum computer can crush it\n"
      "  New lock (ML-KEM): Even quantum computers can't break it\n"
      "  You give out copies of this lock (public key) to everyone\n"
      "  Only your private key can open messages locked with it\n\n"
      "ML-DSA (Digital Signatures) = A Tamper-Proof Wax Seal\n"
      "  Old seal: Quantum computers can forge it\n"
      "  New seal: Impossible to forge, even with quantum computers\n\n"
      "The problem: These new locks and seals are BIGGER and HEAVIER\n"
      "  Old RSA key = 256 bytes (like a small padlock)\n"
      "  New ML-KEM key = 1184 bytes (like a large suitcase lock)\n"
      "  Old signature = ~70 bytes (like a postage stamp)\n"
      "  New signature = 3309 bytes (like a full letter!)\n\n"
      "This size increase is one of the biggest challenges of upgrading.", sz=14)

# Slide 6 - Menu
s = slide(); tb(s, "Meet the PQC Migration Toolkit")
bx(s, "This Python program demonstrates how the new PQC standards work.\nYou don't need to understand the complex math - it shows you the RESULTS.\n\n"
      "  +------------------------------------------------------+\n"
      "  |          PQC MIGRATION TOOLKIT - MAIN MENU           |\n"
      "  +------------------------------------------------------+\n"
      "  |  1.  ML-KEM Key Encapsulation Demo   (FIPS 203)      |\n"
      "  |  2.  ML-DSA Digital Signature Demo   (FIPS 204)      |\n"
      "  |  3.  Hybrid TLS 1.3 Handshake Demo                   |\n"
      "  |  4.  Certificate Migration Analysis                   |\n"
      "  |  5.  Performance Benchmarks + Charts                 |\n"
      "  |  6.  Run ALL modules sequentially                    |\n"
      "  |  0.  Exit                                            |\n"
      "  +------------------------------------------------------+", sz=14)

# Slide 7-11: Modules
s = slide(); tb(s, "Module 1: ML-KEM Key Exchange")
bx(s, "WHAT IT DOES:\n  Two people (Alice and Bob) share a secret key to encrypt messages.\n\nHOW IT WORKS:\n"
      "  1. Alice creates a lock (public key) and keeps the only key (private)\n"
      "  2. Alice gives Bob a copy of her lock\n"
      "  3. Bob uses that lock to lock a secret message (shared secret)\n"
      "  4. Bob sends the locked box (ciphertext) back to Alice\n"
      "  5. Alice uses her private key to open the box and read the secret\n\n"
      "WHAT THE PROGRAM SHOWS:\n  Key sizes at different security levels\n"
      "  Whether the two shared secrets match\n  Comparison with old RSA keys\n\n"
      "KEY INSIGHT: This works EVEN if someone is watching the conversation!", sz=15)

s = slide(); tb(s, "Module 2: ML-DSA Digital Signatures")
bx(s, "WHAT IT DOES:\n  Prove that YOU wrote a message and nobody changed it.\n  Like signing a check, but much more secure.\n\nHOW IT WORKS:\n"
      "  1. You create a signing key (private) and a verification key (public)\n"
      "  2. You 'sign' your message with your private key - creates a signature\n"
      "  3. Anyone can VERIFY the signature using your public key\n"
      "  4. Change even ONE letter - signature becomes invalid\n\n"
      "REAL WORLD EXAMPLE:\n  Downloading software? The developer signs it.\n"
      "  Your computer checks the signature before installing.\n"
      "  If tampered, the signature won't match.\n\n"
      "With PQC, this check stays secure even against quantum computers.", sz=15)

s = slide(); tb(s, "Module 3: Hybrid TLS Handshake")
bx(s, "WHAT IT DOES:\n  Simulates how Chrome connects to websites using BOTH old AND new encryption.\n\nWHY BOTH? (Important!)\n"
      "  Nobody knows when quantum computers arrive (5 years? 20?).\n  If we switch ONLY to PQC and it has a bug, we're unprotected.\n"
      "  Solution: Use BOTH and COMBINE them.\n\nTHE GUARANTEE:\n"
      "  If quantum breaks X25519      -> ML-KEM still protects you\n"
      "  If someone breaks ML-KEM      -> X25519 still protects you\n"
      "  You're safe either way!\n\nHOW IT WORKS:\n"
      "  1. Client creates a classical key (X25519) AND a PQC key (ML-KEM)\n"
      "  2. BOTH public keys sent to server\n"
      "  3. Server does the same - sends BOTH back\n"
      "  4. Both sides compute TWO shared secrets and MIX them together\n"
      "  5. Final session key is a COMBINATION of both\n\n"
      "This is EXACTLY what Google Chrome has been doing since 2024.", sz=14)

s = slide(); tb(s, "Module 4: Certificate Migration Analysis")
bx(s, "WHAT IT DOES:\n  Compares sizes of old certificates vs new PQC keys.\n  Shows the REAL challenge of upgrading the internet.\n\nWHAT IS A CERTIFICATE?\n"
      "  Think of it as an ID card: 'This website is really your bank.'\n\nTHE SIZE PROBLEM:\n"
      "  Old RSA-2048 certificate:         ~993 bytes (fits in one internet packet)\n"
      "  New ML-DSA-65 public key:        ~1952 bytes\n"
      "  New ML-DSA-65 signature:         ~3309 bytes\n\nWHY SIZE MATTERS:\n"
      "  Internet packets max size (MTU) = 1500 bytes\n"
      "  Bigger certs = split across multiple packets = slower loading\n"
      "  Mobile phones and slow connections suffer the most\n\nHYBRID SOLUTION:\n"
      "  Certs containing BOTH old RSA AND new PQC keys.\n"
      "  This is what Chrome and Cloudflare are implementing now.", sz=14)

s = slide(); tb(s, "Module 5: Performance Benchmarks")
bx(s, "WHAT IT DOES:\n  Measures how fast each PQC operation runs on your computer.\n  Like a stopwatch for encryption.\n\nWHAT THE NUMBERS MEAN:\n"
      "  KeyGen = Time to create a new key pair\n  Encaps = Time to lock a secret with a public key\n"
      "  Decaps = Time to unlock with the private key\n  Sign   = Time to sign a message\n"
      "  Verify = Time to check a signature\n\nSAMPLE RESULTS:\n"
      "  ML-KEM-512:  KeyGen 1.6ms | Encaps 2.4ms | Decaps 3.2ms\n"
      "  ML-KEM-768:  KeyGen 2.7ms | Encaps 3.6ms | Decaps 4.6ms\n"
      "  ML-KEM-1024: KeyGen 4.0ms | Encaps 5.0ms | Decaps 6.8ms\n\n"
      "  ML-DSA-44:  KeyGen 5.6ms | Sign 28ms  | Verify 5.8ms\n"
      "  ML-DSA-65:  KeyGen 7.8ms | Sign 43ms  | Verify 8.9ms\n"
      "  ML-DSA-87:  KeyGen 12ms  | Sign 46ms  | Verify 14ms\n\n"
      "For comparison: Blinking takes ~300ms. All these are faster than a blink!", sz=14)

if os.path.exists(CHART_PATH):
    s = slide(); tb(s, "Performance Benchmark Chart", sz=32)
    s.shapes.add_picture(CHART_PATH, Inches(1.5), Inches(1.5), width=Inches(10), height=Inches(4.5))

# Slide - Who uses PQC
s = slide(); tb(s, "Who Is Already Using PQC Right Now?")
bx(s, "This is not future technology. It's already being deployed:\n\n"
      "GOOGLE CHROME (2024+) - X25519 + ML-KEM hybrid for all TLS connections\n"
      "SIGNAL MESSENGER (2023+) - Kyber in PQXDH protocol\n"
      "APPLE iMESSAGE (2024+) - Kyber for post-quantum security\n"
      "AMAZON WEB SERVICES (2020+) - AWS KMS supports PQC\n"
      "CLOUDFLARE - Offers PQC to all their customers (20% of all websites)\n"
      "OPENSSL 3.5 (April 2025) - Most used crypto library, now has native PQC\n\n"
      "PQC is happening NOW, not in the distant future.", sz=16)

# Slide - Challenges
s = slide(); tb(s, "Challenges of Switching to PQC")
bx(s, "Like replacing all locks in every building in every city at once:\n\n"
      "1. BIGGER KEYS - 3-10x larger, more data to send\n"
      "2. SLOWER OPERATIONS - PQC signing is 5-10x slower than ECDSA\n"
      "3. HARDWARE UPGRADES - Banks need new hardware security modules\n"
      "4. BACKWARD COMPATIBILITY - Old devices need to work alongside new\n"
      "5. STANDARDS TAKE TIME - Every protocol needs updating (years)\n\n"
      "That's why organizations need to START PLANNING NOW.", sz=16)

# Slide - How to Run
s = slide(); tb(s, "How to Run This Program")
bx(s, "Step 1: Install Python 3.9+ (python.org)\n"
      "Step 2: pip install kyber-py dilithium-py matplotlib cryptography\n"
      "Step 3: python main.py\n"
      "Step 4: Pick a number from the menu and press Enter\n\n"
      "That's it! No cloud accounts, no API keys, no setup needed.\n\n"
      "To run individual modules separately:\n"
      "  python src/kem_demo.py\n"
      "  python src/sign_demo.py\n"
      "  python src/hybrid_tls_demo.py\n"
      "  python src/cert_migration_demo.py\n"
      "  python src/benchmark.py", sz=16)

# Slide - Why You Should Care
s = slide(); tb(s, "Why Should YOU Care About PQC?")
bx(s, "PERSONAL:\n  Your bank, WhatsApp, and emails are encrypted.\n"
      "  Hackers collect encrypted data NOW to decrypt LATER.\n"
      "  Your medical records, tax returns could be exposed.\n\n"
      "PROFESSIONAL:\n  Companies need people who understand PQC.\n"
      "  Governments are mandating PQC adoption (US, EU, India).\n"
      "  This is a NEW SKILL in high demand.\n\n"
      "ACADEMIC (for students):\n"
      "  The standards were finalized in 2024 - this is BRAND NEW.\n"
      "  Most engineers haven't learned this yet.\n"
      "  A PQC project stands out in college and job interviews.\n\n"
      "BOTTOM LINE: Encryption keeps the digital world safe.\n"
      "Quantum computers will break today's locks.\n"
      "PQC is the new locks protecting us tomorrow.", sz=14)

# Slide - Key Takeaways
s = slide(); tb(s, "Key Takeaways")
bx(s, "1. Quantum computers threaten all current encryption\n\n"
      "2. NIST standardized new PQC algorithms in August 2024\n\n"
      "3. ML-KEM (Kyber) = New way to exchange secret keys\n\n"
      "4. ML-DSA (Dilithium) = New way to sign and verify\n\n"
      "5. PQC keys are 3-10x larger - the main challenge\n\n"
      "6. Chrome, Signal, Apple, AWS already use PQC\n\n"
      "7. Hybrid (old + new) is safer during transition\n\n"
      "8. OpenSSL 3.5 has PQC built-in - production ready\n\n"
      "9. This toolkit lets you EXPERIENCE PQC on your laptop\n\n"
      "10. Start learning NOW - it's the future of security", sz=16)

# Slide - References
s = slide(); tb(s, "References & Where to Learn More")
bx(s, "FOR BEGINNERS:\n"
      "  NIST PQC: nist.gov/pqc\n"
      "  Cloudflare PQC Guide: cloudflare.com/learning/ssl/post-quantum-cryptography\n"
      "  YouTube: 'Post-Quantum Cryptography in 5 Minutes'\n\n"
      "FOR STUDENTS/DEVELOPERS:\n"
      "  [1] FIPS 203 - ML-KEM Standard: csrc.nist.gov/pubs/fips/203/final\n"
      "  [2] FIPS 204 - ML-DSA Standard: csrc.nist.gov/pubs/fips/204/final\n"
      "  [3] Open Quantum Safe: openquantumsafe.org\n"
      "  [4] kyber-py: github.com/GiacomoPope/kyber-py\n"
      "  [5] dilithium-py: github.com/GiacomoPope/dilithium-py\n"
      "  [6] OpenSSL 3.5: github.com/openssl/openssl\n\n"
      "THIS PROJECT:\n"
      "  Location: E:\\pqc-migration-toolkit\\\n"
      "  Main file: main.py  |  Run: python main.py", sz=14)

prs.save(PPT_PATH)
print(f"Presentation saved to: {PPT_PATH}")
print(f"Total slides: {len(prs.slides)}")
