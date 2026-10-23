"""Secure Hybrid Chat — local encrypted chat using X25519 + ML-KEM-768.
Simulates a TLS-style handshake inside the GUI, with message encryption."""

import socket, threading, struct, os, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from src.pqc_wrapper import kem_keygen, kem_encaps, kem_decaps

HOST = "127.0.0.1"
PORT = 8765
SERVER_TIMEOUT = 30

class SecureChatServer:
    def __init__(self):
        self.server = None
        self.conn = None
        self.session_key = None
        self.running = False

    def start(self, on_log):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._run, args=(on_log,), daemon=True).start()

    def _run(self, on_log):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((HOST, PORT))
            self.server.listen(1)
            self.server.settimeout(SERVER_TIMEOUT)
            on_log(f"[Server] Listening on {HOST}:{PORT}")
            on_log("[Server] Waiting for client connection...")
            self.conn, addr = self.server.accept()
            on_log(f"[Server] Client connected from {addr[0]}:{addr[1]}")
            on_log("[Server] ClientHello received")
            self._handshake(on_log)
        except socket.timeout:
            on_log("[Server] Timed out waiting for client.")
            self._cleanup()
        except Exception as e:
            on_log(f"[Server] Error: {e}")
            self._cleanup()

    def _handshake(self, on_log):
        on_log("[Server] ServerHello + Certificate: X25519 + ML-KEM-768")
        s_xsk = x25519.X25519PrivateKey.generate()
        s_xpk = s_xsk.public_key().public_bytes_raw()
        s_kem_ek, s_kem_dk = kem_keygen("ML-KEM-768")
        self.conn.sendall(struct.pack("!I", len(s_xpk)) + s_xpk)
        self.conn.sendall(struct.pack("!I", len(s_kem_ek)) + s_kem_ek)

        c_xpk_len = struct.unpack("!I", self.conn.recv(4))[0]
        c_xpk = self.conn.recv(c_xpk_len)
        c_ct_len = struct.unpack("!I", self.conn.recv(4))[0]
        c_ct = self.conn.recv(c_ct_len)
        on_log(f"[Server] Client KEM ciphertext: {c_ct.hex()[:48]}... ({len(c_ct)}B)")

        s_xshared = s_xsk.exchange(x25519.X25519PublicKey.from_public_bytes(c_xpk))
        s_kem_shared = kem_decaps("ML-KEM-768", s_kem_dk, c_ct)
        self.session_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_CHAT_1.0"
        ).derive(s_xshared + s_kem_shared)
        on_log(f"[Server] Session key: {self.session_key[:8].hex()}...")
        on_log("[Server] Hybrid Key Exchange complete — session secured")

    def send(self, plaintext):
        if not self.conn or not self.session_key:
            return
        ct_bytes = _encrypt(plaintext, self.session_key)
        self.conn.sendall(struct.pack("!I", len(ct_bytes)) + ct_bytes)

    def recv(self, on_log):
        try:
            size = struct.unpack("!I", self.conn.recv(4))[0]
            ct_bytes = b""
            while len(ct_bytes) < size:
                chunk = self.conn.recv(size - len(ct_bytes))
                if not chunk:
                    raise ConnectionError
                ct_bytes += chunk
            plain = _decrypt(ct_bytes, self.session_key)
            return plain
        except Exception:
            return None

    def _cleanup(self):
        self.running = False
        try:
            if self.conn:
                self.conn.close()
            if self.server:
                self.server.close()
        except Exception:
            pass


class SecureChatClient:
    def __init__(self):
        self.sock = None
        self.session_key = None
        self.running = False

    def connect(self, on_log):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._run, args=(on_log,), daemon=True).start()

    def _run(self, on_log):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(SERVER_TIMEOUT)
            on_log(f"[Client] Connecting to {HOST}:{PORT}...")
            self.sock.connect((HOST, PORT))
            on_log("[Client] Connected")
            on_log("[Client] Sending ClientHello...")
            self._handshake(on_log)
        except Exception as e:
            on_log(f"[Client] Connection failed: {e}")
            self._cleanup()

    def _handshake(self, on_log):
        c_xsk = x25519.X25519PrivateKey.generate()
        c_xpk = c_xsk.public_key().public_bytes_raw()
        c_ek, c_dk = kem_keygen("ML-KEM-768")

        s_xpk_len = struct.unpack("!I", self.sock.recv(4))[0]
        s_xpk = self.sock.recv(s_xpk_len)
        s_kem_ek_len = struct.unpack("!I", self.sock.recv(4))[0]
        s_kem_ek = self.sock.recv(s_kem_ek_len)
        on_log(f"[Client] ServerHello + Certificate received")
        on_log(f"[Client] Server X25519 pubkey: {len(s_xpk)}B, ML-KEM pubkey: {len(s_kem_ek)}B")

        c_xshared = c_xsk.exchange(x25519.X25519PublicKey.from_public_bytes(s_xpk))
        s_kem_shared, ct = kem_encaps("ML-KEM-768", s_kem_ek)

        self.sock.sendall(struct.pack("!I", len(c_xpk)) + c_xpk)
        self.sock.sendall(struct.pack("!I", len(ct)) + ct)
        on_log(f"[Client] Sending KEM ciphertext: {ct.hex()[:48]}... ({len(ct)}B)")

        self.session_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"HYBRID_CHAT_1.0"
        ).derive(c_xshared + s_kem_shared)
        on_log(f"[Client] Session key: {self.session_key[:8].hex()}...")
        on_log("[Client] Hybrid Key Exchange complete — session secured")

    def send(self, plaintext):
        if not self.sock or not self.session_key:
            return
        ct_bytes = _encrypt(plaintext, self.session_key)
        self.sock.sendall(struct.pack("!I", len(ct_bytes)) + ct_bytes)

    def recv(self, on_log):
        try:
            size = struct.unpack("!I", self.sock.recv(4))[0]
            ct_bytes = b""
            while len(ct_bytes) < size:
                chunk = self.sock.recv(size - len(ct_bytes))
                if not chunk:
                    raise ConnectionError
                ct_bytes += chunk
            plain = _decrypt(ct_bytes, self.session_key)
            return plain
        except Exception:
            return None

    def _cleanup(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass


def _encrypt(plaintext, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + struct.pack("!I", len(ciphertext)) + ciphertext


def _decrypt(data, key):
    iv = data[:12]
    tag = data[12:28]
    ct_len = struct.unpack("!I", data[28:32])[0]
    ct = data[32:32 + ct_len]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()
