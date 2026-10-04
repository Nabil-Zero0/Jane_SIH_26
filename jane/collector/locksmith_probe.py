"""
Jane Collector — Locksmith Onion Prober
Runs strictly inside Whonix-Workstation via Tor SOCKS proxy (10.152.152.10:9050).
Pure Python standard library (no pip packages, no sudo).

Probes:
  1. /favicon.ico -> Shodan mmh3 hash (computed in RAM, zero bytes saved to disk)
  2. /server-status -> Apache mod_status public IP leak detection
  3. Server headers -> Exact banner & ETag matching
  4. Common misconfigs: /.git/HEAD, /phpinfo.php, /.env

Outputs results to VirtualBox shared folder:
  /media/sf_Jane_SIH_26/data/drop/incoming/locksmith_<batch_id>.json
"""

from __future__ import annotations

import argparse
import codecs
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import urllib.request
import urllib.error
import uuid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("jane.collector.locksmith")

SOCKS_GATEWAY_IP = "10.152.152.10"
SOCKS_PORT = 9050
DEFAULT_TIMEOUT = 25

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
IP_REGEX = re.compile(r"\b(?!(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.))(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def resolve_drop_directory() -> Path:
    """Finds the writable shared folder drop path."""
    candidates = [
        Path("/media/sf_Jane_SIH_26/data/drop/incoming"),
        Path(__file__).resolve().parent.parent.parent / "data" / "drop" / "incoming",
    ]
    for c in candidates:
        try:
            c.mkdir(parents=True, exist_ok=True)
            test_f = c / f".write_test_{uuid.uuid4().hex[:6]}"
            test_f.write_text("ok", encoding="utf-8")
            test_f.unlink()
            return c
        except Exception:
            continue
    fallback = Path("/tmp/data/drop/incoming")
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def mmh3_32(key: bytes, seed: int = 0) -> int:
    """
    Pure Python 32-bit MurmurHash3 implementation.
    Matches Shodan favicon hash algorithm exactly without third-party C extensions.
    """
    length = len(key)
    nblocks = length // 4
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for i in range(nblocks):
        k1 = int.from_bytes(key[i * 4 : (i + 1) * 4], byteorder="little")
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    tail = key[nblocks * 4 :]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)

    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def compute_shodan_favicon_hash(raw_icon_bytes: bytes) -> Tuple[int, str]:
    """
    Computes Shodan-compatible favicon hash:
    Base64 encoded with lines wrapped every 76 chars, hashed via mmh3 32-bit.
    """
    import hashlib
    sha256 = hashlib.sha256(raw_icon_bytes).hexdigest()
    b64_encoded = codecs.encode(raw_icon_bytes, "base64")
    shodan_hash = mmh3_32(b64_encoded)
    return shodan_hash, sha256


class TorSocksConnection:
    """Minimal SOCKS5 socket wrapper over standard Python socket."""
    @staticmethod
    def create_connection(dest_host: str, dest_port: int, timeout: int = DEFAULT_TIMEOUT) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((SOCKS_GATEWAY_IP, SOCKS_PORT))

        # SOCKS5 handshake (No auth)
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
            sock.close()
            raise ConnectionError(f"SOCKS5 auth rejected by {SOCKS_GATEWAY_IP}:{SOCKS_PORT}")

        # SOCKS5 domain connection request
        host_bytes = dest_host.encode("idna")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + dest_port.to_bytes(2, "big")
        sock.sendall(req)

        res = sock.recv(4)
        if len(res) < 4 or res[1] != 0x00:
            sock.close()
            raise ConnectionError(f"SOCKS5 connection to {dest_host}:{dest_port} failed (code {res[1] if len(res) > 1 else 'EOF'})")

        # Drain address field
        addr_type = res[3]
        if addr_type == 0x01:
            sock.recv(4)
        elif addr_type == 0x03:
            dlen = sock.recv(1)[0]
            sock.recv(dlen)
        elif addr_type == 0x04:
            sock.recv(16)
        sock.recv(2)  # port
        return sock


def http_tor_get(
    url: str,
    max_bytes: int = 500_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[int, Dict[str, str], bytes]:
    """
    Performs raw HTTP GET over Tor SOCKS5 socket with zero external dependencies.
    Returns (status_code, headers_dict, body_bytes).
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if not host.endswith(".onion"):
        # For clearnet fallback inside Whonix
        pass

    sock = TorSocksConnection.create_connection(host, port, timeout=timeout)
    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        sock.sendall(req)

        chunks = []
        total = 0
        while total < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

        raw = b"".join(chunks)
    finally:
        sock.close()

    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, {}, raw

    header_part = raw[:header_end].decode("latin-1", errors="replace")
    body = raw[header_end + 4 :]

    lines = header_part.split("\r\n")
    status_code = 0
    if lines and len(lines[0].split()) >= 2:
        try:
            status_code = int(lines[0].split()[1])
        except ValueError:
            pass

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return status_code, headers, body


def probe_onion_target(onion_domain: str) -> Dict[str, Any]:
    """
    Executes full Locksmith probe suite against an onion target.
    """
    onion = onion_domain.strip().lower()
    if onion.startswith("http://"):
        onion = onion[7:]
    if onion.startswith("https://"):
        onion = onion[8:]
    onion = onion.split("/")[0]

    base_url = f"http://{onion}"
    logger.info(f"[*] Starting Locksmith probe for: {base_url}")

    result: Dict[str, Any] = {
        "target": base_url,
        "onion_address": onion,
        "probed_at": datetime.now(timezone.utc).isoformat(),
        "server_banner": None,
        "etag": None,
        "favicon": None,
        "server_status": None,
        "misconfigs": {},
        "leaked_ips": [],
    }

    # 1. Base check (Root banner & ETag)
    try:
        status, headers, body = http_tor_get(f"{base_url}/", max_bytes=100_000)
        result["root_http_status"] = status
        result["server_banner"] = headers.get("server")
        result["etag"] = headers.get("etag")
        logger.info(f"  [+] Root status: {status} | Server: {result['server_banner']} | ETag: {result['etag']}")
    except Exception as e:
        logger.warning(f"  [-] Root probe failed: {e}")
        result["root_http_status"] = 0

    # 2. Favicon Probe
    favicon_urls = [f"{base_url}/favicon.ico"]
    for fav_url in favicon_urls:
        try:
            status, headers, body = http_tor_get(fav_url, max_bytes=200_000)
            if status == 200 and len(body) > 20:
                shodan_hash, sha256 = compute_shodan_favicon_hash(body)
                result["favicon"] = {
                    "url": fav_url,
                    "byte_size": len(body),
                    "mmh3_hash": shodan_hash,
                    "sha256": sha256,
                    "shodan_query": f"http.favicon.hash:{shodan_hash}",
                }
                logger.info(f"  [+] Favicon captured: {len(body)} bytes | mmh3: {shodan_hash} (Query: http.favicon.hash:{shodan_hash})")
                break
        except Exception as e:
            logger.debug(f"Favicon probe error: {e}")

    # 3. Apache mod_status Probe (/server-status)
    try:
        status, headers, body = http_tor_get(f"{base_url}/server-status?auto", max_bytes=100_000)
        if status == 200:
            text = body.decode("utf-8", errors="replace")
            # Look for Apache Scoreboard or ServerUptime
            if "Total Accesses:" in text or "Uptime:" in text or "ServerVersion:" in text:
                logger.warning(f"  [!] CRITICAL: /server-status is OPEN on {onion}!")
                # Scan for leaked clearnet IPs
                leaks = list(set(IP_REGEX.findall(text)))
                result["server_status"] = {
                    "open": True,
                    "mode": "auto",
                    "preview": text[:500],
                    "leaked_ips": leaks,
                }
                result["leaked_ips"].extend(leaks)
        else:
            result["server_status"] = {"open": False, "status": status}
    except Exception as e:
        result["server_status"] = {"open": False, "error": str(e)}

    # 4. Common Misconfiguration & SEO Probes
    probes = [
        ("/robots.txt", "Disallow:"),
        ("/sitemap.xml", "<urlset"),
        ("/sitemap_index.xml", "<sitemapindex"),
        ("/.git/HEAD", "ref: refs/"),
        ("/.env", "DB_"),
        ("/phpinfo.php", "PHP Version"),
    ]
    for path, signature in probes:
        try:
            status, headers, body = http_tor_get(f"{base_url}{path}", max_bytes=50_000)
            text = body.decode("utf-8", errors="replace")
            is_match = (status == 200 and signature in text)
            result["misconfigs"][path] = {
                "status": status,
                "exposed": is_match,
            }
            if is_match:
                logger.warning(f"  [!] CRITICAL: Exposed sensitive endpoint: {path}")
                leaks = list(set(IP_REGEX.findall(text)))
                result["leaked_ips"].extend(leaks)
        except Exception:
            result["misconfigs"][path] = {"status": 0, "exposed": False}

    result["leaked_ips"] = list(set(result["leaked_ips"]))
    return result


def main():
    parser = argparse.ArgumentParser(description="Jane Locksmith — Dark Web Infrastructure Prober")
    parser.add_argument(
        "--target",
        type=str,
        default="unimktsvidgh7bzkgxclqvpioubz7cpn5ty4jftnmuxx6ish6xudebqd.onion",
        help="Target .onion domain to probe",
    )
    parser.add_argument(
        "--targets-file",
        type=str,
        help="Optional text file with list of .onion addresses (one per line)",
    )
    args = parser.parse_args()

    targets: List[str] = []
    if args.targets_file and Path(args.targets_file).exists():
        targets = [line.strip() for line in Path(args.targets_file).read_text().splitlines() if line.strip()]
    elif args.target:
        targets = [args.target]

    drop_dir = resolve_drop_directory()
    logger.info(f"Target count: {len(targets)} | Drop dir: {drop_dir}")

    batch_id = str(uuid.uuid4())
    results: List[Dict[str, Any]] = []

    for t in targets:
        probe_data = probe_onion_target(t)
        results.append(probe_data)

    drop_payload = {
        "batch_id": batch_id,
        "source_agent": "locksmith_prober",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "probes_count": len(results),
        "results": results,
    }

    out_file = drop_dir / f"locksmith_{batch_id}.json"
    out_file.write_text(json.dumps(drop_payload, indent=2), encoding="utf-8")
    logger.info(f"[+] Locksmith batch completed -> {out_file.name}")


if __name__ == "__main__":
    main()
