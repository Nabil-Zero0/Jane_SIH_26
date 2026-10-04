#!/usr/bin/env python3
"""
Jane Collector — Checkpoint 1: Tor Routing & Onion Reachability Check
Runs inside Whonix-Workstation using pure Python standard library.
Verifies:
  1. Outbound Tor routing via check.torproject.org API (IsTor == True)
  2. Direct SOCKS5 socket reachability on Whonix-Gateway (10.152.152.10:9050)
  3. Real .onion resolution & HTTP GET handshake (Tor Project onion)
"""

import json
import socket
import sys
import time
import urllib.request

GATEWAY_IP = "10.152.152.10"
SOCKS_PORT = 9050

TEST_ONIONS = [
    ("Tor Project", "http://2gzyxa5ihm7nsggfxnu52r2g26qd3gtst5gp7ivbvwtfdph62umhmmyd.onion"),
    ("DuckDuckGo", "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"),
]

def check_gateway_socks():
    print(f"[1/3] Testing SOCKS5 connectivity to Whonix-Gateway ({GATEWAY_IP}:{SOCKS_PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((GATEWAY_IP, SOCKS_PORT))
        print("      PASS: SOCKS5 port 9050 on Whonix-Gateway is OPEN and reachable.")
        s.close()
        return True
    except Exception as e:
        print(f"      WARN: Direct connect to {GATEWAY_IP}:{SOCKS_PORT} gave: {e}")
        print("      (Whonix transparent proxy may still route all traffic automatically).")
        s.close()
        return False

def check_tor_exit():
    print("\n[2/3] Verifying Tor routing via check.torproject.org...")
    url = "https://check.torproject.org/api/ip"
    req = urllib.request.Request(url, headers={"User-Agent": "Jane-Plumbing/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            ip = data.get("IP")
            is_tor = data.get("IsTor")
            print(f"      Observed IP : {ip}")
            print(f"      IsTor       : {is_tor}")
            if is_tor is True:
                print("      PASS: Traffic is securely routed through the Tor network.")
                return True
            else:
                print("      FAIL: Traffic is NOT recognized as Tor exit!")
                return False
    except Exception as e:
        print(f"      FAIL: Could not reach check.torproject.org: {e}")
        return False

def check_onion_fetch():
    print("\n[3/3] Verifying live .onion fetch...")
    for name, url in TEST_ONIONS:
        print(f"      Trying {name} ({url[:30]}...)...")
        req = urllib.request.Request(url, headers={"User-Agent": "Jane-Plumbing/1.0"})
        for attempt in range(1, 3):
            try:
                with urllib.request.urlopen(req, timeout=40) as resp:
                    status = resp.getcode()
                    body = resp.read(2048)
                    print(f"      PASS: HTTP Status {status}, read {len(body)} initial bytes from {name}.")
                    return True
            except Exception as e:
                print(f"      Attempt {attempt} failed: {e}")
                time.sleep(2)
    print("      FAIL: Could not establish circuit to any test .onion.")
    return False

def main():
    print("==================================================")
    print("  Jane Collector: Checkpoint 1 Tor Verification   ")
    print("==================================================")
    
    socks_ok = check_gateway_socks()
    tor_ok = check_tor_exit()
    onion_ok = check_onion_fetch()
    
    print("\n----------------- SUMMARY -----------------")
    print(f"  Whonix-Gateway SOCKS (9050) : {'PASS' if socks_ok else 'WARN/BYPASS'}")
    print(f"  Tor Exit Verification       : {'PASS' if tor_ok else 'FAIL'}")
    print(f"  .onion Live Circuit         : {'PASS' if onion_ok else 'FAIL'}")
    print("-------------------------------------------")
    
    if tor_ok and onion_ok:
        print("\nCHECKPOINT 1 PASSED: Whonix collection environment is 100% operational.")
        sys.exit(0)
    else:
        print("\nCHECKPOINT 1 FAILED: Check Gateway status or Tor circuit.")
        sys.exit(1)

if __name__ == "__main__":
    main()
