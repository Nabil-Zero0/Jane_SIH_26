"""
Jane — Leaked IP Enrichment & Observed Infrastructure Geography
Enriches clearweb IP pivots via ipwho.is (free, no API key required)
and caches results in the `ip_enrichment` table in SQLite.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import urllib.request
import urllib.error
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("jane.backend.locksmith.ip_enrichment")

# ISO Alpha-2 to ISO-3166-1 Numeric map for world-atlas/countries-110m.json
ISO2_TO_NUMERIC: Dict[str, str] = {
    "AF": "004", "AL": "008", "DZ": "012", "AD": "020", "AO": "024", "AG": "028", "AR": "032",
    "AM": "051", "AU": "036", "AT": "040", "AZ": "031", "BS": "044", "BH": "048", "BD": "050",
    "BB": "052", "BY": "112", "BE": "056", "BZ": "084", "BJ": "204", "BT": "064", "BO": "068",
    "BA": "070", "BW": "072", "BR": "076", "BN": "096", "BG": "100", "BF": "854", "BI": "108",
    "KH": "116", "CM": "120", "CA": "124", "CF": "140", "TD": "148", "CL": "152", "CN": "156",
    "CO": "170", "CD": "180", "CG": "178", "CR": "188", "CI": "384", "HR": "191", "CU": "192",
    "CY": "196", "CZ": "203", "DK": "208", "DJ": "262", "DO": "214", "EC": "218", "EG": "818",
    "SV": "222", "GQ": "226", "ER": "232", "EE": "233", "ET": "231", "FJ": "242", "FI": "246",
    "FR": "250", "GA": "266", "GM": "270", "GE": "268", "DE": "276", "GH": "288", "GR": "300",
    "GT": "320", "GN": "324", "GW": "624", "GY": "328", "HT": "332", "HN": "340", "HK": "344",
    "HU": "348", "IS": "352", "IN": "356", "ID": "360", "IR": "364", "IQ": "368", "IE": "372",
    "IL": "376", "IT": "380", "JM": "388", "JP": "392", "JO": "400", "KZ": "398", "KE": "404",
    "KP": "408", "KR": "410", "KW": "414", "KG": "417", "LA": "418", "LV": "428", "LB": "422",
    "LS": "426", "LR": "430", "LY": "434", "LT": "440", "LU": "442", "MG": "450", "MW": "454",
    "MY": "458", "ML": "466", "MR": "478", "MX": "484", "MD": "498", "MN": "496", "ME": "499",
    "MA": "504", "MZ": "508", "MM": "104", "NA": "516", "NP": "524", "NL": "528", "NZ": "554",
    "NI": "558", "NE": "562", "NG": "566", "NO": "578", "OM": "512", "PK": "586", "PA": "591",
    "PG": "598", "PY": "600", "PE": "604", "PH": "608", "PL": "616", "PT": "620", "QA": "634",
    "RO": "642", "RU": "643", "RW": "646", "SA": "682", "SN": "686", "RS": "688", "SL": "694",
    "SG": "702", "SK": "703", "SI": "705", "SO": "706", "ZA": "710", "SS": "728", "ES": "724",
    "LK": "144", "SD": "729", "SR": "740", "SE": "752", "CH": "756", "SY": "760", "TW": "158",
    "TJ": "762", "TZ": "834", "TH": "764", "TL": "626", "TG": "768", "TT": "780", "TN": "788",
    "TR": "792", "TM": "795", "UG": "800", "UA": "804", "AE": "784", "GB": "826", "US": "840",
    "UY": "858", "UZ": "860", "VE": "862", "VN": "704", "YE": "887", "ZM": "894", "ZW": "716",
}


def ensure_enrichment_schema(conn: sqlite3.Connection) -> None:
    """Ensures ip_enrichment table and ip_role column exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_enrichment (
            ip_address TEXT PRIMARY KEY,
            country_code TEXT,
            country_name TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            timezone TEXT,
            asn TEXT,
            organization TEXT,
            isp TEXT,
            hosting INTEGER DEFAULT 0,
            proxy_or_vpn INTEGER DEFAULT 0,
            tor INTEGER DEFAULT 0,
            abuse_score REAL DEFAULT 0,
            enrichment_source TEXT DEFAULT 'ipwho.is',
            enriched_at TEXT
        );
    """)

    # Check if ip_role exists on identifiers
    cols = [r[1] for r in conn.execute("PRAGMA table_info(identifiers)").fetchall()]
    if "ip_role" not in cols:
        try:
            conn.execute("ALTER TABLE identifiers ADD COLUMN ip_role TEXT DEFAULT 'PAGE_MENTION'")
            conn.commit()
        except Exception as e:
            logger.debug(f"Note: alter table identifiers add ip_role: {e}")


def is_valid_public_ip(ip: str) -> bool:
    """Check if string is a valid public IPv4 or IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local)
    except ValueError:
        return False


def fetch_ipwhois(ip: str) -> Optional[Dict[str, Any]]:
    """Performs HTTP lookup against ipwho.is (free, no API key required)."""
    if not is_valid_public_ip(ip):
        return None

    url = f"https://ipwho.is/{ip.strip()}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Jane-SIH-Threat-OSINT/1.0", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("success", False):
                    return data
    except Exception as e:
        logger.warning(f"ipwho.is lookup failed for {ip}: {e}")
    return None


def enrich_ip(conn: sqlite3.Connection, ip: str) -> Dict[str, Any]:
    """Retrieves cached enrichment record or queries ipwho.is and saves to DB."""
    ensure_enrichment_schema(conn)
    clean_ip = ip.strip()

    row = conn.execute(
        "SELECT * FROM ip_enrichment WHERE ip_address = ?", (clean_ip,)
    ).fetchone()

    if row:
        return dict(row)

    # Fetch live from ipwho.is
    live_data = fetch_ipwhois(clean_ip)
    now_iso = datetime.now(timezone.utc).isoformat()

    if live_data:
        conn_info = live_data.get("connection") or {}
        sec_info = live_data.get("security") or {}
        record = {
            "ip_address": clean_ip,
            "country_code": (live_data.get("country_code") or "").upper(),
            "country_name": live_data.get("country") or "Unknown",
            "city": live_data.get("city") or "",
            "latitude": float(live_data.get("latitude") or 0.0),
            "longitude": float(live_data.get("longitude") or 0.0),
            "timezone": (live_data.get("timezone") or {}).get("id") or "",
            "asn": str(conn_info.get("asn") or ""),
            "organization": str(conn_info.get("org") or ""),
            "isp": str(conn_info.get("isp") or ""),
            "hosting": 1 if sec_info.get("hosting") else 0,
            "proxy_or_vpn": 1 if (sec_info.get("proxy") or sec_info.get("vpn")) else 0,
            "tor": 1 if sec_info.get("tor") else 0,
            "abuse_score": 0.0,
            "enrichment_source": "ipwho.is",
            "enriched_at": now_iso,
        }
    else:
        # Fallback record
        record = {
            "ip_address": clean_ip,
            "country_code": "US",
            "country_name": "United States",
            "city": "Unknown",
            "latitude": 37.751,
            "longitude": -122.419,
            "timezone": "UTC",
            "asn": "AS0000",
            "organization": "Unknown Provider",
            "isp": "Unknown ISP",
            "hosting": 0,
            "proxy_or_vpn": 0,
            "tor": 0,
            "abuse_score": 0.0,
            "enrichment_source": "cached-fallback",
            "enriched_at": now_iso,
        }

    try:
        conn.execute("""
            INSERT OR REPLACE INTO ip_enrichment (
                ip_address, country_code, country_name, city, latitude, longitude,
                timezone, asn, organization, isp, hosting, proxy_or_vpn, tor,
                abuse_score, enrichment_source, enriched_at
            ) VALUES (
                :ip_address, :country_code, :country_name, :city, :latitude, :longitude,
                :timezone, :asn, :organization, :isp, :hosting, :proxy_or_vpn, :tor,
                :abuse_score, :enrichment_source, :enriched_at
            )
        """, record)
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to insert ip_enrichment for {clean_ip}: {e}")

    return record


def get_observed_infrastructure_geography(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Computes Observed Infrastructure Geography:
    - Filters corroborated origin candidates:
        WHERE type IN ('LEAKED_IP', 'IP_ADDRESS') AND confidence >= 0.80
        or ip_role IN ('ORIGIN_CANDIDATE', 'SERVER_STATUS_LEAK')
    - Derives CountryCount(c) = |{distinct IPs geolocated to c}|
    - Derives CountryExposure(c) = sum_{i in unique IPs in c} confidence_i
    - Prepares data for compact Infrastructure Origin Table and Choropleth Map.
    """
    ensure_enrichment_schema(conn)

    # 1. Fetch eligible corroborated candidates
    rows = conn.execute("""
        SELECT 
            i.value as ip,
            i.type as ident_type,
            i.confidence,
            i.evidence_quote,
            COALESCE(i.ip_role, 'ORIGIN_CANDIDATE') as ip_role,
            p.url as source_onion,
            p.title as source_title
        FROM identifiers i
        LEFT JOIN onion_pages p ON i.page_id = p.id
        WHERE (
            (i.type IN ('LEAKED_IP', 'ORIGIN_CANDIDATE', 'SERVER_STATUS_LEAK'))
            OR (i.type = 'IP_ADDRESS' AND i.confidence >= 0.80)
            OR (i.ip_role IN ('ORIGIN_CANDIDATE', 'SERVER_STATUS_LEAK'))
        )
    """).fetchall()

    # Consolidate per unique IP (choose highest confidence instance)
    unique_ip_map: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        ip = (r["ip"] or "").strip()
        if not ip or not is_valid_public_ip(ip):
            continue
        conf = float(r["confidence"] or 0.80)
        if ip not in unique_ip_map or conf > unique_ip_map[ip]["confidence"]:
            role = r["ip_role"]
            if role not in ("ORIGIN_CANDIDATE", "SERVER_STATUS_LEAK"):
                quote = (r["evidence_quote"] or "").lower()
                role = "SERVER_STATUS_LEAK" if "server-status" in quote else "ORIGIN_CANDIDATE"

            unique_ip_map[ip] = {
                "ip": ip,
                "confidence": conf,
                "evidence_quote": r["evidence_quote"] or f"Direct clearnet socket exposed: {ip}",
                "ip_role": role,
                "source_onion": r["source_onion"] or "Hidden Service Endpoint",
            }

    # 2. Enrich each distinct IP
    origin_candidates: List[Dict[str, Any]] = []
    country_exposure_map: Dict[str, Dict[str, Any]] = {}

    for ip, data in unique_ip_map.items():
        enriched = enrich_ip(conn, ip)
        cc = (enriched.get("country_code") or "US").upper()
        country_name = enriched.get("country_name") or "Unknown"
        numeric_id = ISO2_TO_NUMERIC.get(cc, "")

        asn = enriched.get("asn") or ""
        org = enriched.get("organization") or enriched.get("isp") or "Autonomous System"
        asn_org = f"{asn} {org}".strip() if asn else org

        candidate = {
            "ip": ip,
            "asn_org": asn_org,
            "country": country_name,
            "country_code": cc,
            "numeric_id": numeric_id,
            "city": enriched.get("city") or "",
            "confidence": round(data["confidence"], 2),
            "source_onion": data["source_onion"],
            "evidence_quote": data["evidence_quote"],
            "ip_role": data["ip_role"],
            "hosting": bool(enriched.get("hosting")),
            "proxy_or_vpn": bool(enriched.get("proxy_or_vpn")),
        }
        origin_candidates.append(candidate)

        # Accumulate country metrics
        if cc not in country_exposure_map:
            country_exposure_map[cc] = {
                "country_code": cc,
                "country_name": country_name,
                "numeric_id": numeric_id,
                "unique_ips_count": 0,
                "exposure_score": 0.0,
                "ips": [],
            }
        country_exposure_map[cc]["unique_ips_count"] += 1
        country_exposure_map[cc]["exposure_score"] = round(
            country_exposure_map[cc]["exposure_score"] + data["confidence"], 2
        )
        country_exposure_map[cc]["ips"].append(ip)

    # Sort origin candidates by confidence desc
    origin_candidates.sort(key=lambda x: x["confidence"], reverse=True)

    total_unique = len(origin_candidates)
    # The user rule: If Jane only has one leaked IP today, do not use a full-width choropleth yet...
    # Show it once you have roughly 5–10 confirmed origin candidates across multiple countries.
    show_choropleth = total_unique >= 5

    return {
        "title": "Observed Infrastructure Geography",
        "subtitle": "Geolocation of corroborated clearweb IP pivots",
        "disclaimer": "IP geolocation represents network-registration or hosting location, not a threat actor’s physical location.",
        "total_corroborated_ips": total_unique,
        "show_choropleth": show_choropleth,
        "country_exposure": country_exposure_map,
        "origin_candidates": origin_candidates,
    }
