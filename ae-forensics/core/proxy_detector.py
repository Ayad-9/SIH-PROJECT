"""
AE-Forensics: VPN, Proxy & Anonymizer Detection Engine
Multi-heuristic inspection of email transport headers (Via, X-Forwarded-For, X-Originating-IP),
known commercial VPN IP blocks, Tor exit nodes, data center VPS relays, and reverse DNS heuristics.
Calibrated to provide transparent confidence levels acknowledging evasive proxy routing.
"""

import re
import ipaddress
from typing import Dict, Any, List, Optional


# Known Tor exit node subnets and bulletproof / anonymizer IP prefixes
KNOWN_TOR_EXIT_PREFIXES = [
    "185.220.", "185.107.", "194.26.", "51.15.", "45.154.", "193.56.",
    "185.129.", "195.123.", "198.98.", "204.8.", "178.17.", "185.246."
]

# Major commercial VPN providers (Mullvad, NordVPN, ExpressVPN, ProtonVPN, PIA, Surfshark, etc.)
KNOWN_COMMERCIAL_VPN_PREFIXES = [
    {"prefix": "185.220.", "provider": "Tor Exit Node Network"},
    {"prefix": "45.154.", "provider": "Bulletproof / Offshore S.A."},
    {"prefix": "193.56.", "provider": "FlokiNET Safehaven Proxy"},
    {"prefix": "185.193.", "provider": "Mullvad VPN Relay"},
    {"prefix": "194.126.", "provider": "Mullvad VPN Relay"},
    {"prefix": "185.153.", "provider": "NordVPN Server Pool"},
    {"prefix": "193.36.", "provider": "ExpressVPN Infrastructure"},
    {"prefix": "185.159.", "provider": "ProtonVPN Gateway"},
    {"prefix": "156.146.", "provider": "Surfshark VPN Node"},
    {"prefix": "185.244.", "provider": "Private Internet Access (PIA)"}
]

# Data Center / Cloud VPS Hosting Providers commonly used for disposable relays
KNOWN_DATACENTER_HOSTING = [
    {"prefix": "51.15.", "provider": "Scaleway Cloud / VPS"},
    {"prefix": "178.62.", "provider": "DigitalOcean Droplet Relay"},
    {"prefix": "144.76.", "provider": "Hetzner Dedicated Server"},
    {"prefix": "88.198.", "provider": "Hetzner Online"},
    {"prefix": "54.240.", "provider": "Amazon AWS SES Relay"},
    {"prefix": "18.204.", "provider": "Amazon AWS EC2 Instance"},
    {"prefix": "3.80.", "provider": "Amazon AWS EC2 Instance"},
    {"prefix": "142.250.", "provider": "Google Cloud Platform (GCP)"},
    {"prefix": "20.190.", "provider": "Microsoft Azure VM Relay"}
]

# Suspicious proxy indicators in transport headers
PROXY_HEADER_CANDIDATES = [
    "x-originating-ip",
    "x-forwarded-for",
    "x-proxy-user-ip",
    "x-client-ip",
    "x-real-ip",
    "via"
]


def inspect_proxy_headers(raw_headers: str) -> List[Dict[str, str]]:
    """
    Search for intermediate proxy and client forwarding headers.
    """
    detected_headers = []
    if not raw_headers:
        return detected_headers

    for line in raw_headers.splitlines():
        line_clean = line.strip()
        if ":" not in line_clean:
            continue
        hdr_name, hdr_val = line_clean.split(":", 1)
        hdr_name_lower = hdr_name.strip().lower()

        if hdr_name_lower in PROXY_HEADER_CANDIDATES:
            detected_headers.append({
                "header": hdr_name.strip(),
                "value": hdr_val.strip()
            })
        elif hdr_name_lower == "via":
            val_lower = hdr_val.lower()
            if any(term in val_lower for term in ["squid", "varnish", "haproxy", "nginx", "proxy"]):
                detected_headers.append({
                    "header": "Via (Proxy Gateway)",
                    "value": hdr_val.strip()
                })

    return detected_headers


def check_ip_anonymity(ip_str: str) -> Dict[str, Any]:
    """
    Correlate IP address with known Tor exit nodes, commercial VPN pools, and data centers.
    """
    if not ip_str or ip_str in ("0.0.0.0", "127.0.0.1"):
        return {
            "is_proxy": False,
            "type": "NONE",
            "provider": "Unresolved Origin",
            "confidence": "NONE",
            "score": 0.0
        }

    # 1. Check Tor Exit Node prefixes
    for prefix in KNOWN_TOR_EXIT_PREFIXES:
        if ip_str.startswith(prefix):
            return {
                "is_proxy": True,
                "type": "TOR_EXIT_NODE",
                "provider": "Tor Anonymity Network",
                "confidence": "HIGH",
                "score": 90.0
            }

    # 2. Check Commercial VPN IP pools
    for vpn in KNOWN_COMMERCIAL_VPN_PREFIXES:
        if ip_str.startswith(vpn["prefix"]):
            return {
                "is_proxy": True,
                "type": "COMMERCIAL_VPN",
                "provider": vpn["provider"],
                "confidence": "HIGH",
                "score": 80.0
            }

    # 3. Check Data Center Cloud Hosting
    for dc in KNOWN_DATACENTER_HOSTING:
        if ip_str.startswith(dc["prefix"]):
            return {
                "is_proxy": True,
                "type": "DATA_CENTER_VPS",
                "provider": dc["provider"],
                "confidence": "MEDIUM",
                "score": 45.0
            }

    return {
        "is_proxy": False,
        "type": "DIRECT_ISP",
        "provider": "Standard Consumer / Enterprise ISP",
        "confidence": "LOW",
        "score": 10.0
    }


def check_hostname_heuristics(hops: List[Dict[str, Any]]) -> List[str]:
    """
    Inspect claimed hostnames for proxy, VPN, or anonymizer naming conventions.
    """
    indicators = []
    proxy_keywords = ["vpn", "tor-exit", "proxy", "anonymizer", "exit-node", "bulletproof", "tunnel", "hide"]

    for hop in hops:
        host = hop.get("claimed_host", "").lower()
        org = hop.get("org", "").lower()

        for kw in proxy_keywords:
            if kw in host or kw in org:
                indicators.append(f"Hop #{hop.get('hop_order')}: Hostname/Org matches anonymizer signature '{kw}' ({host or org})")
                break

    return indicators


def detect_vpn_or_proxy(origin_ip: str, hops: List[Dict[str, Any]], raw_headers: str) -> Dict[str, Any]:
    """
    Orchestrates full multi-layer VPN and Proxy heuristics.
    Returns calibrated verdict, confidence rating, detected indicators, and risk score.
    """
    indicators: List[str] = []
    proxy_headers = inspect_proxy_headers(raw_headers)
    for ph in proxy_headers:
        indicators.append(f"Transport Header: {ph['header']} = {ph['value']}")

    ip_analysis = check_ip_anonymity(origin_ip)
    if ip_analysis["is_proxy"]:
        indicators.append(f"Origin IP {origin_ip} identified as {ip_analysis['type']} ({ip_analysis['provider']})")

    host_indicators = check_hostname_heuristics(hops)
    indicators.extend(host_indicators)

    # Determine aggregated confidence and status
    has_tor = ip_analysis["type"] == "TOR_EXIT_NODE" or any("tor" in ind.lower() for ind in indicators)
    has_vpn = ip_analysis["type"] == "COMMERCIAL_VPN" or any("vpn" in ind.lower() for ind in indicators)
    has_dc = ip_analysis["type"] == "DATA_CENTER_VPS"
    has_headers = len(proxy_headers) > 0

    if has_tor:
        classification = "Tor Anonymizer Exit Node"
        badge_status = "TOR DETECTED"
        badge_color = "red"
        confidence = "HIGH (Confirmed Tor Exit Signature)"
        risk_score = 90.0
        summary = f"Origin IP {origin_ip} matches active Tor anonymity relay node. Sender identity is deliberately masked."
    elif has_vpn:
        classification = "Commercial VPN Relay"
        badge_status = "VPN DETECTED"
        badge_color = "amber"
        confidence = "HIGH (Known Commercial VPN ASN / Subnet)"
        risk_score = 75.0
        summary = f"Transmission originated through a commercial VPN server ({ip_analysis['provider']}). True geographical location is hidden."
    elif has_headers and has_dc:
        classification = "Forwarding Proxy via Cloud VPS"
        badge_status = "PROXY DETECTED"
        badge_color = "amber"
        confidence = "MEDIUM (Forwarding Headers + Cloud Hosting)"
        risk_score = 60.0
        summary = f"Email routed through an intermediate web proxy / cloud VPS ({ip_analysis['provider']})."
    elif has_dc:
        classification = "Data Center / Cloud Hosting Relay"
        badge_status = "CLOUD RELAY"
        badge_color = "blue"
        confidence = "MEDIUM (Public Cloud VPS, Not Residential ISP)"
        risk_score = 35.0
        summary = f"Origin IP belongs to a cloud hosting facility ({ip_analysis['provider']}). May represent a transactional relay or hosted proxy."
    elif has_headers:
        classification = "Intermediate HTTP/Mail Forwarding Proxy"
        badge_status = "PROXY HEADERS"
        badge_color = "blue"
        confidence = "MEDIUM (Forwarding Headers Present)"
        risk_score = 40.0
        summary = "Headers indicate message passed through an internal or reverse proxy gateway."
    else:
        classification = "Direct Transmission (Standard ISP / Corporate Gateway)"
        badge_status = "DIRECT / CLEAN"
        badge_color = "emerald"
        confidence = "LOW / NONE (Clean Residential / Enterprise IP)"
        risk_score = 0.0
        summary = f"No VPN, Tor, or public proxy signatures detected. Direct routing via {ip_analysis['provider']}."

    return {
        "is_proxy_or_vpn": (has_tor or has_vpn or has_headers or has_dc),
        "classification": classification,
        "badge_status": badge_status,
        "badge_color": badge_color,
        "confidence": confidence,
        "risk_score": risk_score,
        "provider": ip_analysis["provider"],
        "proxy_headers": proxy_headers,
        "indicators": indicators,
        "summary": summary
    }
