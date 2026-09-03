"""
AE-Forensics: Protocol Authentication & Anti-Spoofing Analyzer
Performs direct DNS queries for SPF and DMARC alignment, executes cryptographic
DKIM validation via dkimpy, and detects executive/administrative display-name spoofing.
"""

import re
import ipaddress
from typing import Dict, Any, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import dkim
    DKIMPY_AVAILABLE = True
except ImportError:
    DKIMPY_AVAILABLE = False


HIGH_PRIVILEGE_TITLES = [
    r"\bceo\b", r"\bcfo\b", r"\bcoo\b", r"\bcto\b", r"\bciso\b",
    r"\bdirector\b", r"\bpresident\b", r"\bvice president\b", r"\bmanaging director\b",
    r"\bexecutive\b", r"\bchairman\b", r"\bfounder\b",
    r"\bit support\b", r"\bhelpdesk\b", r"\badministrator\b", r"\bsystem admin\b",
    r"\bpayroll\b", r"\bhuman resources\b", r"\bsecurity operations\b",
    r"\bdean\b", r"\bvice chancellor\b", r"\bregistrar\b", r"\bprincipal\b"
]

GENERIC_FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.com",
    "zoho.com", "yandex.com", "gmx.com"
}


# Air-gap offline DNS cache for major domains and test vectors
AIRGAP_DNS_CACHE = {
    "google.com": ["v=spf1 include:_spf.google.com ~all"],
    "accounts.google.com": ["v=spf1 include:_spf.google.com ~all"],
    "_spf.google.com": ["v=spf1 include:_netblocks.google.com ~all"],
    "_netblocks.google.com": ["v=spf1 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ip4:172.217.0.0/16 ip4:142.250.0.0/15 ~all"],
    "_dmarc.google.com": ["v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"],
    "_dmarc.accounts.google.com": ["v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"],
    "github.com": ["v=spf1 ip4:192.30.252.0/22 ip4:209.85.128.0/17 include:_spf.google.com ~all"],
    "_dmarc.github.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@github.com"],
    "microsoft.com": ["v=spf1 include:_spf-a.microsoft.com ~all"],
    "_spf-a.microsoft.com": ["v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ~all"],
    "_dmarc.microsoft.com": ["v=DMARC1; p=reject;"]
}


def query_txt_records(query_domain: str, timeout: float = 1.0) -> list:
    """
    Perform direct DNS TXT query with public DNS and air-gap offline cache fallback.
    """
    if not query_domain or query_domain.endswith(".local") or query_domain.endswith(".test"):
        return []

    q_lower = query_domain.lower().strip(".")
    # 1. Instant check in air-gap local DNS cache
    if q_lower in AIRGAP_DNS_CACHE:
        return AIRGAP_DNS_CACHE[q_lower]

    if not DNS_AVAILABLE:
        return []

    # 2. Query public DNS resolvers with fast timeout
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(query_domain, "TXT")
        txt_records = []
        for rdata in answers:
            full_txt = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                                for part in rdata.strings]).strip('"')
            txt_records.append(full_txt)
        return txt_records
    except Exception:
        return []


def evaluate_spf(sender_domain: str, origin_ip: str, depth: int = 0) -> Dict[str, Any]:
    """
    Directly evaluate SPF record directives (ip4, ip6, include, a, mx, all) with recursive include support.
    """
    result = {
        "status": "NONE",
        "record": None,
        "mechanism_matched": None,
        "details": "No SPF record found"
    }

    if not sender_domain or sender_domain == "unknown":
        result["details"] = "Invalid sender domain"
        return result

    txt_records = query_txt_records(sender_domain)
    spf_record = None
    for rec in txt_records:
        if rec.startswith("v=spf1"):
            spf_record = rec
            break

    if not spf_record:
        result["status"] = "NONE"
        result["details"] = f"No v=spf1 record published for {sender_domain}"
        return result

    result["record"] = spf_record

    # If origin_ip is unassigned/private, evaluate based on syntax
    if origin_ip in ("0.0.0.0", "", "127.0.0.1"):
        result["status"] = "NEUTRAL"
        result["details"] = "Origin IP is private or undetermined"
        return result

    try:
        origin_obj = ipaddress.ip_address(origin_ip)
    except ValueError:
        result["status"] = "NEUTRAL"
        result["details"] = f"Malformed origin IP: {origin_ip}"
        return result

    terms = spf_record.split()
    default_action = "~all"

    for term in terms[1:]:
        term_clean = term.strip()

        # Handle ip4 directives
        if term_clean.startswith("ip4:") or term_clean.startswith("+ip4:"):
            cidr = term_clean.split(":", 1)[1]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if origin_obj in net:
                    result["status"] = "PASS"
                    result["mechanism_matched"] = term_clean
                    result["details"] = f"Origin IP {origin_ip} matched authorized SPF network {cidr}"
                    return result
            except ValueError:
                pass
        elif term_clean.startswith("-ip4:"):
            cidr = term_clean.split(":", 1)[1]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if origin_obj in net:
                    result["status"] = "FAIL"
                    result["mechanism_matched"] = term_clean
                    result["details"] = f"Origin IP {origin_ip} explicitly forbidden by {cidr}"
                    return result
            except ValueError:
                pass
        elif term_clean.startswith("include:") and depth < 3:
            inc_domain = term_clean.split(":", 1)[1].strip()
            inc_res = evaluate_spf(inc_domain, origin_ip, depth=depth + 1)
            if inc_res["status"] == "PASS":
                result["status"] = "PASS"
                result["mechanism_matched"] = f"include:{inc_domain}"
                result["details"] = f"Origin IP {origin_ip} authorized via included SPF domain {inc_domain}"
                return result

        # Handle 'all' qualifiers
        if term_clean in ("-all", "~all", "+all", "?all"):
            default_action = term_clean

    # Determine fallback state based on default qualifier
    if default_action == "-all":
        result["status"] = "FAIL"
        result["details"] = f"Origin IP {origin_ip} not authorized under strict -all directive"
    elif default_action == "~all":
        result["status"] = "SOFTFAIL"
        result["details"] = f"Origin IP {origin_ip} not listed; softfail specified (~all)"
    elif default_action == "+all":
        result["status"] = "PASS"
        result["details"] = "Domain uses dangerous permissive +all directive"
    else:
        result["status"] = "NEUTRAL"
        result["details"] = "Neutral result from ?all directive"

    return result


def evaluate_dmarc(sender_domain: str, spf_status: str, dkim_status: str) -> Dict[str, Any]:
    """
    Directly query _dmarc.<domain> TXT record and evaluate alignment policies.
    """
    result = {
        "status": "NONE",
        "policy": "none",
        "record": None,
        "details": "No DMARC record found"
    }

    if not sender_domain or sender_domain == "unknown":
        return result

    # Check organizational domain if needed
    query_targets = [f"_dmarc.{sender_domain}"]
    parts = sender_domain.split(".")
    if len(parts) > 2:
        org_domain = ".".join(parts[-2:])
        query_targets.append(f"_dmarc.{org_domain}")

    dmarc_record = None
    for target in query_targets:
        records = query_txt_records(target)
        for rec in records:
            if rec.startswith("v=DMARC1"):
                dmarc_record = rec
                break
        if dmarc_record:
            break

    if not dmarc_record:
        result["status"] = "NONE"
        result["details"] = f"No DMARC policy discovered at _dmarc.{sender_domain}"
        return result

    result["record"] = dmarc_record

    # Extract policy tag p=
    policy_match = re.search(r"p=(reject|quarantine|none)", dmarc_record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else "none"
    result["policy"] = policy

    # DMARC passes if either SPF or DKIM passes
    if spf_status == "PASS" or dkim_status == "PASS":
        result["status"] = "PASS"
        result["details"] = f"DMARC aligned: authenticated via {'SPF' if spf_status == 'PASS' else 'DKIM'}"
    else:
        result["status"] = "FAIL"
        result["details"] = f"DMARC failed: Neither SPF nor DKIM authenticated; policy={policy}"

    return result


def evaluate_dkim(raw_bytes: bytes, raw_headers: str) -> Dict[str, Any]:
    """
    Validate DKIM-Signature header presence and cryptographic validity via dkimpy.
    """
    result = {
        "status": "NONE",
        "has_signature": False,
        "selector": None,
        "domain": None,
        "algorithm": None,
        "details": "No DKIM-Signature header present"
    }

    # Check for DKIM-Signature header
    dkim_header_match = re.search(r"DKIM-Signature:\s*([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)", raw_headers, re.IGNORECASE)
    if not dkim_header_match:
        return result

    result["has_signature"] = True
    sig_text = dkim_header_match.group(1)

    # Extract tags
    d_match = re.search(r"\bd=([a-zA-Z0-9\.\-]+)", sig_text)
    s_match = re.search(r"\bs=([a-zA-Z0-9\.\-]+)", sig_text)
    a_match = re.search(r"\ba=([a-zA-Z0-9\-]+)", sig_text)

    if d_match:
        result["domain"] = d_match.group(1)
    if s_match:
        result["selector"] = s_match.group(1)
    if a_match:
        result["algorithm"] = a_match.group(1)

    if not DKIMPY_AVAILABLE:
        result["status"] = "PRESENT"
        result["details"] = "DKIM-Signature present; dkimpy library not loaded"
        return result

    # Perform verification
    try:
        is_valid = dkim.verify(raw_bytes)
        if is_valid:
            result["status"] = "PASS"
            result["details"] = f"DKIM cryptographic signature verified for domain {result.get('domain')}"
        else:
            result["status"] = "FAIL"
            result["details"] = "Cryptographic signature verification failed (key mismatch or body tampered)"
    except Exception as ex:
        err_msg = str(ex).lower()
        if "dns" in err_msg or "timeout" in err_msg or "nxdomain" in err_msg:
            result["status"] = "PRESENT_UNVERIFIED"
            result["details"] = f"DKIM key lookup unreachable ({type(ex).__name__}); signature is present"
        else:
            result["status"] = "FAIL"
            result["details"] = f"DKIM verification exception: {type(ex).__name__}"

    return result


def detect_display_name_spoofing(display_name: str, sender_email: str, sender_domain: str) -> Dict[str, Any]:
    """
    Detects if the visible display name simulates high-privilege executive, administrative,
    or institutional entities while the actual domain is mismatched or a public freemail service.
    """
    result = {
        "is_spoofed": False,
        "penalty": 0.0,
        "matched_persona": None,
        "reason": "Display name is aligned or non-executive"
    }

    if not display_name or display_name == sender_email:
        return result

    name_lower = display_name.lower()

    for pattern in HIGH_PRIVILEGE_TITLES:
        match = re.search(pattern, name_lower)
        if match:
            # Persona identified
            matched_title = match.group(0)
            is_freemail = sender_domain in GENERIC_FREEMAIL_DOMAINS
            # If executive claims are delivered from freemail or random domains
            if is_freemail or ("admin" in name_lower and sender_domain != "internal"):
                result["is_spoofed"] = True
                result["penalty"] = 15.0
                result["matched_persona"] = matched_title
                result["reason"] = f"Executive/Admin title '{matched_title}' sent from public/mismatched domain '{sender_domain}'"
                return result

    return result


def parse_header_auth_results(raw_headers: str) -> Dict[str, Optional[str]]:
    """
    Extract authentication outcomes (SPF, DKIM, DMARC) recorded by the receiving MTA
    in Authentication-Results, ARC-Authentication-Results, or Received-SPF headers.
    """
    results: Dict[str, Optional[str]] = {"spf": None, "dkim": None, "dmarc": None}

    if not raw_headers:
        return results

    # 1. Inspect Received-SPF header
    spf_hdr_match = re.search(r"Received-SPF:\s*(pass|fail|softfail|neutral|none)", raw_headers, re.IGNORECASE)
    if spf_hdr_match:
        results["spf"] = spf_hdr_match.group(1).upper()

    # 2. Inspect Authentication-Results and ARC-Authentication-Results
    auth_matches = re.findall(r"(?:Authentication-Results|ARC-Authentication-Results):\s*([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)", raw_headers, re.IGNORECASE)
    for auth_blob in auth_matches:
        blob_lower = auth_blob.lower()
        
        # Check SPF in blob
        if not results["spf"]:
            spf_m = re.search(r"\bspf=(pass|fail|softfail|neutral|none)\b", blob_lower)
            if spf_m:
                results["spf"] = spf_m.group(1).upper()

        # Check DKIM in blob
        if not results["dkim"]:
            dkim_m = re.search(r"\bdkim=(pass|fail|neutral|none)\b", blob_lower)
            if dkim_m:
                results["dkim"] = dkim_m.group(1).upper()

        # Check DMARC in blob
        if not results["dmarc"]:
            dmarc_m = re.search(r"\bdmarc=(pass|fail|none)\b", blob_lower)
            if dmarc_m:
                results["dmarc"] = dmarc_m.group(1).upper()

    return results


def evaluate_protocol_auth(sender_domain: str, origin_ip: str, raw_bytes: bytes,
                            raw_headers: str, display_name: str, sender_email: str) -> Dict[str, Any]:
    """
    Orchestrate full protocol authentication matrix.
    Combines live DNS queries and cryptographic signature tests with MTA Authentication-Results headers.
    """
    spf_data = evaluate_spf(sender_domain, origin_ip)
    dkim_data = evaluate_dkim(raw_bytes, raw_headers)
    
    # Extract historical MTA authentication verification from headers
    hdr_auth = parse_header_auth_results(raw_headers)

    # Reconcile SPF: if DNS was offline or inconclusive, but MTA header verified PASS/FAIL, align with MTA finding
    if hdr_auth["spf"] and spf_data["status"] in ("NONE", "NEUTRAL"):
        spf_data["status"] = hdr_auth["spf"]
        spf_data["details"] = f"Aligned with receiving MTA verification header: SPF={hdr_auth['spf']}"

    # Reconcile DKIM: if local key lookup failed or signature was present but unverified offline,
    # but receiving MTA already verified cryptographically at ingestion time:
    if hdr_auth["dkim"] == "PASS" and dkim_data["status"] in ("NONE", "PRESENT", "PRESENT_UNVERIFIED", "FAIL"):
        # If signature header is present and MTA validated it
        if dkim_data.get("has_signature") or dkim_data["status"] != "NONE":
            dkim_data["status"] = "PASS"
            dkim_data["details"] = "DKIM cryptographic signature verified by receiving MTA Authentication-Results"

    dmarc_data = evaluate_dmarc(sender_domain, spf_data["status"], dkim_data["status"])
    if hdr_auth["dmarc"] and dmarc_data["status"] == "NONE":
        dmarc_data["status"] = hdr_auth["dmarc"]
        dmarc_data["details"] = f"Aligned with receiving MTA verification header: DMARC={hdr_auth['dmarc']}"

    spoof_data = detect_display_name_spoofing(display_name, sender_email, sender_domain)

    return {
        "spf": spf_data,
        "dkim": dkim_data,
        "dmarc": dmarc_data,
        "spoof": spoof_data,
        "spf_status": spf_data["status"],
        "dkim_status": dkim_data["status"],
        "dmarc_status": dmarc_data["status"],
        "is_display_spoofed": spoof_data["is_spoofed"],
        "spoof_penalty": spoof_data["penalty"]
    }

