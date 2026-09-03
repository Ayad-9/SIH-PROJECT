"""
AE-Forensics: Mathematical Scoring Engine
Implements the multi-factor deterministic threat formula per PRD Section 3.2:
  ThreatScore = min(100, 0.40 * S_NLP + 0.30 * S_Auth + 0.15 * S_Net + delta_Spoof)
Categorizes verdicts into:
  CLEAN (< 40)
  SUSPICIOUS (40 - 69)
  MALICIOUS (>= 70)
Supports Proxy/VPN integration and context-aware NLP disambiguation.
"""

from typing import Dict, Any, List, Optional


def _extract_status(auth_data: Dict[str, Any], key: str) -> str:
    val = auth_data.get(key)
    if isinstance(val, dict):
        return str(val.get("status", "NONE")).upper()
    if isinstance(val, str) and val:
        return val.upper()
    status_val = auth_data.get(f"{key}_status")
    if isinstance(status_val, str) and status_val:
        return status_val.upper()
    return "NONE"


def calculate_auth_score(auth_data: Dict[str, Any]) -> float:
    """
    Evaluates protocol verification failures:
    DMARC Fail = 100
    DMARC None + SPF Fail = 70
    DMARC None + SPF Softfail = 40
    DKIM Fail alone = 30
    SPF Pass + DMARC Pass = 0
    """
    dmarc = _extract_status(auth_data, "dmarc")
    spf = _extract_status(auth_data, "spf")
    dkim = _extract_status(auth_data, "dkim")

    if dmarc == "FAIL":
        primary = 100.0
    elif dmarc == "NONE" and spf == "FAIL":
        primary = 70.0
    elif dmarc == "NONE" and spf == "SOFTFAIL":
        primary = 40.0
    elif spf == "PASS" and dmarc == "PASS":
        primary = 0.0
    elif spf == "FAIL":
        primary = 65.0
    elif spf == "SOFTFAIL":
        primary = 35.0
    else:
        primary = 10.0

    # Secondary penalties
    secondary_accum = 0.0
    if dkim == "FAIL":
        secondary_accum += 20.0
    elif dkim == "NONE" and primary < 50.0:
        secondary_accum += 10.0

    return min(100.0, round(primary + secondary_accum, 2))


def calculate_network_score(
    origin_ip: str,
    hops: List[Dict[str, Any]],
    proxy_data: Optional[Dict[str, Any]] = None
) -> float:
    """
    Evaluates network relay anomalies: missing public hops, forged hostnames,
    transmission delays (> 24 hours), or proxy / VPN / Tor anonymizers.
    """
    score = 0.0

    # 1. Missing or unresolvable origin IP
    if origin_ip in ("0.0.0.0", "", "127.0.0.1"):
        score += 35.0

    # 2. Check for anonymizer / Tor / suspicious network tags
    for hop in hops:
        claimed = hop.get("claimed_host", "").lower()
        org = hop.get("org", "").lower()
        if "tor" in claimed or "tor" in org or "exit node" in org:
            score += 50.0
            break
        if "bulletproof" in org or "anonymizer" in org or "vpn" in org:
            score += 40.0
            break

    # 3. Integrate dedicated Proxy & VPN detector if provided
    if proxy_data:
        if proxy_data.get("risk_score", 0.0) >= 75.0:
            score += 50.0
        elif proxy_data.get("risk_score", 0.0) >= 45.0:
            score += 25.0

    # 4. Excessive transmission latency anomalies
    max_latency = max([h.get("latency_seconds", 0) for h in hops], default=0)
    if max_latency > 86400:  # > 24 hours between hops
        score += 20.0
    elif max_latency > 3600:  # > 1 hour
        score += 10.0

    # 5. Hop count anomaly: suspicious if 0 hops or > 12 hops
    hop_count = len(hops)
    if hop_count == 0:
        score += 25.0
    elif hop_count > 12:
        score += 15.0

    return min(100.0, round(score, 2))


def compute_threat_score(
    nlp_score: float,
    auth_data: Dict[str, Any],
    origin_ip: str,
    hops: List[Dict[str, Any]],
    proxy_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Computes overall forensic threat score according to:
      ThreatScore = min(100, 0.40 * S_NLP + 0.30 * S_Auth + 0.15 * S_Net + delta_Spoof)
    """
    s_auth = calculate_auth_score(auth_data)
    s_net = calculate_network_score(origin_ip, hops, proxy_data)
    s_nlp = float(nlp_score)

    delta_spoof = 15.0 if (
        auth_data.get("is_display_spoofed") or 
        auth_data.get("display_spoofing_detected") or 
        auth_data.get("spoof_penalty", 0.0) > 0
    ) else 0.0

    # Determine whether input has RFC authentication infrastructure or is an unverified body/snippet
    has_mta_headers = auth_data.get("has_mta_headers")
    if has_mta_headers is None:
        spf_stat = _extract_status(auth_data, "spf")
        dkim_stat = _extract_status(auth_data, "dkim")
        dmarc_stat = _extract_status(auth_data, "dmarc")
        has_mta_headers = not (spf_stat == "NONE" and dkim_stat == "NONE" and dmarc_stat == "NONE" and not delta_spoof)

    if not has_mta_headers:
        # Telemetry adapts for direct text/body snippets without MTA authentication envelope
        weighted_nlp = 0.65 * s_nlp
        weighted_auth = 0.05 * s_auth
        weighted_net = 0.30 * s_net
        raw_threat_score = weighted_nlp + weighted_auth + weighted_net + delta_spoof
        if s_nlp >= 60.0:
            raw_threat_score = max(raw_threat_score, s_nlp)
    else:
        weighted_nlp = 0.40 * s_nlp
        weighted_auth = 0.30 * s_auth
        weighted_net = 0.15 * s_net
        raw_threat_score = weighted_nlp + weighted_auth + weighted_net + delta_spoof

    threat_score = min(100.0, round(raw_threat_score, 1))

    # Triage Verdict Classification
    if threat_score < 40.0:
        verdict = "CLEAN"
        verdict_badge_color = "emerald"
        verdict_summary = "Clean / Legitimate Transmission • Low Threat Probability"
    elif threat_score < 70.0:
        verdict = "SUSPICIOUS"
        verdict_badge_color = "amber"
        verdict_summary = "Elevated Threat Risk • Anomalous Routing, Protocol Failures, or Coercive Language"
    else:
        verdict = "MALICIOUS"
        verdict_badge_color = "red"
        verdict_summary = "High-Severity Attack Confirmed • Phishing, Fraudulent Impersonation, or Wire Diversion"

    return {
        "threat_score": threat_score,
        "verdict": verdict,
        "verdict_badge_color": verdict_badge_color,
        "verdict_summary": verdict_summary,
        "raw_scores": {
            "s_nlp": s_nlp,
            "s_auth": s_auth,
            "s_net": s_net,
            "delta_spoof": delta_spoof
        },
        "score_breakdown": {
            "nlp_contribution": round(weighted_nlp, 1),
            "auth_contribution": round(weighted_auth, 1),
            "net_contribution": round(weighted_net, 1),
            "spoof_penalty": round(delta_spoof, 1),
            "raw_nlp_score": s_nlp,
            "raw_auth_score": s_auth,
            "raw_net_score": s_net
        }
    }
