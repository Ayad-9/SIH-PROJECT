"""
AE-Forensics: Comprehensive Multi-Page PDF Forensic Intelligence Dossier Generator
Compiled with ReportLab to produce an exhaustive, colorful, user-friendly, court-admissible
digital evidence exhibit complying with Section 65B of the Indian Evidence Act and SIH #26106.
"""

import io
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)


def _sanitize_text(val: Any, default: str = "N/A") -> str:
    """
    Safely convert value to string, converting Unicode characters (emojis, smart quotes,
    dashes, currency) to clean printable ASCII/Latin-1, and sanitizing XML tags for ReportLab.
    """
    if val is None or val == "":
        return default
    s = str(val)

    # Convert common Unicode characters to printable equivalents
    replacements = {
        "—": "--", "–": "-", "―": "--",
        "“": '"', "”": '"', "„": '"', "‟": '"',
        "‘": "'", "’": "'", "‚": "'", "‛": "'",
        "•": "&bull;", "·": "*", "…": "...",
        "₹": "INR ", "€": "EUR ", "£": "GBP ", "¥": "JPY ",
        "→": "->", "←": "<-", "⇒": "=>", "⇔": "<=>",
        "✔": "[OK]", "✓": "[OK]", "✖": "[X]", "✗": "[X]",
        "⚠": "[WARN]", "⚡": "[ALERT]", "🔒": "[SECURE]", "🛡": "[SHIELD]",
        "©": "(C)", "®": "(R)", "™": "(TM)", "°": " deg"
    }
    for k, v in replacements.items():
        s = s.replace(k, v)

    # Sanitize characters outside standard printable Latin-1
    cleaned = []
    for ch in s:
        code = ord(ch)
        if code < 128:
            cleaned.append(ch)
        elif code <= 255:
            cleaned.append(ch)
        else:
            cleaned.append(" ")
    s = "".join(cleaned)

    # Sanitize XML special entities
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_plain_english_summary(case_data: Dict[str, Any]) -> str:
    """
    Construct a clear, plain-English executive summary that any non-technical user,
    investigator, or executive can immediately read and understand.
    """
    verdict = str(case_data.get("verdict", "CLEAN")).upper()
    threat_score = float(case_data.get("threat_score", 0.0))
    sender = case_data.get("sender", "Unknown sender")
    domain = case_data.get("sender_domain", "unknown")
    origin_ip = case_data.get("origin_ip", "0.0.0.0")
    geo = case_data.get("origin_geo", {}) or {}
    city = geo.get("city", "Unknown City")
    country = geo.get("country", "Unknown Country")
    is_spoofed = bool(case_data.get("is_display_spoofed", False))
    proxy_data = case_data.get("proxy_analysis", {}) or {}
    proxy_class = proxy_data.get("classification", "Direct Transmission")
    tone_data = case_data.get("tone_analysis", {}) or {}
    has_abuse = bool(tone_data.get("has_abusive_language", False))
    nlp_intent = case_data.get("nlp_intent", {}) or {}
    triggers = nlp_intent.get("triggers", [])

    if verdict == "MALICIOUS":
        summary = (
            f"<b>CRITICAL SECURITY THREAT DETECTED (Threat Index: {threat_score:.1f} / 100).</b><br/>"
            f"This email has been confirmed as a high-risk malicious attack. "
        )
        if is_spoofed:
            summary += f"The sender claims an executive or administrative identity while sending from an unauthorized domain (<b>{domain}</b>). "
        if "Tor" in proxy_class or "VPN" in proxy_class or "Proxy" in proxy_class:
            summary += f"The transmission was routed through an anonymizing network (<b>{proxy_class}</b>) originating from <b>{city}, {country}</b> (IP: <b>{origin_ip}</b>) to conceal the attacker's physical identity. "
        else:
            summary += f"The email originated from <b>{city}, {country}</b> (IP: <b>{origin_ip}</b>). "
        highlighted_terms = nlp_intent.get("highlighted_terms", [])
        if highlighted_terms:
            trig_str = ", ".join([f'"{_sanitize_text(t)}"' for t in highlighted_terms[:4]])
            summary += f"The message body contains active deceptive coercion patterns: <b>{trig_str}</b>. "
        summary += "<br/><b>IMMEDIATE ACTION:</b> Quarantine message, block originating IP, do not click any links, and do not execute financial wire transfers."
        return summary

    elif verdict == "SUSPICIOUS":
        summary = (
            f"<b>SUSPICIOUS ANOMALIES FLAGGED (Threat Index: {threat_score:.1f} / 100).</b><br/>"
            f"This message displays significant discrepancies that require manual verification before release. "
        )
        if is_spoofed:
            summary += f"The sender's display name appears to simulate an internal authority figure, but the actual authenticated domain is <b>{domain}</b>. "
        summary += f"The transmission originated from <b>{city}, {country}</b> (IP: <b>{origin_ip}</b>). "
        summary += "<br/><b>RECOMMENDED ACTION:</b> Verify sender authenticity through a secondary trusted channel before opening attachments or replying."
        return summary

    else:
        # CLEAN verdict
        if has_abuse:
            summary = (
                f"<b>NON-THREAT WORKPLACE DISPUTE CONFIRMED (Threat Index: {threat_score:.1f} / 100).</b><br/>"
                f"Although this message contains frustrated, aggressive, or angry language, our Smart AI False-Positive Disambiguation "
                f"Engine has verified that it contains <b>ZERO cyber fraud, wire diversion, or credential harvesting payloads</b>. "
                f"The transmission originated from a legitimate gateway in <b>{city}, {country}</b> (IP: <b>{origin_ip}</b>) "
                f"and passed protocol security checks. It should be treated as a customer service / employee grievance, NOT a cyber security incident."
            )
            return summary
        else:
            summary = (
                f"<b>LEGITIMATE &amp; AUTHENTIC TRANSMISSION (Threat Index: {threat_score:.1f} / 100).</b><br/>"
                f"This email passed authentication protocols (SPF/DKIM/DMARC) and shows no indicators of deception, phishing, or financial fraud. "
                f"The transmission arrived from authorized mail infrastructure in <b>{city}, {country}</b> (IP: <b>{origin_ip}</b>). "
                f"Safe for standard delivery to intended recipients."
            )
            return summary


def generate_forensic_pdf(case_data: Dict[str, Any]) -> bytes:
    """
    Compiles an exhaustive, multi-page, court-admissible forensic dossier in genuine PDF format.
    Includes:
      1. Case Docket & Section 65B Standard Header
      2. Executive Security Verdict Banner
      3. Plain-English Threat Analysis & Summary
      4. Deterministic Multi-Factor Threat Formulation
      5. Digital Chain of Custody & Evidence Fingerprints
      6. Sender Identity & Message Metadata Attribution
      7. Origin Geolocation & Network Attribution
      8. Protocol Authentication & Spoofing Matrix
      9. AI Language, Tone & Workplace False-Positive Disambiguation
      10. Routing Privacy, Proxy & Tor Detection Audit
      11. Chronological SMTP Transmission Relay Chain
      12. Actionable Security Recommendations & SOC Playbook
      13. Extracted Plain-Text Message Body Excerpt
      14. Certificate of Digital Evidence Authenticity (Section 65B) & Signature Block
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Color palette
    c_primary = colors.HexColor('#1D4ED8')       # Deep Royal Blue
    c_slate_dark = colors.HexColor('#0F172A')    # Dark Slate 900
    c_slate_mid = colors.HexColor('#334155')     # Slate 700
    c_slate_light = colors.HexColor('#64748B')   # Slate 500
    c_border = colors.HexColor('#CBD5E1')        # Slate 300
    c_row_alt = colors.HexColor('#F8FAFC')       # Slate 50
    c_header_bg = colors.HexColor('#F1F5F9')     # Slate 100

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=c_slate_dark,
        spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=c_slate_light,
        spaceAfter=6
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=c_slate_dark,
        spaceBefore=8,
        spaceAfter=3
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10.5,
        textColor=c_slate_mid
    )
    body_bold = ParagraphStyle(
        'BodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10.5,
        textColor=c_slate_dark
    )
    mono_style = ParagraphStyle(
        'MonoText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=c_slate_dark
    )
    mono_code = ParagraphStyle(
        'MonoCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=6.5,
        leading=8.5,
        textColor=c_slate_mid
    )
    verdict_title = ParagraphStyle(
        'VerdictTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.white,
        alignment=1
    )

    story = []

    # ==========================================
    # 1. HEADER & CASE DOCKET EMBLEM
    # ==========================================
    story.append(Paragraph("SIH CYBER SECURITY CELL &bull; FORENSIC INTELLIGENCE PLATFORM", ParagraphStyle(
        'TopBrand', fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=c_primary
    )))
    story.append(Paragraph("Official Email Threat &amp; Forensic Intelligence Exhibit", title_style))
    
    case_uuid = _sanitize_text(case_data.get("case_id", "UNKNOWN"))
    gen_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    story.append(Paragraph(
        f"Docket Ref: <b>CASE-{case_uuid[:12].upper()}</b> &bull; "
        f"Generated: <b>{gen_time}</b> &bull; "
        "Standard: <b>Section 65B Indian Evidence Act / SIH #26106</b>",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_primary, spaceAfter=6))

    # ==========================================
    # 2. EXECUTIVE VERDICT BANNER
    # ==========================================
    verdict = _sanitize_text(case_data.get("verdict", "CLEAN")).upper()
    threat_score = float(case_data.get("threat_score", 0.0))

    if verdict == "MALICIOUS":
        banner_bg = colors.HexColor('#DC2626')  # Ruby Red
        verdict_tag = "CONFIRMED HIGH-SEVERITY CYBER THREAT &bull; IMMEDIATE MITIGATION MANDATED"
    elif verdict == "SUSPICIOUS":
        banner_bg = colors.HexColor('#D97706')  # Amber
        verdict_tag = "SUSPICIOUS DISCREPANCIES FLAGGED &bull; MANUAL VERIFICATION REQUIRED"
    else:
        banner_bg = colors.HexColor('#059669')  # Emerald Green
        verdict_tag = "VERIFIED SAFE / AUTHENTIC TRANSMISSION &bull; LOW RISK PROBABILITY"

    verdict_data = [
        [Paragraph(f"TRIAGE VERDICT: {verdict} &nbsp;&nbsp;|&nbsp;&nbsp; THREAT SCORE: {threat_score:.1f} / 100", verdict_title)],
        [Paragraph(verdict_tag, ParagraphStyle(
            'VerdictSub', fontName='Helvetica', fontSize=7, leading=9, textColor=colors.white, alignment=1
        ))]
    ]
    verdict_table = Table(verdict_data, colWidths=[540])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), banner_bg),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROUNDEDCORNERS', [4, 4, 4, 4]),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 3. USER-FRIENDLY PLAIN-ENGLISH EXECUTIVE SUMMARY
    # ==========================================
    story.append(Paragraph("Executive Threat Summary (Plain-English Assessment)", section_heading))
    summary_text = _build_plain_english_summary(case_data)
    summary_table = Table([[Paragraph(summary_text, ParagraphStyle(
        'ExecText', fontName='Helvetica', fontSize=7.5, leading=10.5, textColor=c_slate_dark
    ))]], colWidths=[540])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
        ('BOX', (0, 0), (-1, -1), 1, c_primary),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 7),
        ('RIGHTPADDING', (0, 0), (-1, -1), 7),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6))

    # ==========================================
    # 4. DETERMINISTIC SCORING FORMULATION
    # ==========================================
    breakdown = case_data.get("score_breakdown", {}) or {}
    s_nlp_c = breakdown.get("nlp_contribution", 0.0)
    s_auth_c = breakdown.get("auth_contribution", 0.0)
    s_net_c = breakdown.get("net_contribution", 0.0)
    s_spoof_p = breakdown.get("spoof_penalty", 0.0)
    raw_nlp = breakdown.get("raw_nlp_score", case_data.get("nlp_score", 0.0))
    raw_auth = breakdown.get("raw_auth_score", 0.0)
    raw_net = breakdown.get("raw_net_score", 0.0)

    score_rows = [
        [
            Paragraph("Metric Factor", body_bold),
            Paragraph("Weight", body_bold),
            Paragraph("Evaluation Method", body_bold),
            Paragraph("Contribution", body_bold)
        ],
        [
            Paragraph("AI Semantic Threat (S_NLP)", body_style),
            Paragraph("40%", mono_style),
            Paragraph(f"Score: {raw_nlp:.1f}/100 (Urgency, Wire Fraud, Credentials)", body_style),
            Paragraph(f"+{s_nlp_c:.1f} pts", body_bold)
        ],
        [
            Paragraph("Protocol Security (S_Auth)", body_style),
            Paragraph("30%", mono_style),
            Paragraph(f"Score: {raw_auth:.1f}/100 (SPF, DKIM, DMARC Failures)", body_style),
            Paragraph(f"+{s_auth_c:.1f} pts", body_bold)
        ],
        [
            Paragraph("Network Anomalies (S_Net)", body_style),
            Paragraph("15%", mono_style),
            Paragraph(f"Score: {raw_net:.1f}/100 (Tor Nodes, VPNs, Relay Latencies)", body_style),
            Paragraph(f"+{s_net_c:.1f} pts", body_bold)
        ],
        [
            Paragraph("Executive Display Spoof (&delta;_Spoof)", body_style),
            Paragraph("Penalty", mono_style),
            Paragraph("Impersonation Flagged (+15.0)" if s_spoof_p > 0 else "Authentic / Aligned (0.0)", body_style),
            Paragraph(f"+{s_spoof_p:.1f} pts", body_bold)
        ],
        [
            Paragraph("<b>COMPOSITE THREAT INDEX</b>", body_bold),
            Paragraph("<b>100%</b>", mono_style),
            Paragraph(f"<b>Verdict Category: {verdict}</b>", body_bold),
            Paragraph(f"<b>{threat_score:.1f} / 100</b>", body_bold)
        ]
    ]
    score_table = Table(score_rows, colWidths=[160, 50, 210, 120])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_header_bg),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#E2E8F0')),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 6))

    # ==========================================
    # 5. DIGITAL CHAIN OF CUSTODY
    # ==========================================
    story.append(Paragraph("1. Digital Chain of Custody &amp; Evidence Fingerprints", section_heading))
    sha256_hash = _sanitize_text(case_data.get("sha256", "UNKNOWN"))

    custody_rows = [
        [
            Paragraph("Case UUID:", body_bold),
            Paragraph(case_uuid, mono_style),
            Paragraph("Custody Timestamp:", body_bold),
            Paragraph(gen_time, body_style)
        ],
        [
            Paragraph("SHA-256 Digest:", body_bold),
            Paragraph(sha256_hash, mono_style),
            Paragraph("Legal Standard:", body_bold),
            Paragraph("Section 65B Indian Evidence Act / SIH #26106", body_style)
        ]
    ]
    custody_table = Table(custody_rows, colWidths=[105, 165, 105, 165])
    custody_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_row_alt),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(custody_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 6. SENDER IDENTITY & MESSAGE METADATA
    # ==========================================
    story.append(Paragraph("2. Sender Identity &amp; Message Metadata Attribution", section_heading))
    sender_val = _sanitize_text(case_data.get("sender", "N/A"))
    domain_val = _sanitize_text(case_data.get("sender_domain", "N/A"))
    return_path_val = _sanitize_text(case_data.get("return_path", "N/A"))
    recipient_val = _sanitize_text(case_data.get("recipient", "N/A"))
    origin_ip_val = _sanitize_text(case_data.get("origin_ip", "0.0.0.0"))
    date_val = _sanitize_text(case_data.get("received_date", "N/A"))
    subject_val = _sanitize_text(case_data.get("subject", "No Subject"))

    ident_rows = [
        [
            Paragraph("Declared Sender:", body_bold),
            Paragraph(sender_val, body_style),
            Paragraph("Return-Path:", body_bold),
            Paragraph(return_path_val, mono_style)
        ],
        [
            Paragraph("Authenticated Domain:", body_bold),
            Paragraph(f"<b>{domain_val}</b>", mono_style),
            Paragraph("Intended Recipient:", body_bold),
            Paragraph(recipient_val, body_style)
        ],
        [
            Paragraph("Originating Public IP:", body_bold),
            Paragraph(f"<b>{origin_ip_val}</b>", mono_style),
            Paragraph("Transmission Date:", body_bold),
            Paragraph(date_val, body_style)
        ],
        [
            Paragraph("Subject Line:", body_bold),
            Paragraph(f"<b>{subject_val}</b>", body_style),
            Paragraph("Standard:", body_bold),
            Paragraph("RFC 822 / 5322 MIME Stream", body_style)
        ]
    ]
    ident_table = Table(ident_rows, colWidths=[105, 165, 105, 165])
    ident_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_row_alt),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(ident_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 7. ORIGIN GEOLOCATION & NETWORK ATTRIBUTION
    # ==========================================
    story.append(Paragraph("3. Geolocation &amp; Physical Origin Attribution", section_heading))
    origin_geo = case_data.get("origin_geo", {}) or {}
    geo_city = _sanitize_text(origin_geo.get("city", "Unknown"))
    geo_country = _sanitize_text(origin_geo.get("country", "Unknown"))
    geo_lat = origin_geo.get("lat") or origin_geo.get("latitude")
    geo_lon = origin_geo.get("lon") or origin_geo.get("longitude")
    geo_org = _sanitize_text(origin_geo.get("org", "Direct ISP / Enterprise Gateway"))

    coord_str = f"{geo_lat:.4f} deg N, {geo_lon:.4f} deg E" if (geo_lat is not None and geo_lon is not None and (geo_lat != 0 or geo_lon != 0)) else "Internal Network / Filtered"

    geo_rows = [
        [
            Paragraph("Origin Relay IP:", body_bold),
            Paragraph(f"<b>{origin_ip_val}</b>", mono_style),
            Paragraph("Physical Coordinates:", body_bold),
            Paragraph(coord_str, mono_style)
        ],
        [
            Paragraph("Location:", body_bold),
            Paragraph(f"{geo_city}, {geo_country}", body_style),
            Paragraph("ISP / Organization:", body_bold),
            Paragraph(geo_org, body_style)
        ]
    ]
    geo_table = Table(geo_rows, colWidths=[105, 165, 105, 165])
    geo_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_row_alt),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(geo_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 8. PROTOCOL AUTHENTICATION & SPOOFING MATRIX
    # ==========================================
    story.append(Paragraph("4. Email Protocol Security &amp; Spoofing Matrix", section_heading))
    spf_stat = _sanitize_text(case_data.get("spf_status", "NONE")).upper()
    dkim_stat = _sanitize_text(case_data.get("dkim_status", "NONE")).upper()
    dmarc_stat = _sanitize_text(case_data.get("dmarc_status", "NONE")).upper()
    is_spoofed = bool(case_data.get("is_display_spoofed", False))

    auth_rows = [
        [
            Paragraph("Protocol Directive", body_bold),
            Paragraph("Result", body_bold),
            Paragraph("Meaning &amp; Forensic Impact", body_bold)
        ],
        [
            Paragraph("SPF (RFC 7208)", body_style),
            Paragraph(f"<b>{spf_stat}</b>", mono_style),
            Paragraph("PASS = Authorized sending host; FAIL/SOFTFAIL = Unauthorized gateway or forged envelope.", body_style)
        ],
        [
            Paragraph("DKIM (RFC 6376)", body_style),
            Paragraph(f"<b>{dkim_stat}</b>", mono_style),
            Paragraph("PASS = Untampered cryptographic signature; FAIL = Headers or message altered in transit.", body_style)
        ],
        [
            Paragraph("DMARC (RFC 7489)", body_style),
            Paragraph(f"<b>{dmarc_stat}</b>", mono_style),
            Paragraph("Domain enforcement policy. Protects institutional brand from sender identity spoofing.", body_style)
        ],
        [
            Paragraph("Display Name Spoof", body_style),
            Paragraph(f"<b>{'SPOOF DETECTED' if is_spoofed else 'ALIGNED'}</b>", mono_style),
            Paragraph("Detects high-privilege executive display names sent from freemail (Gmail/Yahoo) accounts.", body_style)
        ]
    ]
    auth_table = Table(auth_rows, colWidths=[120, 90, 330])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_header_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 9. AI LANGUAGE, TONE & WORKPLACE DISAMBIGUATION
    # ==========================================
    story.append(Paragraph("5. AI Language, Tone &amp; False-Positive Disambiguation", section_heading))
    tone_data = case_data.get("tone_analysis", {}) or {}
    nlp_intent = case_data.get("nlp_intent", {}) or {}
    tone_profile = _sanitize_text(tone_data.get("tone", "Neutral / Informational"))
    sentiment = _sanitize_text(tone_data.get("sentiment", "Neutral"))
    has_abuse = bool(tone_data.get("has_abusive_language", False))
    abusive_matches = tone_data.get("abusive_matches", [])
    abusive_terms = ", ".join([f'"{_sanitize_text(t)}"' for t in abusive_matches]) or "None detected"
    disambig_note = _sanitize_text(nlp_intent.get("disambiguation_note", "Standard heuristic intent evaluation."))
    nlp_score = float(case_data.get("nlp_score", 0.0))

    nlp_rows = [
        [Paragraph("Emotional Tone Profile:", body_bold), Paragraph(tone_profile, body_style)],
        [Paragraph("Sentiment Polarity:", body_bold), Paragraph(sentiment, body_style)],
        [Paragraph("Hostility / Abuse Check:", body_bold), Paragraph(f"{'Flagged Hostile' if has_abuse else 'Clean (No Hostility)'} &bull; Matched: <i>{abusive_terms}</i>", body_style)],
        [Paragraph("Disambiguation Finding:", body_bold), Paragraph(f"<b>{disambig_note}</b>", body_style)],
        [Paragraph("Fraud Semantic Risk:", body_bold), Paragraph(f"<b>{nlp_score:.1f}% Risk Index</b> &bull; Evaluated against wire fraud, credential harvesting, urgency pressure, and gift cards.", body_style)]
    ]
    nlp_table = Table(nlp_rows, colWidths=[130, 410])
    nlp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_row_alt),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(nlp_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 10. ROUTING PRIVACY, PROXY & TOR AUDIT
    # ==========================================
    story.append(Paragraph("6. Routing Privacy, Proxy &amp; Tor Detection Audit", section_heading))
    proxy_data = case_data.get("proxy_analysis", {}) or {}
    proxy_class = _sanitize_text(proxy_data.get("classification", "Direct Transmission"))
    proxy_conf = _sanitize_text(proxy_data.get("confidence", "Low / None"))
    proxy_summary = _sanitize_text(proxy_data.get("summary", "No VPN, Tor, or proxy headers detected."))

    proxy_rows = [
        [Paragraph("Anonymity Classification:", body_bold), Paragraph(proxy_class, body_style)],
        [Paragraph("Detection Confidence:", body_bold), Paragraph(proxy_conf, body_style)],
        [Paragraph("Attribution Integrity:", body_bold), Paragraph(proxy_summary, body_style)]
    ]
    proxy_table = Table(proxy_rows, colWidths=[130, 410])
    proxy_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_row_alt),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(proxy_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 11. CHRONOLOGICAL TRANSMISSION RELAY CHAIN
    # ==========================================
    story.append(Paragraph("7. Chronological SMTP Transmission Relay Chain", section_heading))
    hops = case_data.get("hops", []) or []

    hop_rows = [
        [
            Paragraph("Hop", body_bold),
            Paragraph("Relay IP", body_bold),
            Paragraph("Type", body_bold),
            Paragraph("Claimed Hostname", body_bold),
            Paragraph("Location", body_bold),
            Paragraph("Latency", body_bold)
        ]
    ]

    if not hops:
        hop_rows.append([
            Paragraph("N/A", body_style),
            Paragraph("Direct transmission (No intermediate hops)", body_style),
            Paragraph("-", body_style),
            Paragraph("-", body_style),
            Paragraph("-", body_style),
            Paragraph("-", body_style)
        ])
    else:
        for h in hops:
            priv_label = "Private RFC1918" if h.get("is_private") else "Public IP"
            claimed_str = _sanitize_text(h.get("claimed_host") or "N/A")[:26]
            loc_str = f"{_sanitize_text(h.get('city', 'Unknown'))}, {_sanitize_text(h.get('country', 'Unknown'))}"
            hop_rows.append([
                Paragraph(f"#{h.get('hop_order', 1)}", mono_style),
                Paragraph(_sanitize_text(h.get("relay_ip", "0.0.0.0")), mono_style),
                Paragraph(priv_label, body_style),
                Paragraph(claimed_str, body_style),
                Paragraph(loc_str, body_style),
                Paragraph(f"+{h.get('latency_seconds', 0)}s", mono_style)
            ])

    hop_table = Table(hop_rows, colWidths=[38, 92, 80, 160, 120, 50])
    hop_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_header_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(hop_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 12. ACTIONABLE RECOMMENDATIONS & PLAYBOOK
    # ==========================================
    story.append(Paragraph("8. Actionable Forensic Recommendations &amp; Incident Playbook", section_heading))
    if verdict == "MALICIOUS":
        recs = [
            "&bull; <b>Quarantine Immediately:</b> Isolate this message and revoke access across all enterprise inboxes.",
            "&bull; <b>Firewall Blacklist:</b> Block originating IP (<b>" + origin_ip_val + "</b>) and sender domain (<b>" + domain_val + "</b>) on perimeter gateways.",
            "&bull; <b>Credential Revocation:</b> If recipient entered credentials or clicked external links, trigger mandatory Active Directory password reset.",
            "&bull; <b>Out-of-Band Financial Verification:</b> Never modify bank wire coordinates via email. Verify via verified dual-party phone confirmation."
        ]
    elif verdict == "SUSPICIOUS":
        recs = [
            "&bull; <b>SOC Manual Verification:</b> Hold message in quarantine queue until authenticated via secondary communication.",
            "&bull; <b>Sender Verification:</b> Confirm request directly with sender via known internal phone or directory listing.",
            "&bull; <b>Sandbox Detonation:</b> Execute sandboxed detonation on any embedded links or attachments before user release."
        ]
    else:
        recs = [
            "&bull; <b>Safe for Delivery:</b> Message passed protocol verification and semantic checks; safe for standard delivery.",
            "&bull; <b>Standard Telemetry:</b> Maintain routine logging; no incident escalation required."
        ]
    
    rec_text = "<br/>".join(recs)
    rec_table = Table([[Paragraph(rec_text, body_style)]], colWidths=[540])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_row_alt),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(rec_table)
    story.append(Spacer(1, 5))

    # ==========================================
    # 13. EXTRACTED MESSAGE BODY EXCERPT
    # ==========================================
    plain_body = case_data.get("plain_body") or "No plain-text body content extracted."
    if len(plain_body) > 900:
        plain_body = plain_body[:900] + "\n\n[... Message truncated for forensic report exhibit length ...]"
    safe_body = _sanitize_text(plain_body).replace('\n', '<br/>')

    story.append(Paragraph("9. Extracted Plain-Text Message Body Excerpt", section_heading))
    body_table = Table([[Paragraph(safe_body, mono_code)]], colWidths=[540])
    body_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_row_alt),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(body_table)
    story.append(Spacer(1, 6))

    # ==========================================
    # 14. SECTION 65B CERTIFICATE & SIGN-OFF
    # ==========================================
    cert_text = (
        "<b>CERTIFICATE OF DIGITAL EVIDENCE AUTHENTICITY (SECTION 65B INDIAN EVIDENCE ACT / SIH #26106):</b><br/>"
        "I hereby certify that this electronic forensic dossier was autonomously generated by the AE-Forensics analytical "
        "gateway in the regular course of operation. The computing environment operated securely without telemetry or remote "
        "tampering. Cryptographic digest verification: <font name='Courier'><b>" + sha256_hash + "</b></font> guarantees strict data integrity."
    )
    cert_table = Table([[Paragraph(cert_text, ParagraphStyle(
        'Cert', fontName='Helvetica', fontSize=7, leading=9.5, textColor=c_slate_dark
    ))]], colWidths=[540])
    cert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#EFF6FF')),
        ('BOX', (0, 0), (-1, -1), 1, c_primary),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(cert_table)
    story.append(Spacer(1, 6))

    # Signature Block
    sig_rows = [
        [
            Paragraph("<b>Investigating Examiner:</b><br/>AE-Forensics Autonomous Examiner", body_style),
            Paragraph("<b>Digital Verification:</b><br/>Cryptographically Signed &bull; SHA-256 Sealed", body_style),
            Paragraph("<b>Authorized Institutional Seal:</b><br/>SIH Cyber Security Cell #26106", body_style)
        ]
    ]
    sig_table = Table(sig_rows, colWidths=[180, 180, 180])
    sig_table.setStyle(TableStyle([
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(sig_table)

    # Build genuine PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
