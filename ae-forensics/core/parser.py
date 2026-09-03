"""
AE-Forensics: RFC-822/5322 MIME Deconstruction & Chronological Hop Extraction
Calculates immutable SHA-256 evidence fingerprint upon ingest, parses all transmission
Received headers chronologically, and extracts clean textual segments and metadata.
"""

import re
import hashlib
import ipaddress
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from typing import List, Dict, Any, Tuple, Optional


def safe_decode_header(raw_val: Optional[str]) -> str:
    """Safely decode RFC 2047 encoded email headers."""
    if not raw_val:
        return ""
    try:
        decoded_parts = decode_header(raw_val)
        result = []
        for text, encoding in decoded_parts:
            if isinstance(text, bytes):
                result.append(text.decode(encoding or "utf-8", errors="replace"))
            else:
                result.append(str(text))
        return " ".join(result).strip()
    except Exception:
        return str(raw_val).strip()


def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract valid IPv4 and IPv6 addresses from header text snippets.
    """
    # Standard IPv4 pattern
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    candidates = re.findall(ipv4_pattern, text)
    valid_ips = []
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            if ip not in valid_ips:
                valid_ips.append(ip)
        except ValueError:
            continue
    return valid_ips


def extract_claimed_host(header_line: str) -> str:
    """
    Extract the claimed sending hostname from a Received header.
    Typical syntax: 'from mail.victim.com (1.2.3.4) by mx.google.com...'
    """
    # Look for 'from <host>'
    match = re.search(r"from\s+([a-zA-Z0-9\.\-\_]+)", header_line, re.IGNORECASE)
    if match:
        host = match.group(1).strip("[]();, ")
        if host.lower() not in ("unknown", "localhost", "127.0.0.1"):
            return host

    # Fallback to helo string
    helo_match = re.search(r"helo=([a-zA-Z0-9\.\-\_]+)", header_line, re.IGNORECASE)
    if helo_match:
        return helo_match.group(1).strip("[]();, ")

    return "Unknown Host"


def parse_received_timestamp(header_line: str) -> Optional[datetime]:
    """
    Extract and parse the semicolon-delimited date string at the end of a Received line.
    """
    if ";" not in header_line:
        return None
    raw_date_part = header_line.rsplit(";", 1)[-1].strip()
    try:
        return parsedate_to_datetime(raw_date_part)
    except Exception:
        return None


def parse_msg_payload(raw_bytes: bytes) -> Tuple[Dict[str, Any], str, str, List[str]]:
    """
    Fallback parser for Microsoft Outlook .msg compound files if extract-msg is available.
    """
    try:
        import extract_msg
        import io
        msg_obj = extract_msg.Message(io.BytesIO(raw_bytes))
        headers_dict = {}
        if msg_obj.header:
            for line in str(msg_obj.header).splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers_dict[k.strip()] = v.strip()

        subject = msg_obj.subject or "No Subject"
        sender = msg_obj.sender or "Unknown"
        to_addr = msg_obj.to or "None"
        date_str = str(msg_obj.date) if msg_obj.date else datetime.now(timezone.utc).isoformat()
        body_text = msg_obj.body or ""
        body_html = msg_obj.htmlBody.decode("utf-8", errors="ignore") if msg_obj.htmlBody else ""

        received_headers = []
        if msg_obj.header:
            for k, v in msg_obj.header.items():
                if k.lower() == "received":
                    received_headers.append(v)

        return (
            {
                "Subject": subject,
                "From": sender,
                "To": to_addr,
                "Date": date_str,
                "Message-ID": headers_dict.get("Message-ID", f"<{hashlib.md5(raw_bytes).hexdigest()}@msg.local>"),
                "Return-Path": headers_dict.get("Return-Path", sender),
                "Reply-To": headers_dict.get("Reply-To", sender),
                "headers_raw": str(msg_obj.header or ""),
                "received_list": received_headers,
            },
            body_text,
            body_html,
            [att.longFilename or att.shortFilename for att in (msg_obj.attachments or []) if att.filename]
        )
    except Exception:
        # If extract_msg fails, attempt to read any plaintext strings from bytes
        return (
            {
                "Subject": "Outlook MSG (Parsed via Binary Fallback)",
                "From": "Unknown <unknown@msg.local>",
                "To": "None",
                "Date": datetime.now(timezone.utc).isoformat(),
                "Message-ID": f"<{hashlib.md5(raw_bytes).hexdigest()}@msg.local>",
                "Return-Path": "None",
                "Reply-To": "None",
                "headers_raw": "",
                "received_list": [],
            },
            raw_bytes.decode("latin1", errors="ignore")[:4000],
            "",
            []
        )


def parse_text_fallback(text: str) -> Tuple[Dict[str, Any], str, str, List[str]]:
    """
    Robust fallback parser for plain text, copied email headers, forwarded messages,
    or informal email transcripts (supporting Gmail, Outlook, Apple Mail, and raw dumps).
    """
    headers: Dict[str, Any] = {
        "Subject": "No Subject",
        "From": "Unknown <unknown@local>",
        "To": "None",
        "Date": datetime.now(timezone.utc).isoformat(),
        "Message-ID": f"<{hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()[:16]}@text.local>",
        "Return-Path": "None",
        "Reply-To": "None",
        "headers_raw": "",
        "received_list": []
    }

    if not text or not text.strip():
        return headers, "", "", []

    # Check for forwarded message preambles
    # e.g., '---------- Forwarded message ---------', '-----Original Message-----', 'Begin forwarded message:'
    fwd_stripped = text
    fwd_marker = re.search(
        r"(?:[-=]{3,}\s*Forwarded message\s*[-=]{3,}|[-=]{3,}\s*Original Message\s*[-=]{3,}|Begin forwarded message:)",
        text,
        re.IGNORECASE
    )
    if fwd_marker:
        fwd_stripped = text[fwd_marker.end():].lstrip()

    # Split into header and body sections if separated by blank line
    parts = re.split(r"\r?\n\r?\n", fwd_stripped, maxsplit=1)
    header_block = parts[0]
    body_text = parts[1] if len(parts) > 1 else fwd_stripped

    # Search for header fields in the candidate block
    extracted_keys = set()
    for line in header_block.splitlines():
        line_clean = line.strip()
        if ":" in line_clean and not line_clean.startswith(">"):
            k, v = line_clean.split(":", 1)
            k_clean = k.strip().lower()
            v_clean = v.strip()
            if k_clean == "subject" and v_clean:
                headers["Subject"] = v_clean
                extracted_keys.add("subject")
            elif k_clean in ("from", "sender") and v_clean:
                headers["From"] = v_clean
                extracted_keys.add("from")
            elif k_clean in ("to", "recipient") and v_clean:
                headers["To"] = v_clean
                extracted_keys.add("to")
            elif k_clean in ("date", "sent") and v_clean:
                headers["Date"] = v_clean
                extracted_keys.add("date")
            elif k_clean == "message-id" and v_clean:
                headers["Message-ID"] = v_clean
                extracted_keys.add("message-id")
            elif k_clean == "return-path" and v_clean:
                headers["Return-Path"] = v_clean
            elif k_clean == "reply-to" and v_clean:
                headers["Reply-To"] = v_clean
            elif k_clean == "received" and v_clean:
                headers["received_list"].append(v_clean)

    # Multi-line or full-text regex sweep for missing critical fields (supports quotes, forwarders, informal pastes)
    if "from" not in extracted_keys:
        m_from = re.search(r"^(?:>*\s*)?(?:From|Sender):\s*([^\r\n]+)", text, re.IGNORECASE | re.MULTILINE)
        if m_from and m_from.group(1).strip():
            headers["From"] = m_from.group(1).strip()
            extracted_keys.add("from")

    if "subject" not in extracted_keys:
        m_subj = re.search(r"^(?:>*\s*)?Subject:\s*([^\r\n]+)", text, re.IGNORECASE | re.MULTILINE)
        if m_subj and m_subj.group(1).strip():
            headers["Subject"] = m_subj.group(1).strip()
            extracted_keys.add("subject")

    if "to" not in extracted_keys:
        m_to = re.search(r"^(?:>*\s*)?(?:To|Recipient):\s*([^\r\n]+)", text, re.IGNORECASE | re.MULTILINE)
        if m_to and m_to.group(1).strip():
            headers["To"] = m_to.group(1).strip()

    if "date" not in extracted_keys:
        m_date = re.search(r"^(?:>*\s*)?(?:Date|Sent):\s*([^\r\n]+)", text, re.IGNORECASE | re.MULTILINE)
        if m_date and m_date.group(1).strip():
            headers["Date"] = m_date.group(1).strip()

    # Capture all Received headers if text is an unparsed header stream
    received_matches = re.findall(r"^(?:>*\s*)?Received:\s*([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)", text, re.IGNORECASE | re.MULTILINE)
    for rec in received_matches:
        rec_clean = " ".join(rec.split())
        if rec_clean not in headers["received_list"]:
            headers["received_list"].append(rec_clean)

    # If body_text still has header lines at top, strip them
    body_lines = []
    in_header_prefix = True
    for line in body_text.splitlines():
        if in_header_prefix:
            if re.match(r"^(?:[-=]{3,}|>*\s*(?:From|To|Date|Sent|Subject|Cc|Bcc|Reply-To):)", line, re.IGNORECASE):
                continue
            if not line.strip():
                continue
            in_header_prefix = False
        body_lines.append(line)

    clean_body = "\n".join(body_lines).strip()
    if not clean_body:
        clean_body = body_text.strip()

    headers["headers_raw"] = header_block
    return headers, clean_body, "", []


def parse_email_bytes(raw_bytes: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Ingest raw RFC-822 (.eml), Outlook (.msg), plain-text (.txt), or pasted text bytes.
    Computes immediate SHA-256 fingerprint, extracts headers, reverses Received hops,
    extracts alternate IP vectors (X-Originating-IP, etc.), and extracts clean bodies.
    """
    # 1. Immediate cryptographic SHA-256 evidence fingerprint
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    # Detect if file is an Outlook compound binary (.msg)
    is_ole_msg = raw_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") or filename.lower().endswith(".msg")
    is_txt = filename.lower().endswith(".txt")

    received_raw_list: List[str] = []
    plain_body = ""
    html_body = ""
    attachments: List[str] = []
    raw_headers_str = ""

    if is_ole_msg:
        meta, plain_body, html_body, attachments = parse_msg_payload(raw_bytes)
        subject = meta["Subject"]
        from_hdr = meta["From"]
        to_hdr = meta["To"]
        date_hdr = meta["Date"]
        message_id = meta["Message-ID"]
        return_path = meta["Return-Path"]
        reply_to = meta["Reply-To"]
        received_raw_list = meta["received_list"]
        raw_headers_str = meta["headers_raw"]
    else:
        # Attempt standard RFC-822 / MIME parsing with BytesParser
        parsed_successfully = False
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            subject = safe_decode_header(msg.get("Subject", ""))
            from_hdr = safe_decode_header(msg.get("From", ""))
            to_hdr = safe_decode_header(msg.get("To", "None"))
            date_hdr = safe_decode_header(msg.get("Date", ""))
            message_id = safe_decode_header(msg.get("Message-ID", f"<{sha256_hash[:16]}@local>"))
            return_path = safe_decode_header(msg.get("Return-Path", "None"))
            reply_to = safe_decode_header(msg.get("Reply-To", "None"))

            plain_parts = []
            html_parts = []

            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    cdispo = str(part.get("Content-Disposition", ""))
                    filename_part = part.get_filename()

                    if filename_part:
                        attachments.append(filename_part)
                    elif ctype == "text/plain" and "attachment" not in cdispo:
                        payload = part.get_payload(decode=True)
                        if payload:
                            plain_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
                    elif ctype == "text/html" and "attachment" not in cdispo:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
            else:
                ctype = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                if payload:
                    decoded = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
                    if ctype == "text/html":
                        html_parts.append(decoded)
                    else:
                        plain_parts.append(decoded)

            plain_body = "\n".join(plain_parts).strip()
            html_body = "\n".join(html_parts).strip()

            received_raw_list = msg.get_all("Received", []) or []
            raw_headers_str = "\n".join([f"{k}: {v}" for k, v in msg.items()])

            # If from_hdr and subject are present, or plain_body extracted, consider parsed
            if from_hdr or subject or plain_body or received_raw_list:
                parsed_successfully = True
        except Exception:
            parsed_successfully = False

        # Fallback to plain-text / decoded string parser if MIME parser failed, found no sender, or text is a forwarded snippet
        if not parsed_successfully or not from_hdr or not subject or "forwarded message" in plain_body.lower() or "original message" in plain_body.lower():
            # Decode using best-effort encodings
            text_candidate = ""
            for enc in ["utf-8", "latin1", "cp1252", "utf-16"]:
                try:
                    text_candidate = raw_bytes.decode(enc)
                    break
                except Exception:
                    continue
            if not text_candidate:
                text_candidate = raw_bytes.decode("utf-8", errors="replace")

            meta, fb_plain, fb_html, fb_att = parse_text_fallback(text_candidate)
            if not from_hdr or from_hdr == "Unknown <unknown@local>":
                if meta["From"] and meta["From"] != "Unknown <unknown@local>":
                    from_hdr = meta["From"]
            if not subject or subject == "No Subject":
                if meta["Subject"] and meta["Subject"] != "No Subject":
                    subject = meta["Subject"]
            if (not to_hdr or to_hdr in ("None", "none")) and meta["To"] != "None":
                to_hdr = meta["To"]
            if not date_hdr and meta["Date"]:
                date_hdr = meta["Date"]
            if not plain_body and fb_plain:
                plain_body = fb_plain
            elif ("forwarded message" in plain_body.lower() or "original message" in plain_body.lower()) and fb_plain:
                plain_body = fb_plain
            if not raw_headers_str and meta["headers_raw"]:
                raw_headers_str = meta["headers_raw"]
            if not received_raw_list and meta["received_list"]:
                received_raw_list = meta["received_list"]

    # Sanitize default values if still empty
    if not subject:
        subject = "No Subject"
    if not from_hdr:
        from_hdr = "Unknown Sender <unknown@external>"
    if not date_hdr:
        date_hdr = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    # If plain body is empty but html exists, strip HTML tags for clean NLP input
    if not plain_body and html_body:
        clean_text = re.sub(r"<style[^>]*>[\s\S]*?</style>", "", html_body, flags=re.IGNORECASE)
        clean_text = re.sub(r"<script[^>]*>[\s\S]*?</script>", "", clean_text, flags=re.IGNORECASE)
        clean_text = re.sub(r"<[^>]+>", " ", clean_text)
        plain_body = re.sub(r"\s+", " ", clean_text).strip()

    # Clean display name and email address
    disp_name, clean_email = parseaddr(from_hdr)
    if not clean_email and "@" in from_hdr:
        email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", from_hdr)
        clean_email = email_match.group(0) if email_match else from_hdr
    sender_domain = clean_email.split("@")[-1].lower().strip(" >") if "@" in clean_email else "unknown"

    # Extract all embedded URLs from text & html
    full_content = f"{plain_body} {html_body}"
    urls = list(set(re.findall(r"https?://[^\s<>'\"\)\]]+", full_content)))

    # Process Received hops: RFC specifies newest at top, so reversing gives chronological order
    ordered_received = list(reversed(received_raw_list))
    hops: List[Dict[str, Any]] = []
    previous_time: Optional[datetime] = None

    for idx, item in enumerate(ordered_received):
        item_str = str(item).replace("\r", " ").replace("\n", " ")
        ips = extract_ips_from_text(item_str)
        relay_ip = ips[0] if ips else "0.0.0.0"

        # Check private IP
        is_private = False
        if relay_ip != "0.0.0.0":
            try:
                is_private = ipaddress.ip_address(relay_ip).is_private
            except ValueError:
                is_private = False

        claimed = extract_claimed_host(item_str)
        timestamp = parse_received_timestamp(item_str)

        # Transmission latency delta
        latency_seconds = 0
        if timestamp and previous_time:
            delta = (timestamp - previous_time).total_seconds()
            latency_seconds = max(0, int(delta))
        if timestamp:
            previous_time = timestamp

        hops.append({
            "hop_order": idx + 1,
            "relay_ip": relay_ip,
            "is_private": is_private,
            "claimed_host": claimed,
            "timestamp": timestamp.isoformat() if timestamp else None,
            "latency_seconds": latency_seconds,
            "raw_header": item_str[:300]
        })

    # If no Received hops were found, search for alternate headers like X-Originating-IP or Received-SPF
    if not hops:
        alt_ip_candidates = []
        for header_name in ["x-originating-ip", "x-sender-ip", "x-real-ip", "x-client-ip"]:
            match = re.search(rf"{header_name}:\s*\[?([0-9a-f\.:]+)\]?", raw_headers_str, re.IGNORECASE)
            if match:
                extracted = extract_ips_from_text(match.group(1))
                if extracted:
                    alt_ip_candidates.append(extracted[0])

        # Also check Received-SPF or Authentication-Results client-ip
        spf_client_ip = re.search(r"(?:client-ip|sender IP)\s*=?\s*([0-9\.]+)", raw_headers_str, re.IGNORECASE)
        if spf_client_ip:
            extracted = extract_ips_from_text(spf_client_ip.group(1))
            if extracted:
                alt_ip_candidates.append(extracted[0])

        for alt_ip in alt_ip_candidates:
            try:
                is_priv = ipaddress.ip_address(alt_ip).is_private
                hops.append({
                    "hop_order": len(hops) + 1,
                    "relay_ip": alt_ip,
                    "is_private": is_priv,
                    "claimed_host": "Origin Gateway Header",
                    "timestamp": None,
                    "latency_seconds": 0,
                    "raw_header": f"Extracted from Alternate Origin Header: {alt_ip}"
                })
            except ValueError:
                pass

        # If still empty, check if message body contains referenced public IPs (e.g. security alert transcripts)
        if not hops:
            body_ips = extract_ips_from_text(plain_body)
            for b_ip in body_ips:
                try:
                    ip_obj = ipaddress.ip_address(b_ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        hops.append({
                            "hop_order": len(hops) + 1,
                            "relay_ip": b_ip,
                            "is_private": False,
                            "claimed_host": "Referenced Remote Host",
                            "timestamp": None,
                            "latency_seconds": 0,
                            "raw_header": f"Extracted from Message Body Content: {b_ip}"
                        })
                        break
                except ValueError:
                    pass

    return {
        "sha256": sha256_hash,
        "subject": subject,
        "from": from_hdr,
        "display_name": disp_name or clean_email or "Unknown",
        "sender_email": clean_email or from_hdr,
        "sender_domain": sender_domain,
        "to": to_hdr,
        "date": date_hdr,
        "message_id": message_id,
        "return_path": return_path,
        "reply_to": reply_to,
        "plain_body": plain_body,
        "html_body": html_body,
        "attachments": attachments,
        "extracted_urls": urls[:20],
        "raw_headers": raw_headers_str,
        "hops": hops,
        "raw_bytes": raw_bytes
    }

