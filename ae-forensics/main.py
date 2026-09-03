"""
AE-Forensics: Main FastAPI Server & Analytical Gateway
Problem Statement #26106 | SIH Cyber Security Cell
Exposes REST endpoints for multipart email triage, historical cases archive,
IMAP worker controls, sample payloads, and serves the SOC analyst single-page UI.
"""

import os
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from database import init_db, save_case, get_cases, get_case_by_id, get_stats, get_case_by_hash
from core.parser import parse_email_bytes
from core.auth import evaluate_protocol_auth
from core.geo_tracer import trace_hops_and_origin
from core.nlp_engine import analyze_semantic_intent
from core.proxy_detector import detect_vpn_or_proxy
from core.scorer import compute_threat_score
from core.pdf_generator import generate_forensic_pdf
from services.imap_worker import get_imap_worker

# Working directory context
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Initialize database schema eagerly on cold start
try:
    init_db()
except Exception:
    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle startup and shutdown handler."""
    # 1. Initialize SQLite schema
    init_db()
    # 2. Start IMAP background polling worker only in persistent server mode (not in Lambda)
    worker = None
    if not os.environ.get("AWS_LAMBDA_FUNCTION_NAME") and not os.environ.get("AWS_EXECUTION_ENV"):
        try:
            worker = get_imap_worker()
            worker.start()
        except Exception:
            pass
    yield
    # Cleanup on server shutdown
    if worker:
        worker.stop()


app = FastAPI(
    title="AE-Forensics: AI-Powered Email Threat & Forensic Intelligence Platform",
    description="Zero-cost, local CPU, air-gap capable email threat detection and geolocation platform.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for security research and front-end integration (Amplify, Lambda, Custom Domains)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r"^https?://.*",
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Type", "Content-Length", "X-Case-ID"],
)


@app.options("/{full_path:path}")
async def preflight_options_handler(full_path: str):
    """Fallback handler to guarantee 200 OK for any OPTIONS preflight request."""
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "*",
        }
    )


def run_full_forensic_pipeline(raw_bytes: bytes, filename: str = "", db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes the comprehensive forensic evaluation on raw email bytes:
    1. Header deconstruction & chronological hop extraction
    2. Private subnet filtering & Origin IP geolocation
    3. Direct DNS SPF / DMARC & cryptographic DKIM checks
    4. CPU-optimized semantic threat intent scoring (BEC, urgency, credentials)
    5. Multi-factor mathematical scoring
    6. SQLite relational persistence
    """
    # Parse RFC-822 / MSG bytes
    parsed = parse_email_bytes(raw_bytes, filename=filename)

    # Resolve hops and true originating IP
    origin_ip, enriched_hops, origin_geo = trace_hops_and_origin(parsed["hops"])

    # Multi-layer VPN / Proxy / Anonymizer detection
    proxy_data = detect_vpn_or_proxy(origin_ip, enriched_hops, parsed["raw_headers"])

    # Protocol authentication checks
    auth_data = evaluate_protocol_auth(
        sender_domain=parsed["sender_domain"],
        origin_ip=origin_ip,
        raw_bytes=raw_bytes,
        raw_headers=parsed["raw_headers"],
        display_name=parsed["display_name"],
        sender_email=parsed["sender_email"]
    )

    # Local semantic intent analysis
    nlp_data = analyze_semantic_intent(parsed["plain_body"])

    # Deterministic threat score computation
    scoring = compute_threat_score(
        nlp_score=nlp_data["nlp_score"],
        auth_data=auth_data,
        origin_ip=origin_ip,
        hops=enriched_hops,
        proxy_data=proxy_data
    )

    # Create immutable forensic case record
    case_id = str(uuid.uuid4())
    case_record = {
        "case_id": case_id,
        "sha256": parsed["sha256"],
        "subject": parsed["subject"],
        "sender": parsed["from"],
        "sender_domain": parsed["sender_domain"],
        "return_path": parsed["return_path"],
        "recipient": parsed["to"],
        "received_date": parsed["date"],
        "origin_ip": origin_ip,
        "threat_score": scoring["threat_score"],
        "verdict": scoring["verdict"],
        "verdict_desc": scoring.get("verdict_summary", ""),
        "spf_status": auth_data["spf_status"],
        "dkim_status": auth_data["dkim_status"],
        "dmarc_status": auth_data["dmarc_status"],
        "is_display_spoofed": auth_data["is_display_spoofed"],
        "nlp_score": nlp_data["nlp_score"],
        "raw_headers": parsed["raw_headers"],
        "plain_body": parsed["plain_body"],
        "extracted_urls": parsed.get("extracted_urls", []),
        "origin_geo": origin_geo,
        "hops": enriched_hops,
        "auth": auth_data,
        "nlp_intent": nlp_data,
        "tone_analysis": nlp_data.get("tone_analysis", {}),
        "proxy_analysis": proxy_data,
        "score_breakdown": scoring["score_breakdown"]
    }

    # Persist in SQLite
    save_case(case_record, enriched_hops, db_path=db_path)

    return case_record


# ==========================================
# SYNTHETIC RFC-822 EMAIL TEST SAMPLES
# ==========================================
SYNTHETIC_SAMPLES = {
    "clean": (
        b"Received: from mail-relay1.google.com (mail-relay1.google.com [209.85.220.41]) by mx.victim.org with ESMTPS id abc1234; Thu, 03 Sep 2026 09:12:00 +0000\r\n"
        b"Received: from 10.0.1.5 (10.0.1.5) by mail-relay1.google.com with SMTP id xyz789; Thu, 03 Sep 2026 09:11:45 +0000\r\n"
        b"From: GitHub Support <support@github.com>\r\n"
        b"To: engineer@victim.org\r\n"
        b"Subject: [GitHub] Security advisory summary for week 36\r\n"
        b"Date: Thu, 03 Sep 2026 09:12:00 +0000\r\n"
        b"Message-ID: <clean-sample-001@github.com>\r\n"
        b"Return-Path: <support@github.com>\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=s202111; h=from:to:subject:date:message-id;\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Hello,\n\nHere is your routine weekly security advisory report for repositories under your organization.\n"
        b"No critical vulnerabilities or action items were detected in your monitored dependencies.\n\n"
        b"Best regards,\nThe GitHub Team\n"
    ),
    "bec": (
        b"Received: from bulletproof-proxy.nl (bulletproof-proxy.nl [45.154.255.88]) by mx.victim.org with ESMTP id bec456; Thu, 03 Sep 2026 10:30:00 +0000\r\n"
        b"Received: from anonymous-vpn.ru (185.220.101.5) by bulletproof-proxy.nl with ESMTP id hop2; Thu, 03 Sep 2026 10:28:10 +0000\r\n"
        b"Received: from 192.168.1.100 (192.168.1.100) by anonymous-vpn.ru with SMTP id hop1; Thu, 03 Sep 2026 10:25:00 +0000\r\n"
        b"From: CFO David Miller <david.miller.cfo99@gmail.com>\r\n"
        b"To: finance-director@victim.org\r\n"
        b"Subject: URGENT: Updated Bank Account Details for Wire Transfer - Invoice #89201\r\n"
        b"Date: Thu, 03 Sep 2026 10:30:00 +0000\r\n"
        b"Message-ID: <bec-fraud-991@gmail.com>\r\n"
        b"Return-Path: <hacker-bounce@apex-vendor-updates.biz>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Dear Accounts Payable Team,\n\n"
        b"Please treat this notice with urgent attention. Due to an ongoing audit and system transition, our banking coordinates have been updated immediately.\n"
        b"Do not send the upcoming wire transfer for invoice #89201 to the previous account.\n\n"
        b"Please execute the transfer funds to our updated bank account details below:\n"
        b"Beneficiary: Apex Global Services Ltd\n"
        b"Routing Number: 021000021\n"
        b"SWIFT Code: CHASEUS33\n"
        b"Account Number: 984128912849\n\n"
        b"Immediate action required. Please attach the remittance advice once completed today.\n\n"
        b"Regards,\nDavid Miller\nChief Financial Officer\n"
    ),
    "phishing": (
        b"Received: from evil-host.xyz (evil-host.xyz [194.26.29.110]) by mx.victim.org with ESMTP id phish77; Thu, 03 Sep 2026 11:15:00 +0000\r\n"
        b"From: IT Support Administrator <security-notice@google.com>\r\n"
        b"To: user@victim.org\r\n"
        b"Subject: Final Warning: Unauthorized Login Detected - Account Suspended Within 24 Hours\r\n"
        b"Date: Thu, 03 Sep 2026 11:15:00 +0000\r\n"
        b"Message-ID: <phish-alert-444@google.com>\r\n"
        b"Return-Path: <nobody@evil-host.xyz>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"SECURITY ALERT:\n\n"
        b"An unauthorized login attempt was detected originating from an unrecognized IP address in Moscow, Russia.\n"
        b"Your institutional email access will be locked and terminated within 24 hours.\n\n"
        b"Immediate action required:\n"
        b"Click here to verify your account and validate your credentials immediately:\n"
        b"https://it-support-portal.cloud/login/verify-credentials?id=99281\n\n"
        b"Reset your password and re-authenticate your session to prevent permanent account suspension.\n\n"
        b"IT Operations & Information Security\n"
    ),
    "spoof": (
        b"Received: from mail-sor-f65.google.com (mail-sor-f65.google.com [209.85.220.65]) by mx.victim.org with ESMTPS id spoofer88; Thu, 03 Sep 2026 12:00:00 +0000\r\n"
        b"From: CEO Vikram Malhotra <vikram.malhotra.exec99@gmail.com>\r\n"
        b"To: staff@victim.org\r\n"
        b"Subject: Quick confidential task - Are you in the office?\r\n"
        b"Date: Thu, 03 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <spoof-ceo-777@gmail.com>\r\n"
        b"Return-Path: <vikram.malhotra.exec99@gmail.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Are you at your desk right now?\n\n"
        b"I need a quick favor. I am currently tied up in a strictly confidential meeting and cannot take calls on my phone.\n"
        b"I need you to urgently purchase 5 Apple gift cards for a critical client presentation today.\n\n"
        b"Please keep this discreet and handle this personally. Email me the voucher codes as soon as possible.\n\n"
        b"Sent from my iPhone\n"
        b"Vikram Malhotra\n"
        b"Chief Executive Officer\n"
    ),
    "angry_complaint": (
        b"Received: from mail-relay1.google.com (mail-relay1.google.com [209.85.220.41]) by mx.victim.org with ESMTPS id complaint99; Thu, 03 Sep 2026 14:20:00 +0000\r\n"
        b"Received: from 10.0.2.14 (10.0.2.14) by mail-relay1.google.com with SMTP id comp123; Thu, 03 Sep 2026 14:19:40 +0000\r\n"
        b"From: Sarah Jenkins <sarah.jenkins@google.com>\r\n"
        b"To: support@victim.org\r\n"
        b"Subject: Unacceptable platform outage - fix this damn issue immediately!\r\n"
        b"Date: Thu, 03 Sep 2026 14:20:00 +0000\r\n"
        b"Message-ID: <complaint-sample-901@google.com>\r\n"
        b"Return-Path: <sarah.jenkins@google.com>\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=20230601;\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"What the hell is going on with the cloud service today? This is complete crap and our entire pipeline is completely broken.\n\n"
        b"You people are acting totally incompetent on this support ticket. Fix this damn issue immediately before our executive client demo.\n"
        b"This service has been absolute garbage all morning and the delay is totally unacceptable and ridiculous.\n\n"
        b"Regards,\nSarah Jenkins\n"
    )
}


# ==========================================
# REST ENDPOINTS
# ==========================================

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Render the SOC Analyst responsive single-page application."""
    index_file = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(index_file):
        raise HTTPException(status_code=404, detail="Template index.html not found")
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


from pydantic import BaseModel

class RawTextPayload(BaseModel):
    raw_text: str
    filename: Optional[str] = "pasted_email.eml"


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Ingest a raw .eml, .msg, or .txt file payload, execute full forensic pipeline,
    and return JSON forensic verdict and hop trace.
    """
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file payload uploaded")
    if len(raw_bytes) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Payload exceeds 25 MB ceiling")

    result = run_full_forensic_pipeline(raw_bytes, filename=file.filename or "")
    return JSONResponse(content=result)


@app.post("/api/analyze-text")
async def analyze_raw_text(payload: RawTextPayload):
    """
    Ingest pasted raw email headers / message content, execute full forensic pipeline,
    and return JSON forensic verdict and hop trace.
    """
    text = payload.raw_text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Empty text content submitted")
    raw_bytes = text.encode("utf-8")
    result = run_full_forensic_pipeline(raw_bytes, filename=payload.filename or "pasted_email.eml")
    return JSONResponse(content=result)


@app.get("/api/sample/{sample_type}")
async def analyze_sample(sample_type: str):
    """
    Load and execute full forensic pipeline on one of the built-in synthetic test vectors.
    """
    sample_key = sample_type.lower()
    if sample_key not in SYNTHETIC_SAMPLES:
        raise HTTPException(status_code=404, detail=f"Sample '{sample_type}' not found. Available: clean, bec, phishing, spoof, angry_complaint")

    raw_bytes = SYNTHETIC_SAMPLES[sample_key]
    result = run_full_forensic_pipeline(raw_bytes, filename=f"sample_{sample_key}.eml")
    return JSONResponse(content=result)


@app.get("/api/cases")
async def list_cases(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    """Retrieve historical triage records ordered chronologically."""
    cases = get_cases(limit=limit, offset=offset)
    return JSONResponse(content=cases)


@app.get("/api/cases/{case_id}")
async def get_case_details(case_id: str):
    """Retrieve full forensic case dossier including sequential hops and headers."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case record not found")
    return JSONResponse(content=case)


@app.get("/api/cases/{case_id}/export")
async def export_court_admissible_case(case_id: str):
    """Generate structured court-admissible forensic JSON evidence package."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case record not found")

    evidence_packet = {
        "court_evidence_metadata": {
            "evidence_id": f"EXHIBIT-{case_id.upper()[:8]}",
            "case_uuid": case_id,
            "sha256_cryptographic_hash": case.get("sha256"),
            "custody_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "compliance_standard": "SIH Cyber Security Cell Problem Statement #26106"
        },
        "message_attribution": {
            "originating_ip": case.get("origin_ip"),
            "declared_sender": case.get("sender"),
            "sender_domain": case.get("sender_domain"),
            "return_path": case.get("return_path"),
            "recipient": case.get("recipient"),
            "received_date": case.get("received_date")
        },
        "protocol_authenticity_matrix": {
            "spf_result": case.get("spf_status"),
            "dkim_result": case.get("dkim_status"),
            "dmarc_result": case.get("dmarc_status")
        },
        "threat_assessment": {
            "threat_score": case.get("threat_score"),
            "verdict": case.get("verdict"),
            "nlp_semantic_intent_score": case.get("nlp_score")
        },
        "transmission_hops": case.get("hops", []),
        "raw_headers": case.get("raw_headers")
    }
    return JSONResponse(content=evidence_packet)


@app.get("/api/report/pdf/{case_id}")
async def download_case_pdf_report(case_id: str, download: bool = False):
    """Generate and stream an official, Section 65B compliant PDF forensic report."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case record not found")
    
    try:
        pdf_bytes = generate_forensic_pdf(case)
        filename = f"AE-Forensics-Report-{case_id[:8].upper()}.pdf"
        disposition = "attachment" if download else "inline"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'{disposition}; filename="{filename}"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")


@app.post("/api/imap/poll")
async def trigger_imap_poll():
    """Manual trigger to execute an immediate IMAP inbox scan."""
    worker = get_imap_worker()
    res = worker.poll_once()
    return JSONResponse(content=res)


@app.get("/api/imap/status")
async def get_imap_status():
    """Check IMAP background listener status."""
    worker = get_imap_worker()
    return JSONResponse(content=worker.get_status())


@app.get("/api/stats")
async def get_dashboard_stats():
    """Return summary triage statistics."""
    stats = get_stats()
    return JSONResponse(content=stats)


@app.get("/api/health")
async def healthcheck():
    """Service health and diagnostic status."""
    return {
        "status": "online",
        "engine": "AE-Forensics Local CPU Engine",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "SQLite (forensics.db)",
        "features": {
            "offline_geotracing": True,
            "dns_validation": True,
            "dkim_cryptography": True,
            "cpu_nlp_engine": True
        }
    }


# AWS Lambda Serverless Entrypoint (Mangum ASGI Adapter)
try:
    from mangum import Mangum
    handler = Mangum(app, lifespan="off")
except ImportError:
    handler = None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
