"""
AE-Forensics: API & Endpoints Verification Script
Tests REST endpoints, file uploads, sample triggers, case retrieval, and evidence export.
"""

import os
import sys
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app, SYNTHETIC_SAMPLES
from database import init_db

# Initialize database
init_db()

client = TestClient(app)

def test_endpoints():
    print("Testing GET / (Dashboard UI)...")
    res = client.get("/")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert "AE-FORENSICS" in res.text, "Title not found in dashboard HTML"
    print("  -> PASSED: Dashboard HTML loaded successfully.")

    print("Testing GET /api/health...")
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    print(f"  -> PASSED: Health status: {data['status']}, features: {list(data['features'].keys())}")

    print("Testing GET /api/sample/bec...")
    res = client.get("/api/sample/bec")
    assert res.status_code == 200
    bec_data = res.json()
    assert bec_data["verdict"] == "MALICIOUS", f"Expected MALICIOUS, got {bec_data['verdict']}"
    assert bec_data["threat_score"] >= 70.0
    case_id = bec_data["case_id"]
    print(f"  -> PASSED: BEC sample verdict: {bec_data['verdict']} (Score: {bec_data['threat_score']})")

    print(f"Testing GET /api/cases/{case_id}...")
    res = client.get(f"/api/cases/{case_id}")
    assert res.status_code == 200
    case_detail = res.json()
    assert len(case_detail["hops"]) > 0
    print(f"  -> PASSED: Case details retrieved with {len(case_detail['hops'])} hops.")

    print(f"Testing GET /api/cases/{case_id}/export...")
    res = client.get(f"/api/cases/{case_id}/export")
    assert res.status_code == 200
    court_pkg = res.json()
    assert "court_evidence_metadata" in court_pkg
    assert court_pkg["court_evidence_metadata"]["sha256_cryptographic_hash"] == bec_data["sha256"]
    print(f"  -> PASSED: Court-admissible export generated (Exhibit ID: {court_pkg['court_evidence_metadata']['evidence_id']}).")

    print("Testing POST /api/analyze (Multipart file upload)...")
    file_bytes = SYNTHETIC_SAMPLES["phishing"]
    files = {"file": ("suspicious_alert.eml", io.BytesIO(file_bytes), "message/rfc822")}
    res = client.post("/api/analyze", files=files)
    assert res.status_code == 200
    upload_res = res.json()
    assert upload_res["verdict"] in ["SUSPICIOUS", "MALICIOUS"]
    print(f"  -> PASSED: Upload triage verdict: {upload_res['verdict']} (Score: {upload_res['threat_score']})")

    print("Testing POST /api/analyze-text (Pasted content)...")
    res = client.post("/api/analyze-text", json={
        "raw_text": "From: Security Team <admin@fake-login.xyz>\nTo: target@victim.org\nSubject: Critical MFA Alert\n\nPlease re-authenticate your session immediately: https://fake-login.xyz/login"
    })
    assert res.status_code == 200
    pasted_res = res.json()
    assert pasted_res["threat_score"] > 0
    print(f"  -> PASSED: Analyze pasted text verdict: {pasted_res['verdict']} (Score: {pasted_res['threat_score']})")

    print(f"Testing GET /api/report/pdf/{case_id}...")
    res = client.get(f"/api/report/pdf/{case_id}?download=true")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert len(res.content) > 1000
    print(f"  -> PASSED: PDF report streamed successfully ({len(res.content)} bytes).")

    print("Testing GET /api/cases...")
    res = client.get("/api/cases")
    assert res.status_code == 200
    cases_list = res.json()
    assert len(cases_list) >= 2
    print(f"  -> PASSED: Historical cases archive returned {len(cases_list)} records.")

    print("Testing GET /api/imap/status...")
    res = client.get("/api/imap/status")
    assert res.status_code == 200
    imap_status = res.json()
    print(f"  -> PASSED: IMAP status: running={imap_status['is_running']}, configured={imap_status['is_configured']}")

    print("\nALL API ENDPOINTS TESTED AND VERIFIED SUCCESSFULLY!\n")

if __name__ == "__main__":
    test_endpoints()

