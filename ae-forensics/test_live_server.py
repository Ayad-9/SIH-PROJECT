"""
AE-Forensics: Live Server & HTTP Integration Test
Queries running Uvicorn instance via Python's standard library urllib.
"""

import urllib.request
import urllib.parse
import json
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def get(path: str):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        raw = resp.read().decode("utf-8")
        try:
            return resp.status, json.loads(raw)
        except Exception:
            return resp.status, raw

def post_multipart(path: str, filename: str, file_bytes: bytes):
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: message/rfc822\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))

def main():
    print(f"Checking live server at {BASE_URL}...")
    
    # 1. Healthcheck
    status, health = get("/api/health")
    assert status == 200 and health["status"] == "online"
    print(f"  [OK] /api/health -> {health['status']}")

    # 2. UI Template
    status, html = get("/")
    assert status == 200 and "AE-FORENSICS" in html
    print("  [OK] / (UI Dashboard HTML loaded)")

    # 3. Test Built-in Sample (BEC Wire Scam)
    status, bec_data = get("/api/sample/bec")
    assert status == 200
    assert bec_data["verdict"] == "MALICIOUS"
    case_id = bec_data["case_id"]
    print(f"  [OK] /api/sample/bec -> Verdict: {bec_data['verdict']}, Score: {bec_data['threat_score']}")

    # 4. Get Case Details
    status, case = get(f"/api/cases/{case_id}")
    assert status == 200 and len(case["hops"]) > 0
    print(f"  [OK] /api/cases/{case_id} -> Retained {len(case['hops'])} hops")

    # 5. Export Court Package
    status, export_pkg = get(f"/api/cases/{case_id}/export")
    assert status == 200
    assert "court_evidence_metadata" in export_pkg
    print(f"  [OK] /api/cases/{case_id}/export -> Exhibit ID: {export_pkg['court_evidence_metadata']['evidence_id']}")

    # 6. Test File Upload (Multipart)
    test_eml = (
        b"From: Bank Fraud Alert <security@phishing-fake.net>\r\n"
        b"To: victim@example.org\r\n"
        b"Subject: Action Required Immediately: Reset Password\r\n"
        b"Received: from 194.26.29.110 by mx.example.org; Thu, 03 Sep 2026 12:00:00 +0000\r\n\r\n"
        b"Your account is suspended within 24 hours. Click here to verify your credentials immediately.\r\n"
    )
    status, upload_res = post_multipart("/api/analyze", "phishing_alert.eml", test_eml)
    assert status == 200
    print(f"  [OK] POST /api/analyze -> Verdict: {upload_res['verdict']} (Score: {upload_res['threat_score']})")

    # 7. List Cases
    status, cases = get("/api/cases")
    assert status == 200 and len(cases) >= 2
    print(f"  [OK] /api/cases -> {len(cases)} historical cases archived")

    # 8. Stats & IMAP status
    status, stats = get("/api/stats")
    assert status == 200 and stats["total_analyzed"] >= 2
    print(f"  [OK] /api/stats -> Total: {stats['total_analyzed']}, Malicious: {stats['malicious_count']}")

    status, imap_status = get("/api/imap/status")
    assert status == 200 and imap_status["is_running"] is True
    print(f"  [OK] /api/imap/status -> Worker running: {imap_status['is_running']}")

    print("\nALL HTTP REST ENDPOINTS AND PIPELINES VALIDATED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
