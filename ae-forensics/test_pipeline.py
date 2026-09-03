"""
AE-Forensics: Verification and Pipeline Test Suite
Tests all modules: parser, auth, geo_tracer, nlp_engine, scorer, database, and samples.
"""

import os
import sys
import unittest

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, save_case, get_cases, get_case_by_id, get_stats
from core.parser import parse_email_bytes
from core.auth import evaluate_protocol_auth, detect_display_name_spoofing
from core.geo_tracer import trace_hops_and_origin, is_private_or_reserved_ip
from core.nlp_engine import analyze_semantic_intent
from core.scorer import compute_threat_score
from main import SYNTHETIC_SAMPLES, run_full_forensic_pipeline


class TestAEForensics(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        for ext in ["", "-shm", "-wal"]:
            f = f"test_forensics_ci.db{ext}"
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
        os.environ["AE_DB_PATH"] = "test_forensics_ci.db"
        init_db("test_forensics_ci.db")

    @classmethod
    def tearDownClass(cls):
        for ext in ["", "-shm", "-wal"]:
            f = f"test_forensics_ci.db{ext}"
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def test_01_private_ip_filter(self):
        self.assertTrue(is_private_or_reserved_ip("127.0.0.1"))
        self.assertTrue(is_private_or_reserved_ip("10.0.5.2"))
        self.assertTrue(is_private_or_reserved_ip("192.168.1.1"))
        self.assertTrue(is_private_or_reserved_ip("172.16.0.10"))
        self.assertTrue(is_private_or_reserved_ip("0.0.0.0"))
        self.assertFalse(is_private_or_reserved_ip("209.85.220.41"))
        self.assertFalse(is_private_or_reserved_ip("45.154.255.88"))

    def test_02_parser_clean_email(self):
        sample_bytes = SYNTHETIC_SAMPLES["clean"]
        parsed = parse_email_bytes(sample_bytes, filename="clean.eml")
        self.assertEqual(len(parsed["sha256"]), 64)
        self.assertIn("GitHub", parsed["subject"])
        self.assertEqual(len(parsed["hops"]), 2)
        self.assertEqual(parsed["sender_domain"], "github.com")

    def test_03_geo_tracer_origin(self):
        sample_bytes = SYNTHETIC_SAMPLES["clean"]
        parsed = parse_email_bytes(sample_bytes)
        origin_ip, hops, origin_geo = trace_hops_and_origin(parsed["hops"])
        # In chronological order, hop 1 is 10.0.1.5 (private), hop 2 is 209.85.220.41 (public)
        self.assertEqual(origin_ip, "209.85.220.41")
        self.assertNotEqual(origin_geo["latitude"], 0.0)
        self.assertNotEqual(origin_geo["longitude"], 0.0)

    def test_04_nlp_engine_bec(self):
        bec_text = "Urgent: Please wire transfer the updated bank account details. Swift code and routing number attached."
        nlp_res = analyze_semantic_intent(bec_text)
        self.assertGreaterEqual(nlp_res["nlp_score"], 40.0)
        self.assertTrue(any("wire transfer" in m for m in nlp_res["highlighted_terms"]))

    def test_05_display_spoofing(self):
        res1 = detect_display_name_spoofing("CEO Vikram Malhotra", "vikram@gmail.com", "gmail.com")
        self.assertTrue(res1["is_spoofed"])
        self.assertEqual(res1["penalty"], 15.0)

        res2 = detect_display_name_spoofing("Normal User", "user@company.com", "company.com")
        self.assertFalse(res2["is_spoofed"])

    def test_06_scorer_bounds(self):
        auth_pass = {"spf_status": "PASS", "dkim_status": "PASS", "dmarc_status": "PASS", "spoof_penalty": 0.0}
        clean_score = compute_threat_score(0.0, auth_pass, "209.85.220.41", [{"latency_seconds": 1}])
        self.assertEqual(clean_score["verdict"], "CLEAN")
        self.assertLess(clean_score["threat_score"], 40.0)

        auth_fail = {"spf_status": "FAIL", "dkim_status": "FAIL", "dmarc_status": "FAIL", "spoof_penalty": 15.0}
        mal_score = compute_threat_score(90.0, auth_fail, "45.154.255.88", [{"org": "bulletproof"}])
        self.assertEqual(mal_score["verdict"], "MALICIOUS")
        self.assertGreaterEqual(mal_score["threat_score"], 70.0)

    def test_07_full_pipeline_end_to_end(self):
        for sample_key in ["clean", "bec", "phishing", "spoof"]:
            raw_bytes = SYNTHETIC_SAMPLES[sample_key]
            result = run_full_forensic_pipeline(raw_bytes, filename=f"sample_{sample_key}.eml", db_path="test_forensics_ci.db")
            self.assertIn("case_id", result)
            self.assertIn("sha256", result)
            self.assertIn("verdict", result)
            self.assertIn(result["verdict"], ["CLEAN", "SUSPICIOUS", "MALICIOUS"])
            self.assertTrue(len(result["hops"]) > 0)

        cases = get_cases(limit=10, db_path="test_forensics_ci.db")
        self.assertEqual(len(cases), 4)

        stats = get_stats("test_forensics_ci.db")
        self.assertEqual(stats["total_analyzed"], 4)


if __name__ == "__main__":
    unittest.main()
