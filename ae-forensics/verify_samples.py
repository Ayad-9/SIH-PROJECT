import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import SYNTHETIC_SAMPLES, run_full_forensic_pipeline

for key in ["clean", "angry_complaint", "bec", "phishing", "spoof"]:
    res = run_full_forensic_pipeline(SYNTHETIC_SAMPLES[key], filename=f"{key}.eml", db_path="test_forensics_ci.db")
    print(f"SAMPLE {key.upper()}:")
    print(f"  Verdict:        {res['verdict']}")
    print(f"  Threat Score:   {res['threat_score']} / 100")
    print(f"  Auth Status:    SPF={res['spf_status']}, DKIM={res['dkim_status']}, DMARC={res['dmarc_status']}")
    print(f"  Tone Profile:   {res['tone_analysis'].get('tone', 'N/A')}")
    print(f"  Sentiment:      {res['tone_analysis'].get('sentiment', 'N/A')}")
    print(f"  Abusive Terms:  {res['tone_analysis'].get('abusive_matches', [])}")
    print(f"  NLP Risk:       {res['nlp_score']}%")
    print(f"  Proxy Status:   {res['proxy_analysis'].get('classification')} (Confidence: {res['proxy_analysis'].get('confidence')})")
    print(f"  Disambiguation: {res['nlp_intent'].get('disambiguation_note', 'N/A')}")
    print(f"  Origin IP:      {res['origin_ip']} ({res['origin_geo']['city']}, {res['origin_geo']['country']})")
    print(f"  Hops Count:     {len(res['hops'])}")
    print(f"  Breakdown:      {res['score_breakdown']}\n")
