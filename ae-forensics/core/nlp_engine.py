"""
AE-Forensics: CPU-Optimized Local Semantic Intent & Threat Engine
Evaluates email text bodies for urgency cues, invoice/wire diversion patterns (BEC),
credential theft vectors, executive impersonation, and comprehensive Tone & Sentiment Analysis.
Features False-Positive Disambiguation: Abusive/frustrated language without cyber fraud vectors
is classified as a non-threat workplace dispute (NOT a cyber attack).
"""

import re
from typing import Dict, Any, List


# Rule-based heuristic pattern dictionary optimized for CPU inference
THREAT_CATEGORIES = {
    "urgency_coercion": {
        "weight": 25.0,
        "patterns": [
            r"\bimmediate(?:ly)?\s+action\s+required\b",
            r"\bimmediate(?:ly)?\b",
            r"\baccount\s+(?:is\s+|has\s+been\s+|will\s+be\s+)?(?:suspended|terminated|locked|restricted|compromised|deactivated|closed|on\s+hold)\b",
            r"\bwithin\s+(?:24|12|48)\s+hours\b",
            r"\bfinal\s+warning\b",
            r"\burgent(?:ly)?\b",
            r"\bact\s+(?:now|immediately)\b",
            r"\btime[\s-]sensitive\b",
            r"\bsecurity\s+(?:alert|notice|warning|incident|update)\b",
            r"\bunauthorized\s+(?:access|login|activity|sign[\s-]in)\b",
            r"\bunusual\s+(?:activity|login|sign[\s-]in)\b",
            r"\bsuspicious\s+(?:activity|login|sign[\s-]in)\b",
            r"\bcompliance\s+mandatory\b",
            r"\baction\s+(?:required|needed)\b",
            r"\bprompt\s+response\b",
            r"\basap\b",
            r"\bdo\s+not\s+delay\b"
        ]
    },
    "payment_diversion_bec": {
        "weight": 35.0,
        "patterns": [
            r"\bwire\s+transfer\b",
            r"\bupdated?\s+bank\s+(?:account|details|info)\b",
            r"\bnew\s+bank\s+(?:account|details|coordinates)\b",
            r"\brouting\s+number\b",
            r"\bswift\s+(?:code|bic)\b",
            r"\biban\b",
            r"\bremittance\s+(?:advice|details)\b",
            r"\binvoice\s+(?:attached|overdue|payment|due)\b",
            r"\bpayment\s+(?:overdue|instructions|pending|diversion)\b",
            r"\btransfer\s+funds\b",
            r"\bchange\s+of\s+(?:banking|account|payment)\b",
            r"\bbeneficiary\s+details\b",
            r"\bvendor\s+payment\b",
            r"\bsettlement\s+statement\b",
            r"\battach(?:ed)?\s+receipt\b",
            r"\bprocess\s+(?:this\s+)?(?:payment|wire|invoice|transaction)\b",
            r"\bnew\s+(?:account|payment|wire)\s+instructions\b"
        ]
    },
    "credential_harvesting": {
        "weight": 30.0,
        "patterns": [
            r"\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|password|identity|credentials|profile|security\s+info)\b",
            r"\b(?:reset|recover|change|unlock)\s+(?:your\s+)?(?:password|account|access|credentials)\b",
            r"\bupdate\s+(?:your\s+)?(?:login|billing|profile|credentials)\b",
            r"\bsign[\s-]in\s+to\s+(?:confirm|verify|unlock|review|restore)\b",
            r"\blogin\s+to\s+(?:confirm|verify|review|unlock|restore)\b",
            r"\bclick\s+(?:here|the\s+link|on\s+this\s+link|below|to\s+verify|to\s+login|to\s+proceed)\b",
            r"\bunlock\s+(?:your\s+)?account\b",
            r"\bconfirm\s+(?:your\s+)?identity\b",
            r"\bvalidate\s+(?:your\s+)?credentials\b",
            r"\bmfa\s+(?:reset|bypass|prompt|code)\b",
            r"\bexpire(?:s|d)?\s+(?:today|soon|in\s+\d+\s+hours?)\b",
            r"\bre[\s-]authenticate\b",
            r"https?://[^\s<>'\"\)\]]+(?:login|signin|verify|account|auth|reset|passwd|password|portal|update|secure)[^\s<>'\"\)\]]*"
        ]
    },
    "executive_impersonation": {
        "weight": 15.0,
        "patterns": [
            r"\bare\s+you\s+(?:at\s+your\s+desk|available|in\s+the\s+office|free\s+right\s+now)\b",
            r"\bneed\s+a\s+quick\s+favor\b",
            r"\bi\s+(?:am|need\s+you)\s+(?:in\s+a\s+meeting|traveling|busy|offsite)\b",
            r"\bdo\s+not\s+call\s+(?:my\s+phone|me)\b",
            r"\bstrictly\s+confidential\b",
            r"\bdiscreet\s+matter\b",
            r"\bhandle\s+this\s+personally\b",
            r"\bgift\s+cards?\b",
            r"\bapple\s+gift\s+card\b",
            r"\bsteam\s+card\b",
            r"\bw[-]?2\s+tax\s+forms\b",
            r"\bwire\s+instructions\s+from\s+ceo\b",
            r"\bsent\s+from\s+my\s+iphone\b"
        ]
    }
}

# Emotion, Tone & Sentiment Dictionary
ABUSIVE_FRUSTRATED_PATTERNS = [
    r"\b(?:damn|hell|crap|bullshit|screw\s+this)\b",
    r"\b(?:idiots?|morons?|incompetent|stupid|pathetic)\b",
    r"\b(?:terrible|worst|horrible|useless|disaster|garbage)\b",
    r"\b(?:ridiculous|unacceptable|furious|pissed\s+off|outrageous)\b",
    r"\bwhat\s+the\s+hell\b",
    r"\bfix\s+this\s+(?:crap|damn\s+issue|mess)\b",
    r"\byou\s+(?:people\s+are\s+useless|are\s+incompetent)\b"
]

PROFESSIONAL_PATTERNS = [
    r"\b(?:sincerely|best\s+regards|kind\s+regards|warm\s+regards)\b",
    r"\b(?:thank\s+you|appreciate\s+your\s+time|please\s+let\s+me\s+know)\b",
    r"\b(?:pleasure\s+working\s+with\s+you|glad\s+to\s+assist)\b"
]


def analyze_tone_and_sentiment(text_lower: str) -> Dict[str, Any]:
    """
    Evaluates emotional tone, sentiment polarity, and presence of abusive/frustrated language.
    """
    abusive_matches = []
    for pat in ABUSIVE_FRUSTRATED_PATTERNS:
        matches = re.findall(pat, text_lower)
        if matches:
            abusive_matches.extend(matches)

    prof_matches = []
    for pat in PROFESSIONAL_PATTERNS:
        matches = re.findall(pat, text_lower)
        if matches:
            prof_matches.extend(matches)

    has_abuse = len(abusive_matches) > 0
    has_prof = len(prof_matches) > 0

    if has_abuse:
        tone = "Frustrated / Hostile (Aggressive Complaint)"
        sentiment = "Negative / Agitated"
        tone_badge_color = "amber"
    elif has_prof:
        tone = "Professional / Courteous"
        sentiment = "Positive / Formal"
        tone_badge_color = "emerald"
    else:
        tone = "Neutral / Informational"
        sentiment = "Neutral"
        tone_badge_color = "blue"

    return {
        "tone": tone,
        "sentiment": sentiment,
        "has_abusive_language": has_abuse,
        "abusive_matches": list(set(abusive_matches)),
        "tone_badge_color": tone_badge_color
    }


def analyze_semantic_intent(text_body: str) -> Dict[str, Any]:
    """
    Perform local NLP intent classification across the 4 primary email threat vectors
    and context-aware tone analysis with False-Positive Disambiguation.
    """
    if not text_body or not text_body.strip():
        return {
            "nlp_score": 0.0,
            "category_scores": {cat: 0.0 for cat in THREAT_CATEGORIES},
            "triggers": [],
            "highlighted_terms": [],
            "risk_summary": "Clean: No Textual Threat Indicators",
            "tone_analysis": {
                "tone": "Neutral",
                "sentiment": "Neutral",
                "has_abusive_language": False,
                "abusive_matches": [],
                "tone_badge_color": "blue"
            },
            "disambiguation_note": "No text content detected."
        }

    normalized_text = " ".join(text_body.lower().split())

    # 1. Evaluate Tone & Sentiment
    tone_data = analyze_tone_and_sentiment(normalized_text)

    # 2. Evaluate Threat Categories
    category_matches: Dict[str, List[str]] = {}
    category_scores: Dict[str, float] = {}
    all_matched_terms: List[str] = []
    total_score = 0.0

    for cat_name, cat_meta in THREAT_CATEGORIES.items():
        weight = cat_meta["weight"]
        patterns = cat_meta["patterns"]
        matched_in_cat = []

        for pattern in patterns:
            found = re.findall(pattern, normalized_text)
            if found:
                for term in found:
                    term_str = term if isinstance(term, str) else term[0]
                    matched_in_cat.append(term_str)
                    if term_str not in all_matched_terms:
                        all_matched_terms.append(term_str)

        category_matches[cat_name] = matched_in_cat
        count = len(matched_in_cat)

        if count == 0:
            cat_score = 0.0
        elif count == 1:
            cat_score = weight * 0.6
        elif count == 2:
            cat_score = weight * 0.85
        else:
            cat_score = weight * 1.0

        category_scores[cat_name] = round(cat_score, 2)
        total_score += cat_score

    # Keyword density & multi-vector reinforcement bonus
    active_categories = sum(1 for hits in category_matches.values() if hits)
    if active_categories >= 3:
        total_score += 15.0
    elif active_categories >= 2:
        total_score += 8.0

    raw_threat_score = min(100.0, round(total_score, 2))

    # 3. CRITICAL FALSE-POSITIVE DISAMBIGUATION RULE:
    # If the text contains angry/abusive language BUT NO cyber fraud vectors
    # (no wire transfer, no credential harvesting, no executive spoofing):
    # It must NOT be flagged as a cyber threat!
    has_hard_fraud = bool(
        category_matches.get("payment_diversion_bec") or
        category_matches.get("credential_harvesting") or
        category_matches.get("executive_impersonation")
    )

    is_workplace_dispute = tone_data["has_abusive_language"] and not has_hard_fraud

    if is_workplace_dispute:
        # Zero out threat score: emotional outburst, not a cyber attack!
        normalized_score = 0.0
        summary = "Emotional Workplace Complaint (Non-Cyber Threat)"
        disambiguation_note = (
            "Abusive / Angry language detected, but ZERO cyber fraud, wire diversion, or credential harvesting vectors found. "
            "Engine has safely classified this as a legitimate workplace dispute (NOT a cyber threat)."
        )
    elif raw_threat_score >= 70.0:
        normalized_score = raw_threat_score
        summary = "High Risk: Aggressive Social Engineering / Fraud Intent Identified"
        disambiguation_note = "High-confidence deceptive intent: wire transfer, credential prompts, or executive pressure detected."
    elif raw_threat_score >= 40.0:
        normalized_score = raw_threat_score
        summary = "Moderate Risk: Suspicious Urgency or Financial Divergence Language"
        disambiguation_note = "Moderate threat indicators detected; manual SOC verification recommended."
    elif raw_threat_score > 0.0:
        normalized_score = raw_threat_score
        summary = "Low Risk: Minor Coercion or Common Business Keywords Observed"
        disambiguation_note = "Minor urgency cues observed without malicious payload."
    else:
        normalized_score = 0.0
        summary = "Clean: No Semantic Risk Vectors Detected"
        disambiguation_note = "Text is benign with standard business communication intent."

    # Format trigger details for UI display
    triggers_list = []
    for cat_name, hits in category_matches.items():
        if hits:
            triggers_list.append({
                "category": cat_name.replace("_", " ").title(),
                "score": category_scores[cat_name],
                "matches": list(set(hits))
            })

    return {
        "nlp_score": normalized_score,
        "category_scores": category_scores,
        "triggers": triggers_list,
        "highlighted_terms": all_matched_terms,
        "risk_summary": summary,
        "tone_analysis": tone_data,
        "is_workplace_dispute": is_workplace_dispute,
        "disambiguation_note": disambiguation_note
    }
