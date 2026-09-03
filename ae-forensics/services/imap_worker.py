"""
AE-Forensics: Background Asynchronous IMAP Inbox Polling Worker
Continuously listens for unread messages, extracts raw RFC-822 byte streams,
and routes them into the local forensic pipeline and SQLite persistence.
"""

import os
import imaplib
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from database import save_case, get_case_by_hash
from core.parser import parse_email_bytes
from core.auth import evaluate_protocol_auth
from core.geo_tracer import trace_hops_and_origin
from core.nlp_engine import analyze_semantic_intent
from core.scorer import compute_threat_score

logger = logging.getLogger("ae_forensics.imap")
logging.basicConfig(level=logging.INFO)


class IMAPWorker:
    def __init__(self):
        self.host = os.environ.get("IMAP_HOST", "")
        self.port = int(os.environ.get("IMAP_PORT", "993"))
        self.user = os.environ.get("IMAP_USER", "")
        self.password = os.environ.get("IMAP_PASSWORD", "")
        self.folder = os.environ.get("IMAP_FOLDER", "INBOX")
        self.poll_interval = int(os.environ.get("IMAP_POLL_INTERVAL", "30"))

        self.running = False
        self.task: Optional[asyncio.Task] = None
        self.is_connected = False
        self.last_poll_time: Optional[str] = None
        self.status_message = "Idle (Unconfigured or Standby)"
        self.total_ingested = 0

    def is_configured(self) -> bool:
        return bool(self.host and self.user and self.password)

    def process_raw_email(self, raw_bytes: bytes, source_info: str = "IMAP Ingestion") -> Dict[str, Any]:
        """
        Execute full analytical pipeline on ingested email bytes and persist to SQLite.
        """
        parsed = parse_email_bytes(raw_bytes, filename="imap_message.eml")

        # Deduplication check by SHA-256
        existing = get_case_by_hash(parsed["sha256"])
        if existing:
            return existing

        origin_ip, enriched_hops, origin_geo = trace_hops_and_origin(parsed["hops"])
        auth_data = evaluate_protocol_auth(
            sender_domain=parsed["sender_domain"],
            origin_ip=origin_ip,
            raw_bytes=raw_bytes,
            raw_headers=parsed["raw_headers"],
            display_name=parsed["display_name"],
            sender_email=parsed["sender_email"]
        )
        nlp_data = analyze_semantic_intent(parsed["plain_body"])
        score_data = compute_threat_score(
            nlp_score=nlp_data["nlp_score"],
            auth_data=auth_data,
            origin_ip=origin_ip,
            hops=enriched_hops
        )

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
            "threat_score": score_data["threat_score"],
            "verdict": score_data["verdict"],
            "spf_status": auth_data["spf_status"],
            "dkim_status": auth_data["dkim_status"],
            "dmarc_status": auth_data["dmarc_status"],
            "nlp_score": nlp_data["nlp_score"],
            "raw_headers": parsed["raw_headers"]
        }

        save_case(case_record, enriched_hops)
        self.total_ingested += 1
        logger.info(f"Ingested IMAP email: {parsed['subject']} | Verdict: {score_data['verdict']}")
        return case_record

    def poll_once(self) -> Dict[str, Any]:
        """
        Synchronously perform a single IMAP poll pass.
        """
        self.last_poll_time = datetime.now(timezone.utc).isoformat()
        if not self.is_configured():
            self.status_message = "IMAP server not configured (Set IMAP_HOST, IMAP_USER, IMAP_PASSWORD in environment)"
            return {"status": "unconfigured", "message": self.status_message, "polled_count": 0}

        try:
            mail = imaplib.IMAP4_SSL(self.host, self.port, timeout=10)
            mail.login(self.user, self.password)
            mail.select(self.folder)
            self.is_connected = True

            status, messages = mail.search(None, "UNSEEN")
            if status != "OK":
                mail.logout()
                self.status_message = "IMAP folder check failed"
                return {"status": "error", "message": self.status_message, "polled_count": 0}

            msg_ids = messages[0].split()
            count = 0

            for msg_id in msg_ids:
                res, data = mail.fetch(msg_id, "(RFC822)")
                if res == "OK" and data and len(data) > 0 and isinstance(data[0], tuple):
                    raw_bytes = data[0][1]
                    self.process_raw_email(raw_bytes, source_info=f"IMAP msg_id {msg_id.decode()}")
                    count += 1

            mail.close()
            mail.logout()
            self.status_message = f"Successfully polled {count} new messages at {self.last_poll_time}"
            return {"status": "ok", "message": self.status_message, "polled_count": count}

        except Exception as ex:
            self.is_connected = False
            self.status_message = f"IMAP connection failed: {type(ex).__name__} ({str(ex)})"
            logger.warning(self.status_message)
            return {"status": "error", "message": self.status_message, "polled_count": 0}

    async def _loop(self):
        """Continuous polling background coroutine."""
        logger.info("Starting AE-Forensics IMAP background poller listener...")
        while self.running:
            try:
                # Run sync IMAP operation in thread to avoid blocking event loop
                await asyncio.to_thread(self.poll_once)
            except Exception as ex:
                self.status_message = f"Worker loop error: {str(ex)}"
                logger.error(self.status_message)

            await asyncio.sleep(self.poll_interval)

    def start(self):
        """Start the background worker."""
        if not self.running:
            self.running = True
            self.task = asyncio.create_task(self._loop())

    def stop(self):
        """Stop the background worker."""
        self.running = False
        if self.task:
            self.task.cancel()

    def get_status(self) -> Dict[str, Any]:
        """Return worker diagnostic state."""
        return {
            "is_configured": self.is_configured(),
            "is_running": self.running,
            "is_connected": self.is_connected,
            "host": self.host or "Not configured",
            "folder": self.folder,
            "poll_interval_seconds": self.poll_interval,
            "last_poll_time": self.last_poll_time,
            "status_message": self.status_message,
            "total_ingested": self.total_ingested
        }


# Global singleton instance
_worker_instance: Optional[IMAPWorker] = None


def get_imap_worker() -> IMAPWorker:
    global _worker_instance
    if _worker_instance is None:
        _worker_instance = IMAPWorker()
    return _worker_instance
