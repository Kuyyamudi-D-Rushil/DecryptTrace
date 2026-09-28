import logging
import json
from datetime import datetime

class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger("decrypttrace.audit")
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_event(self, event_type: str, actor_id: str, target_id: str, details: dict):
        """
        Structured JSON audit logging.
        Automatically redacts any sensitive keys found in 'details'.
        """
        redacted_details = self._redact(details)
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "actor_id": actor_id,
            "target_id": target_id,
            "details": redacted_details
        }
        self.logger.info(json.dumps(log_entry))

    def _redact(self, data: dict) -> dict:
        redacted = {}
        sensitive_keys = {"secret", "password", "private_key", "share_a", "share_b", "token"}
        for k, v in data.items():
            if any(s in k.lower() for s in sensitive_keys):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = v
        return redacted

audit_logger = AuditLogger()
