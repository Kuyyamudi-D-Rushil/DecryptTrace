import logging
from typing import ClassVar


class SensitiveDataRedactor(logging.Filter):
    SENSITIVE_KEYS: ClassVar[frozenset[str]] = frozenset({
        "dek", "share_a", "share_b", "k_wm", "private_key", "plaintext"
    })
    
    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, "msg") and isinstance(record.msg, str):
            msg = record.msg.lower()
            for key in self.SENSITIVE_KEYS:
                if key in msg:
                    record.msg = "[REDACTED SENSITIVE FIELD]"
        return True

def setup_logging(level: str = "INFO"):
    logger = logging.getLogger("decrypttrace")
    logger.setLevel(level)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}')
    handler.setFormatter(formatter)
    handler.addFilter(SensitiveDataRedactor())
    
    if not logger.handlers:
        logger.addHandler(handler)
        
    return logger
