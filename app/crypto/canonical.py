from typing import Any

import jcs  # type: ignore

from .errors import CanonicalizationError


def canonical_serialize(obj: dict[str, Any]) -> bytes:
    """
    Serializes a Python dictionary to a strict RFC 8785 JSON Canonicalization Scheme (JCS) representation.
    Produces deterministic UTF-8 bytes output regardless of input dictionary ordering.
    """
    try:
        # jcs.canonicalize requires the object to be JSON serializable, and it outputs bytes.
        return jcs.canonicalize(obj)
    except Exception as e:
        raise CanonicalizationError("Failed to serialize object canonically.") from e
