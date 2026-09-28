from pydantic import BaseModel

from app.crypto.canonical import canonical_serialize


def canonicalize_for_signing(model: BaseModel) -> bytes:
    """
    Dumps the Pydantic model to a dict, removes any signature fields,
    and serializes it strictly using RFC 8785 JCS.
    """
    d = model.model_dump(mode="json")
    d.pop("signature_hex", None)
    d.pop("auth_signature_hex", None)
    return canonical_serialize(d)

def canonicalize_artifact(model: BaseModel) -> bytes:
    """
    Dumps the artifact envelope to a dict, removes artifact_hash_hex,
    and serializes it strictly using RFC 8785 JCS.
    """
    d = model.model_dump(mode="json")
    d.pop("artifact_hash_hex", None)
    return canonical_serialize(d)
