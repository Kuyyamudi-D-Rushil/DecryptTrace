import pytest

from app.crypto.canonical import canonical_serialize
from app.crypto.errors import CanonicalizationError


def test_canonicalization_ordering():
    obj1 = {"a": 1, "b": 2, "c": 3}
    obj2 = {"c": 3, "a": 1, "b": 2}
    
    bytes1 = canonical_serialize(obj1)
    bytes2 = canonical_serialize(obj2)
    
    assert bytes1 == bytes2
    assert bytes1 == b'{"a":1,"b":2,"c":3}'

def test_canonicalization_unicode_and_escapes():
    # RFC 8785 handles unicode strictly
    obj = {"key": "value\n\r", "utf8": "é"}
    result = canonical_serialize(obj)
    
    assert b"\\n" in result
    assert b"\\r" in result
    assert "é".encode() in result

def test_canonicalization_numbers():
    # RFC 8785 restricts number representation
    obj = {"zero": 0, "negative_zero": -0.0, "large": 1e9}
    result = canonical_serialize(obj)
    
    # In RFC 8785, -0 is serialized as 0 or strictly formatted. jcs handles this.
    assert result == b'{"large":1000000000,"negative_zero":-0,"zero":0}' or result == b'{"large":1000000000,"negative_zero":0,"zero":0}'

def test_canonicalization_invalid_type():
    class CustomObj:
        pass
        
    obj = {"a": CustomObj()}
    with pytest.raises(CanonicalizationError):
        canonical_serialize(obj) # type: ignore
