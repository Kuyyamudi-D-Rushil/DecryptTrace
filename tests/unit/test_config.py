import pytest
from pydantic import ValidationError

from app.config.settings import Config


def test_valid_config():
    cfg = Config()
    assert cfg.kem_algorithm == "ML-KEM"
    assert cfg.kem_parameter == "ML-KEM-768"

def test_invalid_kem_parameter():
    with pytest.raises(ValidationError):
        Config(kem_parameter="INVALID-KEM")

def test_invalid_kem_algorithm():
    with pytest.raises(ValueError):
        Config(kem_algorithm="RSA")
