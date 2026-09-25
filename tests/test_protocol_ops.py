import pytest
from app.protocol_ops import _validate_port, ProtocolError

def test_valid_port():
    assert _validate_port(443) == 443

@pytest.mark.parametrize("value", [0, 65536, -1])
def test_invalid_port(value):
    with pytest.raises(ProtocolError):
        _validate_port(value)
