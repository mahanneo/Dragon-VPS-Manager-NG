import pytest
from app.panel_ops import validate_domain, PanelOperationError

def test_valid_domain_normalized():
    assert validate_domain("Panel.Example.COM.") == "panel.example.com"

@pytest.mark.parametrize("value", ["localhost", "bad_domain.com", "http://example.com", ""])
def test_invalid_domain_rejected(value):
    with pytest.raises(PanelOperationError):
        validate_domain(value)
