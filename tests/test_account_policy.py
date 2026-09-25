import pytest
from app.system_ops import validate_user_password, OperationError

def test_four_digit_pin_allowed():
    validate_user_password("1234")

def test_short_pin_rejected():
    with pytest.raises(OperationError):
        validate_user_password("123")
