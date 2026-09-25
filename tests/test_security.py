from app.security import hash_password, verify_password

def test_password_hash_roundtrip():
    h=hash_password('A-strong-password-123')
    assert h.startswith('scrypt$')
    assert verify_password('A-strong-password-123',h)
    assert not verify_password('wrong-password',h)
