import pytest
from app.protocol_ops import _validate_port, _validate_endpoint_host, _uri_host, _endpoint_is_private, create_xray_inbound, ProtocolError

def test_valid_port():
    assert _validate_port(443) == 443

@pytest.mark.parametrize("value", [0, 65536, -1])
def test_invalid_port(value):
    with pytest.raises(ProtocolError):
        _validate_port(value)


@pytest.mark.parametrize("value,expected", [
    ("178.83.45.215","178.83.45.215"),
    (" example.com ","example.com"),
    ("VPN.Example.COM","vpn.example.com"),
    ("[2001:db8::1]","2001:db8::1"),
])
def test_valid_endpoint_host(value, expected):
    assert _validate_endpoint_host(value) == expected

@pytest.mark.parametrize("value", [
    "",
    "https://example.com",
    "example.com:443",
    "example.com/path",
    "bad host",
    "-bad.example.com",
    "bad_.example.com",
])
def test_invalid_endpoint_host(value):
    with pytest.raises(ProtocolError):
        _validate_endpoint_host(value)

def test_ipv6_uri_host_is_bracketed():
    assert _uri_host("2001:db8::1") == "[2001:db8::1]"

def test_ipv4_uri_host_is_not_bracketed():
    assert _uri_host("178.83.45.215") == "178.83.45.215"


def test_public_ipv4_is_not_private():
    assert _endpoint_is_private("178.83.45.215") is False

def test_private_ipv4_is_private():
    assert _endpoint_is_private("10.10.0.2") is True

def test_public_vless_none_is_rejected_before_core_mutation():
    with pytest.raises(ProtocolError, match="choose REALITY or TLS"):
        create_xray_inbound("vless",2087,"mahan","178.83.45.215","xhttp","none","/makia","","")
