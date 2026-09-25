import pytest
from app.protocol_ops import _build_xray_stream, ProtocolError

def test_websocket_stream_uses_current_method_schema():
    stream, meta = _build_xray_stream("/bin/true","vless","ws","none","/socket","","")
    assert stream["method"] == "websocket"
    assert stream["wsSettings"]["path"] == "/socket"
    assert stream["security"] == "none"
    assert meta == {}

def test_grpc_stream_service_name():
    stream, _ = _build_xray_stream("/bin/true","vless","grpc","none","makia-grpc","","")
    assert stream["method"] == "grpc"
    assert stream["grpcSettings"]["serviceName"] == "makia-grpc"

def test_reality_rejects_incompatible_protocol():
    with pytest.raises(ProtocolError):
        _build_xray_stream("/bin/true","trojan","tcp","reality","/","example.com","example.com:443")

def test_reality_rejects_incompatible_transport():
    with pytest.raises(ProtocolError):
        _build_xray_stream("/bin/true","vless","ws","reality","/","example.com","example.com:443")
