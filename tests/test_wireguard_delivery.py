from app import access_ops


def test_wireguard_domain_package_contains_direct_ip_profile_and_qr():
    domain=(
        "[Interface]\nPrivateKey = client-private\nAddress = 10.66.66.2/32\n\n"
        "[Peer]\nPublicKey = server-public\nEndpoint = vpn.example.test:443\nAllowedIPs = 0.0.0.0/0\n"
    )
    direct=domain.replace("vpn.example.test","203.0.113.10")
    payload=access_ops.wireguard_payload("phone",domain,"10.66.66.2",direct,"ip")
    assert payload["native_filename"]=="phone.conf"
    assert "phone.conf" in payload["files"]
    assert "phone-qr.svg" in payload["files"]
    assert "phone-ip.conf" in payload["files"]
    assert "phone-ip-qr.svg" in payload["files"]
    assert b"203.0.113.10:443" in payload["files"]["phone-ip.conf"]
    assert payload["summary"]["alternate_profile"] is True


def test_wireguard_ip_package_stays_single_profile():
    config="[Interface]\nPrivateKey = key\n[Peer]\nEndpoint = 203.0.113.10:443\n"
    payload=access_ops.wireguard_payload("phone",config,"10.66.66.2")
    assert "phone.conf" in payload["files"]
    assert "phone-ip.conf" not in payload["files"]
    assert payload["summary"]["alternate_profile"] is False
