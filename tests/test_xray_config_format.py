from pathlib import Path

from app import protocol_ops


def test_xray_temp_path_always_ends_in_json(tmp_path):
    base=tmp_path/"config.json"
    candidate=protocol_ops._xray_temp_json_path(base,"create")
    assert candidate.parent == base.parent
    assert candidate.name.endswith(".json")
    assert ".makia-create-" in candidate.name


def test_xray_temp_paths_are_unique(tmp_path):
    base=tmp_path/"config.json"
    one=protocol_ops._xray_temp_json_path(base,"validate")
    two=protocol_ops._xray_temp_json_path(base,"validate")
    assert one != two


def test_xray_test_config_forces_json_format(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(protocol_ops,"_run",lambda args,**kwargs:calls.append((args,kwargs)) or "")
    cfg=tmp_path/"config.any-extension"
    protocol_ops._xray_test_config("/usr/local/bin/xray",cfg)
    args,kwargs=calls[0]
    assert args == ["/usr/local/bin/xray","run","-test","-format=json","-config",str(cfg)]
    assert kwargs["timeout"] == 30
