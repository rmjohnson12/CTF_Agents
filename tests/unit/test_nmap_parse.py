from tools.network.nmap import NmapTool
from core.utils.security import SecurityPolicyError


def test_parse_ports():
    sample = """\
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd
443/tcp  open  https   nginx
"""
    ports = NmapTool._parse_ports(sample)
    assert len(ports) == 2
    assert ports[0].port == 80
    assert ports[0].service == "http"


def test_nmap_blocks_non_allowlisted_target(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOWED_NETWORKS", "localhost")

    try:
        NmapTool().scan_top("203.0.113.10", timeout_s=1)
        assert False, "expected SecurityPolicyError"
    except SecurityPolicyError:
        assert True
