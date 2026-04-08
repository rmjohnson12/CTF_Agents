from tools.network.nmap import NmapTool


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
