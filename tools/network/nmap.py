from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from tools.common.runner import ToolRunner
from tools.common.result import ToolResult


@dataclass(frozen=True)
class NmapPort:
    port: int
    proto: str
    state: str
    service: str


@dataclass(frozen=True)
class NmapScan:
    target: str
    ports: List[NmapPort]
    raw: ToolResult


class NmapTool:
    """
    Thin wrapper around nmap. MVP goal:
    - run a basic scan
    - parse 'PORT STATE SERVICE' lines into structured ports
    """

    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    def scan_top(self, target: str, *, timeout_s: int = 120) -> NmapScan:
        res = self.runner.run(
            ["nmap", "-sV", "--top-ports", "100", target],
            timeout_s=timeout_s,
        )
        ports = self._parse_ports(res.stdout)
        return NmapScan(target=target, ports=ports, raw=res)

    @staticmethod
    def _parse_ports(text: str) -> List[NmapPort]:
        out: List[NmapPort] = []
        for line in text.splitlines():
            m = re.match(r"^(\d+)\/(\w+)\s+(\w+)\s+(\S+)", line.strip())
            if not m:
                continue
            out.append(
                NmapPort(
                    port=int(m.group(1)),
                    proto=m.group(2),
                    state=m.group(3),
                    service=m.group(4),
                )
            )
        return out
