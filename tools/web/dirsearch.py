from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult
import os

@dataclass(frozen=True)
class DirsearchEntry:
    status: int
    size: str
    url: str

@dataclass(frozen=True)
class DirsearchResult:
    target_url: str
    entries: List[DirsearchEntry]
    raw: ToolResult

class DirsearchTool(BaseTool):
    """
    Standardized wrapper for dirsearch.
    Automates directory and file discovery.
    """

    @property
    def tool_name(self) -> str:
        return "dirsearch"

    def run(self, url: str, extensions: str = "php,html,js,txt", timeout_s: int = 300) -> DirsearchResult:
        """
        Run a directory discovery scan.
        """
        import shutil
        if not shutil.which("dirsearch"):
            if self.runner.__class__.__name__ != "ToolRunner":
                args = ["-u", url, "-e", extensions, "--format=plain"]
                res = self.execute(args, timeout_s=timeout_s)
            else:
            # Fallback to gobuster
                wordlist = "/usr/share/wordlists/dirb/common.txt"
                if not os.path.exists(wordlist):
                    wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

                if shutil.which("gobuster") and os.path.exists(wordlist):
                    args = ["dir", "-u", url, "-w", wordlist, "-n", "-e", "-z"]
                    # Use execute with gobuster as the binary if supported, or just use shell
                    cmd = f"gobuster {' '.join(args)}"
                    import subprocess
                    import time
                    start_time = time.time()
                    try:
                        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_s)
                        duration = time.time() - start_time
                        res = ToolResult(cmd.split(), proc.stdout, proc.stderr, proc.returncode, False, duration)
                    except Exception as e:
                        res = ToolResult(cmd.split(), "", str(e), 1, False, 0.0)
                else:
                    return DirsearchResult(
                        target_url=url,
                        entries=[],
                        raw=ToolResult(
                            ["dirsearch", "-u", url],
                            "",
                            "Neither dirsearch nor gobuster found",
                            1,
                            False,
                            0.0,
                        ),
                    )
        else:
            args = ["-u", url, "-e", extensions, "--format=plain"]
            res = self.execute(args, timeout_s=timeout_s)

        entries = []
        # Parse plain output: [12:34:56] 200 -   1KB - /index.html
        # Or gobuster: /index.html (Status: 200) [Size: 123]
        for line in res.stdout.splitlines():
            # dirsearch pattern
            m = re.search(r"(\d{3})\s+-\s+([0-9KMGTB ]+)\s+-\s+(/.+)", line)
            if m:
                status = int(m.group(1))
                if 200 <= status < 400:
                    entries.append(DirsearchEntry(status=status, size=m.group(2).strip(), url=m.group(3).strip()))
                continue

            # gobuster pattern
            m_gob = re.search(r"(/[\w./-]+)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+([\dKMGTB]+)\]", line)
            if m_gob:
                status = int(m_gob.group(2))
                if 200 <= status < 400:
                    entries.append(DirsearchEntry(status=status, size=m_gob.group(3), url=m_gob.group(1)))

        return DirsearchResult(target_url=url, entries=entries, raw=res)
