import pytest
from tools.base_tool import BaseTool
from tools.common.runner import ToolRunner, RunnerConfig
from tools.common.result import ToolResult
from typing import Any, List, Optional

class MockRunner:
    def __init__(self, stdout="", stderr="", exit_code=0, timed_out=False):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.last_argv = None

    def run(self, argv, timeout_s=None, cwd=None, env=None):
        self.last_argv = argv
        return ToolResult(
            argv=argv,
            stdout=self.stdout,
            stderr=self.stderr,
            exit_code=self.exit_code,
            timed_out=self.timed_out,
            duration_s=0.1
        )

class SimpleTool(BaseTool):
    @property
    def tool_name(self) -> str:
        return "echo"

    def run(self, message: str) -> str:
        res = self.execute([message])
        return res.stdout.strip()

def test_base_tool_execution():
    runner = MockRunner(stdout="hello world\n")
    tool = SimpleTool(runner=runner)
    
    result = tool.run("hello world")
    
    assert result == "hello world"
    assert runner.last_argv == ["echo", "hello world"]

def test_base_tool_timeout():
    runner = MockRunner(timed_out=True)
    tool = SimpleTool(runner=runner)
    
    # In a real tool, run() might handle the timeout. 
    # For this simple mock, we just check the execute call.
    res = tool.execute(["test"])
    assert res.timed_out is True

def test_nmap_tool_migration():
    from tools.network.nmap import NmapTool
    
    stdout = """
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd
443/tcp  open  https   nginx
"""
    runner = MockRunner(stdout=stdout)
    tool = NmapTool(runner=runner)
    
    scan = tool.run("127.0.0.1")
    
    assert len(scan.ports) == 2
    assert scan.ports[0].port == 80
    assert scan.ports[0].service == "http"
    assert runner.last_argv == ["nmap", "-sV", "--top-ports", "100", "127.0.0.1"]

def test_binwalk_tool_migration():
    from tools.forensics.binwalk import BinwalkTool
    
    stdout = """
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 512 x 512, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, default compression
"""
    runner = MockRunner(stdout=stdout)
    tool = BinwalkTool(runner=runner)
    
    res = tool.run("test.png")
    
    assert len(res.signatures) == 2
    assert res.signatures[0].decimal == 0
    assert res.signatures[0].hexadecimal == "0x0"
    assert "PNG image" in res.signatures[0].description
    assert runner.last_argv == ["binwalk", "test.png"]
