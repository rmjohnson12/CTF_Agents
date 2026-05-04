"""
Wrapper for pwntools for binary exploitation.
"""

from typing import Any, Dict, List, Optional
import subprocess
import os
from tools.base_tool import BaseTool

class PwntoolsWrapper(BaseTool):
    """
    Utility wrapper for common pwntools operations.
    Note: Requires 'pwntools' to be installed in the environment.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("pwntools", "Binary exploitation toolkit", config)

    def run_checksec(self, binary_path: str) -> Dict[str, Any]:
        """Run checksec on a binary to identify mitigations."""
        try:
            # We use the CLI version of checksec if available
            result = subprocess.run(["checksec", "--format=json", "--file=" + binary_path], 
                                   capture_output=True, text=True)
            import json
            return json.loads(result.stdout)
        except Exception as e:
            # Fallback to manual check or simplified output
            return {"error": str(e), "message": "checksec execution failed"}

    def generate_template(self, binary_path: str, remote_info: Optional[str] = None) -> str:
        """Generate a basic pwntools exploit template."""
        template = f"""
from pwn import *

# Context
context.binary = '{binary_path}'

def start():
    if args.REMOTE:
        return remote('{remote_info.split(":")[0] if remote_info else "localhost"}', {remote_info.split(":")[1] if remote_info and ":" in remote_info else 1337})
    else:
        return process('{binary_path}')

io = start()

# Exploit goes here

io.interactive()
"""
        return template.strip()

    def execute(self, script_path: str, timeout_s: int = 30) -> Dict[str, Any]:
        """Execute a pwntools script and return output."""
        try:
            result = subprocess.run(["python3", script_path], 
                                   capture_output=True, text=True, timeout=timeout_s)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {"error": "Execution timed out", "success": False}
        except Exception as e:
            return {"error": str(e), "success": False}
