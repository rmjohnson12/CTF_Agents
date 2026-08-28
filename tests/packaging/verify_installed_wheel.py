"""Smoke-test the installed wheel without importing from the source checkout."""

from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
import tempfile
from importlib import metadata, resources
from pathlib import Path


EXPECTED_COMMANDS = {
    "ctf-agents": ["--help"],
    "ctf-agents-run": ["--help"],
    "ctf-agents-campaign": ["--help"],
    "ctf-agents-check": ["--no-ping"],
    "ctf-agents-report": ["--help"],
}


def main() -> int:
    distribution = metadata.distribution("ctf-agents")
    commands = {
        entry.name: entry
        for entry in distribution.entry_points
        if entry.group == "console_scripts"
    }
    assert commands.keys() == EXPECTED_COMMANDS.keys(), (
        f"wheel console commands differ: {sorted(commands)}"
    )

    script = resources.files("tools.pwn").joinpath("DumpAnalysis.java")
    assert script.is_file(), "DumpAnalysis.java is missing from the installed wheel"
    assert "class DumpAnalysis" in script.read_text(encoding="utf-8")

    scripts_dir = Path(sysconfig.get_path("scripts"))
    env = os.environ.copy()
    env["LLM_PROVIDER"] = "none"
    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "NVAPI_KEY",
        "NVAPI_KEYS",
        "NGC_API_KEY",
    ):
        env.pop(key, None)

    with tempfile.TemporaryDirectory(prefix="ctf_agents_wheel_smoke_") as work_dir:
        for command, args in EXPECTED_COMMANDS.items():
            executable = scripts_dir / command
            assert executable.is_file(), f"installed console script is missing: {executable}"
            completed = subprocess.run(
                [str(executable), *args],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            assert completed.returncode == 0, (
                f"{command} {' '.join(args)} failed with {completed.returncode}\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )

    print("Installed wheel resource and all five console commands verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
