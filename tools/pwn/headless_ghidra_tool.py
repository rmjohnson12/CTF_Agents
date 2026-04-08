"""Headless Ghidra integration tool.

MVP wrapper that:
- validates GHIDRA_HOME
- invokes analyzeHeadless with the DumpAnalysis postScript
- parses the four artifact files (strings, imports, exports, functions)
  into structured dataclasses
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from tools.common.runner import ToolRunner
from tools.common.result import ToolResult

# Path to the companion Ghidra postScript (relative to repo root)
_SCRIPT_DIR = Path(__file__).resolve().parents[2] / "shared" / "scripts"
_POST_SCRIPT = _SCRIPT_DIR / "DumpAnalysis.java"


@dataclass(frozen=True)
class GhidraString:
    address: str
    value: str


@dataclass(frozen=True)
class GhidraExport:
    address: str
    name: str


@dataclass(frozen=True)
class GhidraFunction:
    address: str
    name: str


@dataclass(frozen=True)
class GhidraAnalysis:
    """Structured results from a headless Ghidra run."""
    binary_path: str
    strings: List[GhidraString]
    imports: List[str]
    exports: List[GhidraExport]
    functions: List[GhidraFunction]
    raw: ToolResult


class HeadlessGhidraTool:
    """
    Thin wrapper around Ghidra's analyzeHeadless CLI.

    Requires the GHIDRA_HOME environment variable to point at a valid
    Ghidra installation directory (the one containing ``support/analyzeHeadless``).
    """

    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    @staticmethod
    def find_analyze_headless() -> str:
        """Locate the analyzeHeadless script using GHIDRA_HOME."""
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if not ghidra_home:
            raise EnvironmentError(
                "GHIDRA_HOME is not set. "
                "Set it to your Ghidra installation directory."
            )

        ghidra_path = Path(ghidra_home)
        if not ghidra_path.is_dir():
            raise EnvironmentError(
                f"GHIDRA_HOME does not exist or is not a directory: {ghidra_home}"
            )

        # analyzeHeadless lives under support/
        candidate = ghidra_path / "support" / "analyzeHeadless"
        if not candidate.exists():
            raise FileNotFoundError(
                f"analyzeHeadless not found at {candidate}. "
                "Check your GHIDRA_HOME setting."
            )

        return str(candidate)

    def analyze(
        self,
        binary_path: str,
        *,
        timeout_s: int = 600,
        project_dir: Optional[str] = None,
        project_name: str = "ctf_tmp",
    ) -> GhidraAnalysis:
        """
        Run Ghidra headless analysis on a binary and return structured results.

        Args:
            binary_path: Path to the binary to analyze.
            timeout_s: Maximum seconds for the analysis run.
            project_dir: Directory for the temporary Ghidra project.
                         Defaults to a new temp directory.
            project_name: Ghidra project name (arbitrary).

        Returns:
            GhidraAnalysis with parsed strings, imports, exports, and functions.
        """
        analyze_headless = self.find_analyze_headless()

        binary = Path(binary_path)
        if not binary.is_file():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Use a temp directory for artifacts and the Ghidra project
        work_dir = project_dir or tempfile.mkdtemp(prefix="ghidra_")
        work = Path(work_dir)
        work.mkdir(parents=True, exist_ok=True)

        strings_path = str(work / "strings.tsv")
        imports_path = str(work / "imports.tsv")
        exports_path = str(work / "exports.tsv")
        functions_path = str(work / "functions.tsv")

        argv = [
            analyze_headless,
            str(work),          # project location
            project_name,       # project name
            "-import", str(binary),
            "-postScript", str(_POST_SCRIPT),
            strings_path,
            imports_path,
            exports_path,
            functions_path,
            "-deleteProject",   # clean up the .gpr after run
        ]

        res = self.runner.run(argv, timeout_s=timeout_s, cwd=str(work))

        # Parse the four artifact files
        strings = self._parse_strings(strings_path)
        imports = self._parse_imports(imports_path)
        exports = self._parse_exports(exports_path)
        functions = self._parse_functions(functions_path)

        return GhidraAnalysis(
            binary_path=str(binary),
            strings=strings,
            imports=imports,
            exports=exports,
            functions=functions,
            raw=res,
        )

    # ------------------------------------------------------------------
    # Parsers for the TSV artifact files produced by DumpAnalysis.java
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_strings(path: str) -> List[GhidraString]:
        """Parse address<TAB>value lines."""
        results: List[GhidraString] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n\r")
                    if not line:
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        results.append(GhidraString(address=parts[0], value=parts[1]))
        except FileNotFoundError:
            pass
        return results

    @staticmethod
    def _parse_imports(path: str) -> List[str]:
        """Parse one-symbol-per-line imports."""
        results: List[str] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results.append(line)
        except FileNotFoundError:
            pass
        return results

    @staticmethod
    def _parse_exports(path: str) -> List[GhidraExport]:
        """Parse address<TAB>name lines."""
        results: List[GhidraExport] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n\r")
                    if not line:
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        results.append(GhidraExport(address=parts[0], name=parts[1]))
        except FileNotFoundError:
            pass
        return results

    @staticmethod
    def _parse_functions(path: str) -> List[GhidraFunction]:
        """Parse address<TAB>name lines."""
        results: List[GhidraFunction] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n\r")
                    if not line:
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        results.append(GhidraFunction(address=parts[0], name=parts[1]))
        except FileNotFoundError:
            pass
        return results