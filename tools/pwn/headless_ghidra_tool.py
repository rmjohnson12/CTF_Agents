from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class HeadlessGhidraResult:
    binary_path: str
    project_dir: str
    project_name: str
    elapsed_s: float
    artifacts: Dict[str, str]
    command: List[str]


class HeadlessGhidraTool:
    """
    Runs Ghidra's headless analyzer (analyzeHeadless) and exports basic artifacts.

    Requirements:
    - GHIDRA_HOME environment variable set to your Ghidra install directory
      (the folder that contains support/analyzeHeadless)
    - Java installed (Ghidra bundles a JRE in some distributions; depends on install)

    This tool is intentionally MVP: run analysis + dump text artifacts.
    """

    def __init__(self, *, results_dir: str = "results", timeout_s: int = 300):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s

    def _analyze_headless_path(self) -> Path:
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if not ghidra_home:
            raise RuntimeError("GHIDRA_HOME is not set. Set it to your Ghidra install directory.")
        p = Path(ghidra_home) / "support" / "analyzeHeadless"
        if not p.exists():
            raise RuntimeError(f"analyzeHeadless not found at: {p}")
        return p

    def analyze(self, *, binary_path: str, project_name: Optional[str] = None) -> HeadlessGhidraResult:
        started = time.time()

        bin_path = Path(binary_path).expanduser().resolve()
        if not bin_path.exists():
            raise FileNotFoundError(f"Binary not found: {bin_path}")

        ts = time.strftime("%Y%m%d_%H%M%S")
        project_name = project_name or f"ghidra_{bin_path.stem}_{ts}"

        run_dir = self.results_dir / project_name
        run_dir.mkdir(parents=True, exist_ok=True)

        project_dir = run_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)

        scripts_dir = run_dir / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)

        # Minimal Ghidra Java post-scripts to export artifacts.
        # We keep them in the run folder so the tool is self-contained.
        export_script = scripts_dir / "ExportBasics.java"
        export_script.write_text(self._export_basics_java(), encoding="utf-8")

        artifacts = {
            "strings_txt": str(run_dir / "strings.txt"),
            "imports_txt": str(run_dir / "imports.txt"),
            "exports_txt": str(run_dir / "exports.txt"),
            "functions_txt": str(run_dir / "functions.txt"),
            "meta_json": str(run_dir / "meta.json"),
        }

        analyze_headless = self._analyze_headless_path()

        # analyzeHeadless <projectDir> <projectName> -import <file> -analysisTimeoutPerFile <sec>
        # -postScript <ScriptName> <arg1> <arg2> ...
        cmd = [
            str(analyze_headless),
            str(project_dir),
            project_name,
            "-import",
            str(bin_path),
            "-analysisTimeoutPerFile",
            "120",
            "-postScript",
            export_script.name,
            artifacts["strings_txt"],
            artifacts["imports_txt"],
            artifacts["exports_txt"],
            artifacts["functions_txt"],
        ]

        env = os.environ.copy()
        # Make sure Ghidra can find our script
        env["GHIDRA_HEADLESS_SCRIPTS_DIR"] = str(scripts_dir)

        # Some Ghidra installs look in -scriptPath; if needed, add it:
        # cmd.extend(["-scriptPath", str(scripts_dir)])

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(run_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"Ghidra headless timed out after {self.timeout_s}s") from e

        elapsed = time.time() - started

        meta = {
            "binary_path": str(bin_path),
            "project_dir": str(project_dir),
            "project_name": project_name,
            "elapsed_s": elapsed,
            "command": cmd,
            "stdout": proc.stdout[-20000:],  # tail to keep bounded
            "stderr": proc.stderr[-20000:],
            "returncode": proc.returncode,
            "artifacts": artifacts,
        }
        Path(artifacts["meta_json"]).write_text(json.dumps(meta, indent=2), encoding="utf-8")

        if proc.returncode != 0:
            # Make the error actionable: include last stderr lines
            raise RuntimeError(
                "Ghidra analyzeHeadless failed.\n"
                f"Return code: {proc.returncode}\n"
                f"Stderr (tail):\n{meta['stderr']}"
            )

        return HeadlessGhidraResult(
            binary_path=str(bin_path),
            project_dir=str(project_dir),
            project_name=project_name,
            elapsed_s=elapsed,
            artifacts=artifacts,
            command=cmd,
        )

    @staticmethod
    def _export_basics_java() -> str:
        # Ghidra Headless PostScript in Java: dump strings/imports/exports/functions.
        # This is MVP: fast, reliable, and produces artifacts the agent can parse.
        return r'''
// ExportBasics.java
// Usage (headless): -postScript ExportBasics.java <stringsPath> <importsPath> <exportsPath> <functionsPath>
import java.io.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.util.*;
import ghidra.util.exception.*;

public class ExportBasics extends GhidraScript {
    @Override
    public void run() throws Exception {
        String stringsPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "strings.txt";
        String importsPath = getScriptArgs().length > 1 ? getScriptArgs()[1] : "imports.txt";
        String exportsPath = getScriptArgs().length > 2 ? getScriptArgs()[2] : "exports.txt";
        String functionsPath = getScriptArgs().length > 3 ? getScriptArgs()[3] : "functions.txt";

        dumpStrings(stringsPath);
        dumpImports(importsPath);
        dumpExports(exportsPath);
        dumpFunctions(functionsPath);
    }

    private void dumpStrings(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            Listing listing = currentProgram.getListing();
            DataIterator it = listing.getDefinedData(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Data d = it.next();
                DataType dt = d.getDataType();
                if (dt != null && dt.getName() != null && dt.getName().toLowerCase().contains("string")) {
                    String s = d.getValue() != null ? d.getValue().toString() : "";
                    if (s != null && s.length() > 0) {
                        pw.println(d.getAddress().toString() + "\t" + s);
                    }
                }
            }
        }
    }

    private void dumpImports(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator it = st.getExternalSymbols();
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                pw.println(s.getName(true));
            }
        }
    }

    private void dumpExports(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator it = st.getSymbolIterator(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                // crude export-ish heuristic: global, non-external, has address
                if (!s.isExternal() && s.getAddress() != null && s.isGlobal()) {
                    pw.println(s.getAddress().toString() + "\t" + s.getName(true));
                }
            }
        }
    }

    private void dumpFunctions(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            FunctionManager fm = currentProgram.getFunctionManager();
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                pw.println(f.getEntryPoint().toString() + "\t" + f.getName());
            }
        }
    }
}
'''