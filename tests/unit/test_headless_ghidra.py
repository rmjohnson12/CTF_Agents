"""Unit tests for HeadlessGhidraTool.

These tests exercise the TSV parsers and GHIDRA_HOME validation
without requiring a Ghidra installation.
"""
import os
import pytest

from tools.pwn.headless_ghidra_tool import (
    HeadlessGhidraTool,
    GhidraString,
    GhidraExport,
    GhidraFunction,
)


# ── TSV parsing ──────────────────────────────────────────────────────

def test_parse_strings(tmp_path):
    tsv = tmp_path / "strings.tsv"
    tsv.write_text("00401000\tHello World\n00401020\tUsage: ./bin\n")

    result = HeadlessGhidraTool._parse_strings(str(tsv))

    assert len(result) == 2
    assert result[0] == GhidraString(address="00401000", value="Hello World")
    assert result[1] == GhidraString(address="00401020", value="Usage: ./bin")


def test_parse_strings_missing_file():
    result = HeadlessGhidraTool._parse_strings("/nonexistent/strings.tsv")
    assert result == []


def test_parse_imports(tmp_path):
    tsv = tmp_path / "imports.tsv"
    tsv.write_text("libc::printf\nlibc::malloc\n")

    result = HeadlessGhidraTool._parse_imports(str(tsv))

    assert result == ["libc::printf", "libc::malloc"]


def test_parse_imports_skips_blank_lines(tmp_path):
    tsv = tmp_path / "imports.tsv"
    tsv.write_text("puts\n\ngets\n\n")

    result = HeadlessGhidraTool._parse_imports(str(tsv))

    assert result == ["puts", "gets"]


def test_parse_exports(tmp_path):
    tsv = tmp_path / "exports.tsv"
    tsv.write_text("00400000\t_start\n00400100\tmain\n")

    result = HeadlessGhidraTool._parse_exports(str(tsv))

    assert len(result) == 2
    assert result[0] == GhidraExport(address="00400000", name="_start")
    assert result[1] == GhidraExport(address="00400100", name="main")


def test_parse_functions(tmp_path):
    tsv = tmp_path / "functions.tsv"
    tsv.write_text("00400000\t_init\n00400080\tmain\n004000f0\t_fini\n")

    result = HeadlessGhidraTool._parse_functions(str(tsv))

    assert len(result) == 3
    assert result[1] == GhidraFunction(address="00400080", name="main")


def test_parse_functions_empty_file(tmp_path):
    tsv = tmp_path / "functions.tsv"
    tsv.write_text("")

    result = HeadlessGhidraTool._parse_functions(str(tsv))

    assert result == []


# ── GHIDRA_HOME validation ───────────────────────────────────────────

def test_find_analyze_headless_missing_env(monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)

    with pytest.raises(EnvironmentError, match="GHIDRA_HOME is not set"):
        HeadlessGhidraTool.find_analyze_headless()


def test_find_analyze_headless_bad_dir(monkeypatch):
    monkeypatch.setenv("GHIDRA_HOME", "/nonexistent/ghidra_dir")

    with pytest.raises(EnvironmentError, match="not a directory"):
        HeadlessGhidraTool.find_analyze_headless()


def test_find_analyze_headless_no_script(monkeypatch, tmp_path):
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))

    with pytest.raises(FileNotFoundError, match="analyzeHeadless not found"):
        HeadlessGhidraTool.find_analyze_headless()


def test_find_analyze_headless_success(monkeypatch, tmp_path):
    support = tmp_path / "support"
    support.mkdir()
    script = support / "analyzeHeadless"
    script.write_text("#!/bin/sh\n")

    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))

    result = HeadlessGhidraTool.find_analyze_headless()
    assert result == str(script)
