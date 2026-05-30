#!/usr/bin/env python3
"""
Athene CLI banner — the burrowing-owl CTF colony.

Usage:
    from athene_banner import banner
    banner(version="2.0", sentries=8)

Respects the NO_COLOR convention (https://no-color.org): set the NO_COLOR
environment variable to any value to disable ANSI colors.
"""
import os
import sys

# Burrow palette (256-color ANSI)
_AMBER = "\033[38;5;214m"   # owl eyes / accent
_SAND = "\033[38;5;179m"    # sand
_CREAM = "\033[38;5;230m"   # plumage / wordmark
_DIM = "\033[38;5;243m"     # subtitle
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("ATHENE_NO_BANNER_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, *codes: str) -> str:
    if not _supports_color():
        return text
    return f"{''.join(codes)}{text}{_RESET}"


def _owl_lines() -> list[str]:
    """Six-line burrowing owl: round head, big eyes, long bare legs."""
    eye = _paint("\u25c9", _AMBER)            # ◉
    beak = _paint("\u2572\u2571", _CREAM)      # ╲╱
    frame = lambda s: _paint(s, _CREAM)
    legs = lambda s: _paint(s, _SAND)
    return [
        frame("  \u256d\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256e  "),  #  ╭───────╮
        frame("  \u2502 ") + eye + frame("   ") + eye + frame(" \u2502  "),    #  │ ◉   ◉ │
        frame("  \u2502  ") + beak + frame("   \u2502  "),                      #  │  ╲╱   │
        frame("  \u2570\u2500\u2500\u252c\u2500\u252c\u2500\u2500\u256f  "),  #  ╰──┬─┬──╯
        legs("     \u2571 \u2572     "),                                       #     ╱ ╲
        legs("    \u2571   \u2572    "),                                       #    ╱   ╲
    ]


def banner(version: str = "2.0", sentries: int = 8) -> None:
    """Print the Athene launch banner to stdout."""
    owl = _owl_lines()
    rule = _paint("\u2500" * 34, _DIM)  # ─────...
    text = [
        "",
        _paint("A T H E N E", _BOLD, _CREAM),
        rule,
        _paint("wisdom that digs", _SAND),
        _paint("the burrowing-owl CTF colony", _DIM),
        _paint(
            f"v{version}  \u00b7  colony online \u25b8 {sentries} sentries ready",
            _AMBER,
        ),
    ]
    gap = "   "
    for i, owl_line in enumerate(owl):
        right = text[i] if i < len(text) else ""
        print(f"{owl_line}{gap}{right}")
    print()


if __name__ == "__main__":
    banner()
