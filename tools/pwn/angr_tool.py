"""Angr symbolic execution wrapper for CTF binary challenges."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Sentinel keywords that commonly mark "win" conditions in CTF binaries
_WIN_SYMBOLS = frozenset([
    "win", "flag", "print_flag", "get_flag", "give_flag",
    "backdoor", "shell", "success", "correct", "chall",
    "winner", "congratulations", "congrats",
])


@dataclass
class AngrResult:
    """Result from an angr symbolic execution run."""
    binary_path: str
    found: bool
    stdin_input: Optional[bytes] = None
    target_addr: Optional[int] = None
    target_symbol: Optional[str] = None
    error: Optional[str] = None
    duration_s: float = 0.0


@dataclass
class SymbolHit:
    addr: int
    name: str


class AngrTool:
    """
    Symbolic execution helper built on angr.

    Typical workflow:
      1. Call ``find_win_symbols`` to locate candidate "win" functions.
      2. Call ``find_input`` (or ``find_input_by_symbol``) to discover an
         stdin payload that drives execution to the target address.

    Both methods return ``AngrResult``; callers should check ``.found`` and
    ``.error`` before using ``.stdin_input``.

    Raises ``ImportError`` at construction time if angr is not installed.
    """

    def __init__(self) -> None:
        try:
            import angr as _angr  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "angr is not installed. Run: pip install angr"
            ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_win_symbols(self, binary_path: str) -> List[SymbolHit]:
        """
        Return a list of (addr, name) pairs for functions whose names match
        common CTF win-condition patterns.

        Uses CFGFast for speed; falls back to the symbol table if the CFG
        can't be computed.
        """
        import angr

        proj = angr.Project(binary_path, auto_load_libs=False)
        hits: List[SymbolHit] = []

        # Primary: walk the symbol table directly — fast and reliable
        for sym in proj.loader.main_object.symbols:
            if sym.name and sym.rebased_addr:
                low = sym.name.lower()
                if any(kw in low for kw in _WIN_SYMBOLS):
                    hits.append(SymbolHit(addr=sym.rebased_addr, name=sym.name))

        # Secondary: CFGFast function names (catches renamed / stripped symbols
        # that angr recovers via heuristics)
        if not hits:
            try:
                cfg = proj.analyses.CFGFast(show_progressbar=False, normalize=True)
                for func in cfg.kb.functions.values():
                    if func.name:
                        low = func.name.lower()
                        if any(kw in low for kw in _WIN_SYMBOLS):
                            hits.append(SymbolHit(addr=func.addr, name=func.name))
            except Exception:
                pass

        return hits

    def find_input(
        self,
        binary_path: str,
        find_addr: int,
        avoid_addrs: Optional[List[int]] = None,
        timeout_s: int = 120,
    ) -> AngrResult:
        """
        Use angr's explorer to find a stdin payload that reaches *find_addr*.

        Args:
            binary_path: Path to the ELF/binary.
            find_addr: Address to reach.
            avoid_addrs: Addresses that indicate failure paths (optional).
            timeout_s: Wall-clock limit for the exploration.

        Returns:
            AngrResult — check .found and .error.
        """
        import angr

        start = time.time()
        try:
            proj = angr.Project(binary_path, auto_load_libs=False)
            state = proj.factory.full_init_state()

            # Apply a reasonable stdin size cap to keep the state space bounded
            state.libc.buf_symbolic_bytes = 256

            simgr = proj.factory.simulation_manager(state)

            simgr.explore(
                find=find_addr,
                avoid=avoid_addrs or [],
                timeout=timeout_s,
            )

            duration = time.time() - start

            if simgr.found:
                found_state = simgr.found[0]
                stdin_bytes = found_state.posix.dumps(0)
                return AngrResult(
                    binary_path=binary_path,
                    found=True,
                    stdin_input=stdin_bytes,
                    target_addr=find_addr,
                    duration_s=duration,
                )

            return AngrResult(
                binary_path=binary_path,
                found=False,
                target_addr=find_addr,
                error="No path found within timeout/constraints",
                duration_s=duration,
            )

        except Exception as exc:
            return AngrResult(
                binary_path=binary_path,
                found=False,
                error=str(exc),
                duration_s=time.time() - start,
            )

    def find_input_by_symbol(
        self,
        binary_path: str,
        symbol_name: str,
        avoid_addrs: Optional[List[int]] = None,
        timeout_s: int = 120,
    ) -> AngrResult:
        """
        Convenience wrapper: look up *symbol_name* then call ``find_input``.
        """
        import angr

        try:
            proj = angr.Project(binary_path, auto_load_libs=False)
            sym = proj.loader.main_object.get_symbol(symbol_name)
            if sym is None or not sym.rebased_addr:
                return AngrResult(
                    binary_path=binary_path,
                    found=False,
                    target_symbol=symbol_name,
                    error=f"Symbol '{symbol_name}' not found in binary",
                )
        except Exception as exc:
            return AngrResult(
                binary_path=binary_path,
                found=False,
                target_symbol=symbol_name,
                error=str(exc),
            )

        result = self.find_input(
            binary_path,
            find_addr=sym.rebased_addr,
            avoid_addrs=avoid_addrs,
            timeout_s=timeout_s,
        )
        result = AngrResult(
            binary_path=result.binary_path,
            found=result.found,
            stdin_input=result.stdin_input,
            target_addr=result.target_addr,
            target_symbol=symbol_name,
            error=result.error,
            duration_s=result.duration_s,
        )
        return result
