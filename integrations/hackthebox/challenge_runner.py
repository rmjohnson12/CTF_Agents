"""Orchestration: discover -> filter -> (spawn) -> download -> solve -> report.

Every challenge is processed in its own try/except so one failure never aborts
the run. Nothing is submitted unless ``submit=True`` is passed explicitly.
Solver scope is limited to HTB-provided artifacts (downloaded files) and the
HTB-provided instance target — no other hosts are ever passed to the solver.
"""
from __future__ import annotations

import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .archive import extract_download
from .client import HTBClient
from .config import HTBConfig
from .errors import HTBAuthError, HTBError
from .models import Challenge, ChallengeAttempt, SpawnInfo
from core.utils.security import temporary_allowed_networks

logger = logging.getLogger(__name__)

# Candidate flag patterns. HTB{...} is the canonical format; the generic pattern
# is kept as a secondary so we still surface a plausible flag from other formats.
_HTB_FLAG_RE = re.compile(r"HTB\{[^}\s]{1,256}\}", re.IGNORECASE)
_GENERIC_FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^}\s]{1,256}\}")

SolverFn = Callable[[Dict[str, Any]], Dict[str, Any]]


def _tcp_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    """Return True if a TCP connection to the HTB-provided target succeeds.

    Only ever called with the exact host/port HTB returned for a spawned
    instance — never used to scan arbitrary hosts.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def is_htb_flag(candidate: str) -> bool:
    return bool(_HTB_FLAG_RE.fullmatch(candidate.strip()))


def extract_candidate_flags(text: str) -> List[str]:
    """Return unique candidate flags found in ``text``, HTB-format first."""
    if not text:
        return []
    htb = _HTB_FLAG_RE.findall(text)
    generic = [m for m in _GENERIC_FLAG_RE.findall(text) if not _HTB_FLAG_RE.fullmatch(m)]
    ordered: List[str] = []
    for item in htb + generic:
        if item not in ordered:
            ordered.append(item)
    return ordered


def filter_challenges(
    challenges: List[Challenge],
    *,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    name_contains: Optional[str] = None,
    challenge_id: Optional[int] = None,
    include_retired: bool = False,
    include_solved: bool = False,
    include_locked: bool = False,
    max_count: Optional[int] = None,
) -> List[Challenge]:
    """Apply the operator's selection filters.

    Retired, solved, and locked/unavailable challenges are excluded by default
    and only included when explicitly requested. ``name_contains`` /
    ``challenge_id`` target a specific challenge (case-insensitive substring /
    exact id).
    """
    category_l = category.strip().lower() if category else None
    difficulty_l = difficulty.strip().lower() if difficulty else None
    name_l = name_contains.strip().lower() if name_contains else None

    selected: List[Challenge] = []
    for ch in challenges:
        if challenge_id is not None and ch.id != challenge_id:
            continue
        if name_l and name_l not in ch.name.lower():
            continue
        if category_l and ch.category.lower() != category_l:
            continue
        if difficulty_l and ch.difficulty.lower() != difficulty_l:
            continue
        if ch.retired and not include_retired:
            continue
        if ch.solved and not include_solved:
            continue
        if ch.locked and not include_locked:
            continue
        selected.append(ch)
        if max_count is not None and len(selected) >= max_count:
            break
    return selected


class ChallengeRunner:
    def __init__(
        self,
        client: HTBClient,
        config: Optional[HTBConfig] = None,
        *,
        solver_fn: Optional[SolverFn] = None,
        base_dir: str = "runs/htb",
        solver_timeout_seconds: float = 600.0,
        reachability_check: Optional[Callable[[str, int], bool]] = None,
    ):
        self.client = client
        self.config = config or client.config
        self.base_dir = Path(base_dir)
        self.solver_timeout_seconds = solver_timeout_seconds
        self._solver_fn = solver_fn  # None -> lazily build the real coordinator
        self._reachability_check = reachability_check or _tcp_reachable
        self._coordinator = None

    # ------------------------------------------------------------------ run
    def run(
        self,
        challenges: List[Challenge],
        *,
        dry_run: bool = True,
        do_start: bool = True,
        submit: bool = False,
        submit_difficulty: int = 50,
        stop_started: bool = True,
    ) -> List[ChallengeAttempt]:
        attempts: List[ChallengeAttempt] = []
        for ch in challenges:
            attempts.append(
                self._run_one(
                    ch,
                    dry_run=dry_run,
                    do_start=do_start,
                    submit=submit,
                    submit_difficulty=submit_difficulty,
                    stop_started=stop_started,
                )
            )
        return attempts

    def _run_one(
        self,
        challenge: Challenge,
        *,
        dry_run: bool,
        do_start: bool,
        submit: bool,
        submit_difficulty: int,
        stop_started: bool,
    ) -> ChallengeAttempt:
        started_here = False
        t0 = time.monotonic()
        # Enrich with the info endpoint: the list endpoint omits the description
        # and can misreport download/instance availability (both matter for
        # solving). This is a read-only, in-scope call.
        challenge = self._enrich(challenge)
        attempt = ChallengeAttempt(challenge=challenge, dry_run=dry_run)
        try:
            if dry_run:
                self._plan_dry_run(attempt)
                return attempt

            work_dir = self.base_dir / challenge.slug
            work_dir.mkdir(parents=True, exist_ok=True)
            attempt.work_dir = str(work_dir)

            # 1) Spawn instance if the challenge needs one and start is enabled.
            if challenge.needs_instance and do_start:
                spawn = self._start_and_wait(challenge)
                if spawn is not None:
                    attempt.spawn = spawn
                    attempt.started = True
                    started_here = True

            # 2) Download + safe-extract artifacts.
            if challenge.has_download:
                attempt.downloaded_files = self._download(challenge, work_dir)

            # 3) Run the solver, strictly within HTB-provided scope. If the
            # challenge needs an instance we could not spawn and there are no
            # downloaded artifacts, there is nothing for the solver to work on —
            # skip it instead of burning time/LLM calls against no target.
            target = attempt.spawn.target if attempt.spawn else None
            if challenge.needs_instance and not target and not attempt.downloaded_files:
                attempt.solver_status = "skipped: no reachable target"
                attempt.solver_steps.append(
                    "Challenge requires a spawned instance but none was available "
                    "(start endpoint unavailable/unconfirmed); skipped the solver."
                )
                return attempt
            self._solve(challenge, attempt)

            # 4) Optional, explicit-only flag submission.
            if submit and attempt.candidate_flags:
                self._submit(challenge, attempt, submit_difficulty)

            return attempt
        except HTBAuthError:
            raise  # auth errors must abort the whole run
        except Exception as exc:  # noqa: BLE001 - one challenge must not kill the run
            attempt.error = f"{type(exc).__name__}: {exc}"
            logger.warning("Challenge %s failed: %s", challenge.slug, attempt.error)
            return attempt
        finally:
            attempt.duration_seconds = time.monotonic() - t0
            if started_here and stop_started:
                self._stop_quietly(challenge)

    def _enrich(self, challenge: Challenge) -> Challenge:
        """Merge full detail from the info endpoint; fall back to list data."""
        try:
            full = self.client.get_challenge(challenge.id)
        except HTBError as exc:
            logger.debug("Could not enrich challenge %s: %s", challenge.id, exc)
            return challenge
        challenge.description = full.description or challenge.description
        challenge.has_download = full.has_download or challenge.has_download
        challenge.needs_instance = full.needs_instance or challenge.needs_instance
        if full.category and full.category != "unknown":
            challenge.category = full.category
        if full.raw:
            challenge.raw = full.raw
        return challenge

    # ------------------------------------------------------------ dry-run
    def _plan_dry_run(self, attempt: ChallengeAttempt) -> None:
        ch = attempt.challenge
        plan = [
            f"[dry-run] Would create work dir runs/htb/{ch.slug}/",
        ]
        if ch.needs_instance:
            plan.append("[dry-run] Would start a challenge instance (needs_instance=true).")
        if ch.has_download:
            plan.append("[dry-run] Would download and safely extract challenge files.")
        plan.append("[dry-run] Would run the CTF_Agents solver against local files/target.")
        plan.append("[dry-run] Would collect candidate flags; would NOT submit.")
        attempt.solver_steps = plan
        attempt.solver_status = "dry-run"

    # ------------------------------------------------------------ spawn
    def _start_and_wait(self, challenge: Challenge) -> Optional[SpawnInfo]:
        # The client starts the container and polls HTB's play_info for the
        # IP:PORT, so here we only add a best-effort TCP reachability check
        # against the exact HTB-provided target (never any other host).
        try:
            spawn = self.client.start_instance(challenge.id)
        except HTBError as exc:
            logger.warning("Could not start instance for %s: %s", challenge.slug, exc)
            return None
        host = spawn.host or spawn.ip
        if host and spawn.port and self._reachability_check(host, spawn.port):
            spawn.status = "reachable"
        return spawn

    def _stop_quietly(self, challenge: Challenge) -> None:
        try:
            self.client.stop_instance(challenge.id)
        except HTBError as exc:
            logger.debug("Instance stop for %s failed (non-fatal): %s", challenge.slug, exc)

    # ------------------------------------------------------------ download
    def _download(self, challenge: Challenge, work_dir: Path) -> List[str]:
        content = self.client.download_challenge(challenge.id)
        return extract_download(
            content,
            str(work_dir),
            filename_hint=f"{challenge.slug}.zip",
            password=self.config.archive_password,
        )

    # ------------------------------------------------------------ solve
    @staticmethod
    def _solver_target(spawn: Optional[SpawnInfo]) -> Optional[str]:
        """Build the URL passed to the solver. HTB instances give a bare
        ip:port, but the HTTP-based agents need a scheme, so default to http://."""
        if not spawn:
            return None
        if spawn.url:
            return spawn.url
        host = spawn.ip or spawn.host
        if host and spawn.port:
            return f"http://{host}:{spawn.port}"
        return spawn.target

    def _solve(self, challenge: Challenge, attempt: ChallengeAttempt) -> None:
        target = self._solver_target(attempt.spawn)
        challenge_ctx: Dict[str, Any] = {
            "id": f"htb-{challenge.id}",
            "name": challenge.name,
            "category": challenge.category,
            "description": challenge.description,
            "files": list(attempt.downloaded_files),
            "url": target,
            "metadata": {"source": "hackthebox", "htb_challenge_id": challenge.id},
        }
        solver = self._solver_fn or self._default_solver
        host = (attempt.spawn.ip or attempt.spawn.host) if attempt.spawn else None
        try:
            # Scope the allowlist extension to this one solver invocation. A
            # completed or failed HTB run must not leave a remote host trusted
            # for unrelated work later in the same process.
            with temporary_allowed_networks([host] if host else []):
                result = self._run_with_timeout(solver, challenge_ctx)
        except FutureTimeout:
            attempt.solver_status = "timeout"
            attempt.solver_steps.append(
                f"Solver exceeded {self.solver_timeout_seconds:.0f}s timeout; skipped."
            )
            return
        except Exception as exc:  # noqa: BLE001
            attempt.solver_status = "error"
            attempt.error = f"solver: {type(exc).__name__}: {exc}"
            return

        attempt.solver_status = str(result.get("status", "unknown"))
        steps = result.get("steps") or []
        attempt.solver_steps.extend(str(s) for s in steps[-30:])

        # Gather candidate flags from the explicit flag + the whole step trace.
        haystack = "\n".join([str(result.get("flag") or "")] + [str(s) for s in steps])
        candidates = extract_candidate_flags(haystack)
        # Prefer real HTB-format flags; keep others as lower-priority candidates.
        attempt.candidate_flags = [c for c in candidates if is_htb_flag(c)] + [
            c for c in candidates if not is_htb_flag(c)
        ]

    def _run_with_timeout(self, solver: SolverFn, ctx: Dict[str, Any]) -> Dict[str, Any]:
        # Do NOT use `with ThreadPoolExecutor()`: its __exit__ calls
        # shutdown(wait=True), which would block until a hung solver finishes and
        # defeat the timeout. Shut down without waiting so a timeout returns now.
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(solver, ctx)
        try:
            return future.result(timeout=self.solver_timeout_seconds)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def _default_solver(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Lazily build the shared coordinator and run the existing pipeline."""
        if self._coordinator is None:
            from main import build_coordinator  # local import: heavy dependency tree

            self._coordinator = build_coordinator(max_iterations=5)
        return self._coordinator.solve_challenge(ctx)

    # ------------------------------------------------------------ submit
    def _submit(self, challenge: Challenge, attempt: ChallengeAttempt, difficulty: int) -> None:
        flag = next((c for c in attempt.candidate_flags if is_htb_flag(c)), None)
        if not flag:
            attempt.submission_result = "skipped: no HTB-format flag among candidates"
            return
        try:
            result = self.client.submit_flag(challenge.id, flag, difficulty=difficulty)
            attempt.submitted = True
            attempt.submission_result = str(result.get("message") or result)
        except HTBError as exc:
            attempt.submission_result = f"submission failed: {exc}"
