import base64
import json
import threading
import time

from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from core.utils.security import temporary_allowed_networks
from tools.web.registration_race import (
    RegistrationPermissionRaceTool,
    RegistrationRaceResult,
)


FLAG = "WIZ_CTF{race_agent_recovered}"


def _jwt(payload):
    def encode(value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{encode({'alg': 'HS512', 'typ': 'JWT'})}.{encode(payload)}.signature"


class _Response:
    def __init__(self, status_code, body="", json_body=None):
        self.status_code = status_code
        self.text = body
        self._json_body = json_body

    def json(self):
        if self._json_body is None:
            raise ValueError("not JSON")
        return self._json_body


def _proven_source():
    return [
        """
        const PermissionAdmin = 0
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            permission_level INT,
            username TEXT
        );
        INSERT INTO users (username, password_hash, profile_picture_url) VALUES ($1, $2, $3)
        """,
        """
        func RegisterHandler(c echo.Context) error {
            username := c.FormValue("username")
            password := c.FormValue("password")
            profilePicURL := c.FormValue("profile_picture_url")
            userID, err := database.CreateUser(username, password, profilePicURL)
            database.UpdateUserPermissions(userID, PermissionUser)
        }
        func LoginHandler(c echo.Context) error {
            var userPerms int
            err := DB.QueryRow("SELECT id, password_hash, permission_level FROM users WHERE username = $1").Scan(&userID, &hash, &userPerms)
            if err == sql.ErrNoRows { return unauthorized }
            token, err := auth.CreateJWT(userID, userPerms)
            response := map[string]string{"token": token}
        }
        if u.Hostname() != "ui-avatars.com" { return bad }
        """,
        """
        type Claims struct { Perms int `json:"perms"` }
        e.Match([]string{"GET", "POST"}, "/auth/register", RegisterHandler)
        e.Match([]string{"GET", "POST"}, "/auth/login", LoginHandler)
        adminGroup := e.Group("/admin")
        adminGroup.POST("/confessions/approve/:id", ApproveConfessionHandler)
        if idStr == "flag" { return flag }
        """,
    ]


def test_source_detector_requires_the_complete_permission_race_chain():
    evidence = WebExploitationAgent._detect_go_registration_permission_race(
        _proven_source()
    )

    assert evidence is not None
    assert evidence["register_path"] == "/auth/register"
    assert evidence["login_path"] == "/auth/login"
    assert evidence["flag_path"] == "/admin/confessions/approve/flag"
    assert evidence["admin_claim"] == "perms"
    assert evidence["extra_registration"]["profile_picture_url"].startswith(
        "https://ui-avatars.com/"
    )

    safe_source = [chunk.replace("permission_level INT,", "permission_level INT DEFAULT 1,") for chunk in _proven_source()]
    assert (
        WebExploitationAgent._detect_go_registration_permission_race(safe_source)
        is None
    )


def test_registration_race_tool_wins_and_does_not_persist_tokens():
    lock = threading.Lock()
    users = {}
    admin_token = _jwt({"user_id": 7, "perms": 0})
    user_token = _jwt({"user_id": 7, "perms": 1})

    def request(method, url, *, data=None, headers=None, **_kwargs):
        if url.endswith("/auth/register"):
            with lock:
                users[data["username"]] = {"password": data["password"], "perms": None}
            time.sleep(0.04)
            with lock:
                users[data["username"]]["perms"] = 1
            return _Response(303)

        if url.endswith("/auth/login"):
            with lock:
                user = users.get(data["username"])
                perms = None if user is None else user["perms"]
            if user is None:
                return _Response(401)
            token = admin_token if perms is None else user_token
            return _Response(200, json_body={"token": token})

        if url.endswith("/admin/confessions/approve/flag"):
            if (headers or {}).get("Authorization") == f"Bearer {admin_token}":
                return _Response(200, json.dumps({"flag": FLAG}))
            return _Response(403)

        return _Response(404)

    tool = RegistrationPermissionRaceTool(
        request_func=request,
        jitter_func=lambda _low, _high: 0.005,
    )
    evidence = WebExploitationAgent._detect_go_registration_permission_race(
        _proven_source()
    )

    with temporary_allowed_networks(["target"]):
        result = tool.run(
            "http://target",
            evidence,
            attempts=2,
            logins_per_attempt=12,
            jitter_seconds=0.01,
        )

    assert result.flag == FLAG
    assert result.admin_candidates >= 1
    artifact = result.sanitized_artifact()
    assert artifact["captured_sensitive_values"] is False
    assert "eyj" not in json.dumps(artifact).lower()
    assert admin_token not in json.dumps(artifact)


def test_web_agent_routes_source_proven_race_before_generic_recon(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    for index, content in enumerate(_proven_source()):
        (source_dir / f"part_{index}.go").write_text(content)

    class _SolvedRace:
        def __init__(self):
            self.calls = []

        def run(self, url, evidence, **kwargs):
            self.calls.append((url, evidence, kwargs))
            return RegistrationRaceResult(FLAG, 3, 4, 1, 247)

    race = _SolvedRace()
    agent = WebExploitationAgent(registration_race_tool=race)
    result = agent.solve_challenge(
        {
            "id": "source-race",
            "name": "Generic registration challenge",
            "category": "web",
            "description": "Analyze the supplied Go source and solve the authorized target.",
            "url": "http://target",
            "files": [str(source_dir)],
        }
    )

    assert result["status"] == "solved"
    assert result["flag"] == FLAG
    assert race.calls
    assert "registration_permission_race" in result["vulnerabilities_found"]
    attempt = result["artifacts"]["registration_permission_race_attempt"]
    assert attempt["captured_sensitive_values"] is False
