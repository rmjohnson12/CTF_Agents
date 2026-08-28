import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from core.utils.security import temporary_allowed_networks
from tools.web.registration_race import RegistrationPermissionRaceTool


FLAG = "WIZ_CTF{socket_race_verified}"


def _jwt(perms):
    def part(value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{part({'alg': 'HS512'})}.{part({'user_id': 3, 'perms': perms})}.sig"


def _source_tree(path):
    (path / "database.go").write_text(
        """
        const PermissionAdmin = 0
        CREATE TABLE users (permission_level INT, username TEXT);
        INSERT INTO users (username, password_hash, profile_picture_url) VALUES ($1,$2,$3)
        """
    )
    (path / "handlers.go").write_text(
        """
        func RegisterHandler(c echo.Context) error {
          username := c.FormValue("username"); password := c.FormValue("password")
          profilePicURL := c.FormValue("profile_picture_url")
          userID, err := database.CreateUser(username, password, profilePicURL)
          database.UpdateUserPermissions(userID, PermissionUser)
        }
        func LoginHandler(c echo.Context) error {
          var userPerms int
          err := DB.QueryRow("SELECT id, password_hash, permission_level FROM users").Scan(&userID, &hash, &userPerms)
          if err == sql.ErrNoRows { return unauthorized }
          token, err := auth.CreateJWT(userID, userPerms)
          response := map[string]string{"token": token}
        }
        if u.Hostname() != "ui-avatars.com" { return bad }
        """
    )
    (path / "main.go").write_text(
        """
        type Claims struct { Perms int `json:"perms"` }
        e.POST("/auth/register", RegisterHandler); e.POST("/auth/login", LoginHandler)
        adminGroup := e.Group("/admin")
        adminGroup.POST("/confessions/approve/:id", ApproveConfessionHandler)
        if idStr == "flag" { return flag }
        """
    )


def test_web_agent_executes_source_proven_race_over_http(tmp_path):
    lock = threading.Lock()
    users = {}
    admin_token = _jwt(0)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def _reply(self, status, body="", content_type="text/plain"):
            encoded = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            fields = parse_qs(self.rfile.read(length).decode())
            username = fields.get("username", [""])[0]
            password = fields.get("password", [""])[0]

            if self.path == "/auth/register":
                with lock:
                    users[username] = {"password": password, "perms": None}
                time.sleep(0.05)
                with lock:
                    users[username]["perms"] = 1
                self._reply(303)
                return

            if self.path == "/auth/login":
                with lock:
                    user = users.get(username)
                    perms = None if user is None else user["perms"]
                if user is None or user["password"] != password:
                    self._reply(401)
                    return
                token = admin_token if perms is None else _jwt(1)
                self._reply(200, json.dumps({"token": token}), "application/json")
                return

            if self.path == "/admin/confessions/approve/flag":
                if self.headers.get("Authorization") == f"Bearer {admin_token}":
                    self._reply(200, json.dumps({"flag": FLAG}), "application/json")
                else:
                    self._reply(403)
                return

            self._reply(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    _source_tree(source_dir)

    race_tool = RegistrationPermissionRaceTool(
        jitter_func=lambda _low, _high: 0.01
    )
    agent = WebExploitationAgent(registration_race_tool=race_tool)
    try:
        with temporary_allowed_networks(["127.0.0.1"]):
            result = agent.solve_challenge(
                {
                    "id": "registration-race-e2e",
                    "name": "Registration race fixture",
                    "category": "web",
                    "description": "Solve this authorized source-backed web target.",
                    "url": f"http://127.0.0.1:{server.server_port}",
                    "files": [str(source_dir)],
                }
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["status"] == "solved"
    assert result["flag"] == FLAG
    assert result["artifacts"]["registration_permission_race_attempt"][
        "captured_sensitive_values"
    ] is False
