"""Centralized defaults and constants for the CTF multi-agent system."""

from pathlib import Path
from typing import List, Tuple

# Wordlists
DEFAULT_ROCKYOU_PATHS: List[str] = [
    str(Path(__file__).resolve().parent.parent / "shared" / "wordlists" / "passwords" / "rockyou.txt"),
    "/usr/share/wordlists/rockyou.txt",
    str(Path.home() / "Downloads" / "rockyou.txt"),
    str(Path.home() / "Downloads" / "rockyou" / "rockyou.txt"),
]

# Web exploitation
COMMON_WEB_PATHS: List[str] = [
    "/robots.txt",
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.DS_Store",
    "/config.php.bak",
    "/index.php.bak",
    "/index.php.old",
    "/index.php~",
    "/www.zip",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/.htaccess",
    "/admin",
    "/login",
    "/server-status",
    "/phpinfo.php",
    "/.ssh/id_rsa",
    "/credentials.txt",
    "/notes.txt",
    "/info.txt",
    "/old/",
    "/secret/",
    "/hidden/",
    "/users",
]

COMMON_ADMIN_PATHS: List[str] = [
    "",
    "/admin",
    "/dashboard",
    "/management",
    "/admin/dashboard",
    "/admin/index.php",
]

# Cookie manipulation
DEFAULT_ADMIN_COOKIE: List[dict] = [{"name": "admin", "value": "true", "path": "/"}]
DEFAULT_AUTH_HEADERS: dict = {"Cookie": "admin=true"}

# Credentials
COMMON_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("guest", "guest"),
]

# SQL Injection payloads
SQLI_PAYLOADS: List[str] = [
    "' OR 1=1 --",
    "admin' --",
    "' OR '1'='1",
]

# HTB
HTB_IP_PREFIXES: List[str] = ["10.10."]
HTB_DOMAIN_KEYWORDS: List[str] = ["hackthebox"]

# JavaScript analysis
JS_COMMON_PATHS: List[str] = [
    "/static/app.js",
    "/main.js",
    "/dev/rel.js",
    "/js/app.js",
]

# Flag patterns (for reference — prefer core.utils.flag_utils)
FLAG_PATTERNS: List[str] = [
    r"SKY-[A-Z0-9-]+",
    r"NCL-[A-Z0-9-]+",
    r"CTF\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"flag\{[^}]+\}",
]
