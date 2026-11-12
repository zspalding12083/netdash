"""Dashboard logins for a handful of people (stdlib only).

Off unless NETDASH_AUTH=on. Users live in netdash's SQLite and are managed
from the command line (`python3 -m netdash user add NAME`, see __main__.py).
Passwords are hashed with PBKDF2-SHA256 (600,000 rounds, random salt). A login
gives a random session token in an HttpOnly, SameSite=Strict cookie; only its
SHA-256 is stored, so a copy of the database can't be used to log in.

Repeated failures are slowed down: MAX_FAILURES wrong passwords from one
address, or for one user name, within LOCK_FOR block further tries for LOCK_FOR.

Settings (/etc/netdash.env):
    NETDASH_AUTH          on / off (default off)
    NETDASH_SESSION_DAYS  how long a login lasts; default 30
"""
import datetime as dt
import hashlib
import hmac
import os
import secrets
import threading
import time

ITERATIONS = 600_000
MIN_PASSWORD = 10
MAX_FAILURES = 5
LOCK_FOR = 15 * 60            # seconds
COOKIE = "netdash_session"
# Compared against when the user name doesn't exist, so a wrong name takes as long as a wrong password.
_DUMMY = (b"\0" * 16, ITERATIONS, hashlib.pbkdf2_hmac("sha256", b"x", b"\0" * 16, ITERATIONS))


def hash_password(password: str, salt: bytes | None = None, iterations: int = ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    return salt, iterations, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def check_password_rules(name: str, password: str) -> str | None:
    """A reason the password isn't acceptable, or None."""
    if len(password) < MIN_PASSWORD:
        return f"use at least {MIN_PASSWORD} characters"
    if password.lower() == name.lower():
        return "the password can't be the user name"
    return None


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, store, env=os.environ):
        self.store = store
        self.enabled = (env.get("NETDASH_AUTH") or "off").lower() in ("on", "1", "yes", "true")
        self.session_for = dt.timedelta(days=float(env.get("NETDASH_SESSION_DAYS") or 30))
        self._failures = {}           # key ("ip:..." / "user:...") -> [monotonic times]
        self._lock = threading.Lock()

    # ---- rate limiting -----------------------------------------------------
    def _recent(self, key, now):
        times = [t for t in self._failures.get(key, []) if now - t < LOCK_FOR]
        self._failures[key] = times
        return times

    def locked(self, ip, user) -> bool:
        now = time.monotonic()
        with self._lock:
            return any(len(self._recent(k, now)) >= MAX_FAILURES for k in (f"ip:{ip}", f"user:{user.lower()}"))

    def _fail(self, ip, user):
        now = time.monotonic()
        with self._lock:
            for k in (f"ip:{ip}", f"user:{user.lower()}"):
                self._recent(k, now).append(now)
            if len(self._failures) > 10000:     # bounded memory
                self._failures.clear()

    # ---- logins ------------------------------------------------------------
    def login(self, user: str, password: str, ip: str):
        """(token, None) on success, or (None, reason) with reason "locked" / "bad"."""
        user = (user or "").strip()
        if self.locked(ip, user):
            return None, "locked"
        u = self.store.get_user(user) if user else None
        salt, iterations, expected = (u["salt"], u["iterations"], u["hash"]) if u else _DUMMY
        _, _, got = hash_password(password or "", salt, iterations)
        if not u or not hmac.compare_digest(got, expected):
            self._fail(ip, user)
            return None, "bad"
        token = secrets.token_urlsafe(32)
        expires = (dt.datetime.now() + self.session_for).isoformat(timespec="seconds")
        self.store.add_session(token_hash(token), u["name"], expires, ip)
        return token, None

    def user_for(self, token: str | None):
        return self.store.session_user(token_hash(token)) if token else None

    def logout(self, token: str | None) -> None:
        if token:
            self.store.delete_session(token_hash(token))

    def max_age(self) -> int:
        return int(self.session_for.total_seconds())

    # ---- user management (CLI) ---------------------------------------------
    def set_password(self, name: str, password: str) -> None:
        problem = check_password_rules(name, password)
        if problem:
            raise ValueError(problem)
        self.store.set_user(name, *hash_password(password))
