# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Serwer HTTP (biblioteka standardowa) + API JSON. Wielu użytkowników, role, dziennik zmian."""
from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import ssl
import threading
import time
import traceback
from datetime import date, datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from . import engine as E
from . import feeds
from . import importer as I
from . import tickets as T
from . import xlsx_export as X
from . import __author__, __license__, __url__, __version__
from .storage import Vault, WrongPassphrase, canon, now_iso

APP_NAME = "VulnBuster"
ABOUT = {"version": __version__, "license": __license__, "author": __author__, "url": __url__}
STATIC = os.path.join(os.path.dirname(__file__), "static")
SESSION_TTL = 8 * 3600
MAX_BODY = 60 * 1024 * 1024
MAX_FAILS, LOCKOUT_S = 5, 15 * 60
MAX_CHANGES_PER_ENTRY = 300

TRIAGE = {
    "affected": "Dotyczy nas — wymaga działań",
    "used_safe": "Używamy, ale niepodatne / zmitygowane",
    "not_used": "Nie używamy produktu",
    "not_applicable": "Nie dotyczy nas (inny powód)",
    "pending": "W analizie",
}
PRODUCT_STATUS = {"used": "Używamy", "not_used": "Nie używamy", "unknown": "Nie wiadomo"}
ROLES = {"viewer": 0, "editor": 1, "admin": 2}
ROLE_LABELS = {"viewer": "Podgląd", "editor": "Analityk", "admin": "Administrator"}
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,39}$")

# śledzone kolekcje dla dziennika zmian: typ -> (funkcja zwracająca {id: obiekt}, funkcja etykiety)
TRACK = {
    "host": (lambda db: db["hosts"], lambda o: o.get("hostname", "?")),
    "product": (lambda db: db["products"], lambda o: o.get("name", "?")),
    "cve": (lambda db: db["cves"], lambda o: o.get("id", "?")),
    "exception": (lambda db: {e["id"]: e for e in db["exceptions"]}, lambda o: (o.get("reason") or "")[:60]),
    "installation": (lambda db: db["inventory"], None),
    "user": (lambda db: db["users"], lambda o: o.get("username", "?")),
    "kev_decision": (lambda db: db["kev_product_map"], lambda o: o.get("label", "?")),
    "settings": (lambda db: {"settings": db["settings"]}, lambda o: "Ustawienia"),
    "ticket": (lambda db: {t["id"]: t for t in db.get("tickets", [])}, lambda o: (o.get("subject") or "")[:80]),
}
DIFF_IGNORE = {"updated_at", "last_seen", "history", "import_id", "first_seen", "updated_by", "last_login",
               "password_changed_at"}
CREATE_IGNORE = DIFF_IGNORE | {"id", "created_at", "created_by", "username", "host_id", "product_id"}


class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status, self.msg = status, msg


def today():
    return date.today().isoformat()


def stamp():
    """Znacznik wersji obiektu (z mikrosekundami — do wykrywania równoczesnej edycji)."""
    return datetime.now(timezone.utc).isoformat()


def require(cond, msg, status=400):
    if not cond:
        raise ApiError(status, msg)


def clean(s, n=4000):
    return str(s if s is not None else "").strip()[:n]


def short(v, n=300):
    if v is None or v == "":
        return v
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[: n - 1] + "…"


class App:
    def __init__(self, data_path: str, secure_cookie=False):
        self.vault = Vault(data_path)
        self.sessions: dict[str, dict] = {}
        self.import_cache: dict[str, dict] = {}
        self.fails: dict[str, list] = {}
        self.secure_cookie = secure_cookie
        self.routes = []
        self.user = None          # bieżący użytkownik (ustawiany pod blokadą sejfu)
        self._pending = None      # zmiana do zapisania po wykonaniu handlera
        self._dash = None         # pamięć podręczna pulpitu (do następnego zapisu)
        self._register()

    # ------------------------------------------------------------ routing
    def route(self, method, pattern, auth=True, role=None, heavy=False):
        """heavy=True: operacja zmienia inwentarz (instalacje) — dziennik porównuje także instalacje."""
        rx = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")
        role = role or ("viewer" if method == "GET" else "editor")

        def deco(fn):
            self.routes.append((method, rx, fn, auth, role, heavy))
            return fn
        return deco

    def dispatch(self, method, path, query, body, token):
        for m, rx, fn, auth, role, heavy in self.routes:
            if m != method:
                continue
            mt = rx.match(path)
            if not mt:
                continue
            params = {k: unquote(v) for k, v in mt.groupdict().items()}
            if not auth:
                return fn(body=body, query=query, **params)
            require(self.vault.unlocked, "Sejf zablokowany — zaloguj się, aby go odblokować", 423)
            with self.vault.lock:
                user = self.session_user(token)
                require(user, "Wymagane logowanie", 401)
                if user.get("must_change") and not path.startswith("/api/me"):
                    raise ApiError(403, "Najpierw zmień hasło tymczasowe")
                require(ROLES[user["role"]] >= ROLES[role],
                        f"Brak uprawnień (wymagana rola: {ROLE_LABELS[role]})", 403)
                self.user, self._pending = user, None
                before = self.snapshot(heavy) if method != "GET" else None
                try:
                    res = fn(body=body, query=query, **params)
                    if self._pending:
                        self.commit(before)
                    return res
                except Exception:
                    if method != "GET" and self.vault.unlocked:
                        self.vault.reload()   # wycofanie częściowych zmian w pamięci
                    raise
                finally:
                    self.user, self._pending = None, None
        raise ApiError(404, "Nie znaleziono")

    @property
    def db(self):
        return self.vault.db

    @property
    def uname(self):
        return (self.user or {}).get("username", "system")

    def save(self, action, detail="", backup=False):
        """Oznacza zmianę do zapisu; zapis + wpis w dzienniku robi dispatch() po handlerze."""
        self._pending = {"action": action, "detail": detail, "backup": backup}

    # ------------------------------------------------------------ dziennik zmian
    def snapshot(self, heavy=False):
        return {t: {k: canon(v) for k, v in get(self.db).items()} for t, (get, _) in TRACK.items()
                if heavy or t != "installation"}

    def label(self, typ, key, obj):
        if typ == "installation":
            h = self.db["hosts"].get(obj.get("host_id"), {}).get("hostname", "?")
            p = self.db["products"].get(obj.get("product_id"), {}).get("name", "?")
            return f"{h} / {p}"
        return TRACK[typ][1](obj)

    def fmt_field(self, f, v):
        """Czytelna postać złożonych pól w dzienniku."""
        if v in (None, "", [], {}):
            return v
        P = self.db["products"]
        try:
            if f == "rules":
                out = []
                for r in v:
                    br = ", ".join(f"{b.get('branch')}→" + ({"nofix": "brak poprawki", "safe": "niepodatna"}.get(
                        b.get("state"), b.get("fixed") or "?")) for b in r.get("branches", []))
                    out.append(f"{P.get(r['product_id'], {}).get('name', r['product_id'])}: {br or 'bez gałęzi'}")
                return "; ".join(out)
            if f == "triage":
                return f"{v.get('decision')} — {v.get('note') or 'bez notatki'} ({v.get('verified_by') or '?'}, {v.get('verified_at')})"
            if f == "assessment":
                return (f"ryzyko: {E.RISK_LABELS.get(v.get('risk'), '—')}, ocena: {v.get('score') or '—'}, "
                        f"termin: {v.get('deadline') or '—'}; wpływ: {(v.get('impact') or '—')[:120]}; "
                        f"wykorzystanie: {(v.get('exploitation') or '—')[:120]}")
            if f == "team":
                return self.db["settings"].get("teams") and next(
                    (t["name"] for t in self.db["settings"]["teams"] if t["id"] == v), v) or v
            if f == "mitigations":
                return "; ".join(f"{m.get('group') or m.get('cve_id')}: {m.get('description') or ''}" for m in v)
            if f == "product_ids":
                return ", ".join(P.get(x, {}).get("name", x) for x in v)
            if f in ("groups", "aliases", "reported_cves") and isinstance(v, list):
                return ", ".join(map(str, v))
            if f == "settings" or isinstance(v, dict) and f == "groups":
                return v
        except Exception:  # noqa: BLE001
            pass
        return v

    def diff(self, before):
        after = self.snapshot("installation" in before)
        changes, stats = [], {}
        for typ in before:
            b, a = before[typ], after[typ]
            for key in set(b) | set(a):
                if b.get(key) == a.get(key):
                    continue
                old = json.loads(b[key]) if key in b else None
                new = json.loads(a[key]) if key in a else None
                op = "create" if old is None else "delete" if new is None else "update"
                fields = {}
                if op == "update":
                    for f in set(old) | set(new):
                        if f in DIFF_IGNORE or old.get(f) == new.get(f):
                            continue
                        fields[f] = [short(self.fmt_field(f, old.get(f))), short(self.fmt_field(f, new.get(f)))]
                    if not fields:
                        continue
                elif typ != "installation":
                    src = new or old
                    fields = {f: short(self.fmt_field(f, v)) for f, v in src.items()
                              if f not in CREATE_IGNORE and v not in (None, "", [], {})}
                else:
                    fields = {"version": short((new or old).get("version"))}
                st = stats.setdefault(typ, {"create": 0, "update": 0, "delete": 0})
                st[op] += 1
                changes.append({"type": typ, "id": key, "label": self.label(typ, key, new or old), "op": op,
                                "fields": fields})
        return changes, stats

    def commit(self, before):
        p = self._pending
        changes, stats = self.diff(before)
        entry = {"ts": now_iso(), "user": self.uname, "action": p["action"], "summary": p["detail"][:500],
                 "changes": changes[:MAX_CHANGES_PER_ENTRY], "stats": stats}
        if len(changes) > MAX_CHANGES_PER_ENTRY:
            entry["truncated"] = len(changes) - MAX_CHANGES_PER_ENTRY
        self.vault.save(force_backup=p["backup"])
        self.vault.append_audit(entry)

    def load_obs(self, imp):
        """Obserwacje importu z osobnego pliku (z uwzględnieniem scalonych aplikacji)."""
        if imp.get("observations") is not None:
            obs = imp["observations"]
        elif imp.get("archived"):
            return None
        else:
            obs = self.vault.read_observations(imp["id"])
        red = self.db.get("product_redirects") or {}
        if obs and red:
            obs = [dict(o, p=red.get(o["p"], o["p"])) if o["p"] in red else o for o in obs]
        return obs

    def log_event(self, user, action, detail=""):
        if self.vault.unlocked:
            with self.vault.lock:
                self.vault.append_audit({"ts": now_iso(), "user": user, "action": action, "summary": detail,
                                         "changes": [], "stats": {}})

    def last_change(self, ent_id):
        for e in reversed(self.vault.audit_entries):
            for c in e.get("changes") or []:
                if c["id"] == ent_id:
                    return e
        return None

    def check_version(self, ent, body):
        v = body.get("_version")
        if v and ent.get("updated_at") and v != ent["updated_at"]:
            e = self.last_change(ent.get("id") or "")
            who = self.display(e["user"]) if e else "inny użytkownik"
            when = (e or {}).get("ts", "")[:16].replace("T", " ")
            raise ApiError(409, f"Ten obiekt zmienił w międzyczasie {who} ({when} UTC). Odśwież stronę, "
                                f"sprawdź zmiany i wprowadź swoje ponownie.")

    def display(self, username):
        u = (self.db or {}).get("users", {}).get(username)
        return f"{u.get('display_name') or username} ({username})" if u else username

    # ------------------------------------------------------------ sesje i logowanie
    def new_session(self, username):
        tok = secrets.token_urlsafe(32)
        self.sessions[tok] = {"user": username, "exp": time.time() + SESSION_TTL}
        return tok

    def session_user(self, tok):
        s = self.sessions.get(tok or "")
        if not s or s["exp"] < time.time() or not self.vault.unlocked:
            self.sessions.pop(tok or "", None)
            return None
        u = self.db["users"].get(s["user"])
        if not u or not u.get("active", True):
            self.sessions.pop(tok, None)
            return None
        s["exp"] = time.time() + SESSION_TTL
        return u

    def kill_sessions(self, username, except_tok=None):
        for t in [t for t, s in self.sessions.items() if s["user"] == username and t != except_tok]:
            del self.sessions[t]

    def check_lockout(self, username):
        f = self.fails.get(username)
        if f and f[1] > time.time():
            mins = int((f[1] - time.time()) // 60) + 1
            raise ApiError(429, f"Konto tymczasowo zablokowane po {MAX_FAILS} błędnych próbach. Spróbuj za {mins} min.")

    def register_fail(self, username):
        f = self.fails.setdefault(username, [0, 0])
        f[0] += 1
        if f[0] >= MAX_FAILS:
            f[0], f[1] = 0, time.time() + LOCKOUT_S
            self.log_event(username, "auth.lockout", "Blokada konta po błędnych próbach logowania")
        time.sleep(1.0)

    def me(self, u):
        return {"username": u["username"], "display_name": u.get("display_name") or u["username"],
                "role": u["role"], "role_label": ROLE_LABELS[u["role"]], "must_change": bool(u.get("must_change"))}

    # ------------------------------------------------------------ helpers
    def product_row(self, p, usage, cve_count):
        st = self.db["settings"]
        return {**{k: p.get(k) for k in ("id", "name", "vendor", "aliases", "category", "status", "notes",
                                          "verified_at", "verified_by", "created_at", "updated_at", "team")},
                "hosts": usage.get(p["id"], 0), "cves": cve_count.get(p["id"], 0),
                "stale": E.staleness(p.get("verified_at"), st)}

    def cve_row(self, c, open_map=None):
        st = self.db["settings"]
        k = self.db["kev"]["entries"].get(c["id"])
        t = c.get("triage") or {}
        return {"id": c["id"], "title": c.get("title") or (k or {}).get("vulnerabilityName", ""),
                "cvss": c.get("cvss"), "severity": c.get("severity"), "groups": c.get("groups", []),
                "kev": bool(k), "kev_date": (k or {}).get("dateAdded"), "kev_due": (k or {}).get("dueDate"),
                "products": [self.db["products"].get(r["product_id"], {}).get("name", "?") for r in c.get("rules", [])],
                "triage": t, "stale": E.staleness(t.get("verified_at"), st) if t.get("decision") else None,
                "open": (open_map or {}).get(c["id"], 0), "updated_at": c.get("updated_at")}

    def open_by_cve(self):
        ctx = E.Ctx(self.db)
        out = {}
        for inst in self.db["inventory"].values():
            if inst.get("removed"):
                continue
            host = self.db["hosts"].get(inst["host_id"])
            for f in E.findings_for(ctx, host, inst["product_id"], inst.get("version"), inst.get("reported_cves")):
                if f["status"] in E.ACTION:
                    out[f["cve"]] = out.get(f["cve"], 0) + 1
        return out

    def ensure_cve(self, cid):
        cid = cid.upper().strip()
        require(re.match(r"^CVE-\d{4}-\d{4,}$", cid), f"Niepoprawny identyfikator CVE: {cid}")
        c = self.db["cves"].get(cid)
        if c is None:
            k = self.db["kev"]["entries"].get(cid, {})
            c = {"id": cid, "title": k.get("vulnerabilityName", ""), "description": k.get("shortDescription", ""),
                 "cvss": None, "severity": None, "groups": [], "rules": [], "triage": {}, "notes": "",
                 "created_at": now_iso(), "updated_at": now_iso()}
            self.db["cves"][cid] = c
        return c

    def find_or_create_product(self, name, vendor="", status="used"):
        idx = I.product_index(self.db)
        pid = idx.get(E.norm(name))
        if pid:
            return pid, False
        pid = I.new_id("p")
        self.db["products"][pid] = {"id": pid, "name": name, "vendor": vendor, "aliases": [], "category": "",
                                    "status": status, "notes": "", "verified_at": today(), "created_at": now_iso()}
        return pid, True

    # ------------------------------------------------------------ endpoints
    def _register(self):
        r = self.route
        V = self.vault

        @r("GET", "/api/status", auth=False)
        def status(body, query):
            return {"initialized": V.initialized, "unlocked": V.unlocked, "app": APP_NAME, **ABOUT}

        def check_password(pw, username):
            require(len(pw) >= 12, "Hasło musi mieć co najmniej 12 znaków")
            require(pw.lower() != username.lower(), "Hasło nie może być takie jak login")

        @r("POST", "/api/init", auth=False)
        def init(body, query):
            username = clean(body.get("username"), 40).lower()
            pw = body.get("password") or ""
            require(USER_RE.match(username), "Login: 2–40 znaków, małe litery, cyfry, . _ -")
            check_password(pw, username)
            with V.lock:
                require(not V.initialized, "Sejf już istnieje")
                V.init(username, pw)
                V.db["users"][username] = {"username": username, "display_name": clean(body.get("display_name"), 100),
                                           "role": "admin", "active": True, "created_at": now_iso(),
                                           "created_by": username, "last_login": now_iso(), "must_change": False}
                V.save()
                V.append_audit({"ts": now_iso(), "user": username, "action": "vault.init",
                                "summary": "Utworzono sejf i konto administratora", "changes": [], "stats": {}})
            return {"ok": True, "_session": self.new_session(username)}

        @r("POST", "/api/login", auth=False)
        def login(body, query):
            username = clean(body.get("username"), 40).lower()
            pw = body.get("password") or ""
            require(username and pw, "Podaj login i hasło")
            require(V.initialized, "Sejf nie jest jeszcze utworzony")
            self.check_lockout(username)
            bad = ApiError(403, "Nieprawidłowy login lub hasło")
            with V.lock:
                was_locked = not V.unlocked
                if was_locked:
                    try:
                        V.unlock(username, pw)
                    except WrongPassphrase:
                        self.register_fail(username)
                        raise bad
                elif not V.verify(username, pw):
                    self.log_event(username, "auth.fail", "Nieudane logowanie")
                    self.register_fail(username)
                    raise bad
                u = V.db["users"].get(username)
                if not u or not u.get("active", True):
                    if was_locked:
                        V.lock_vault()
                    self.register_fail(username)
                    raise bad
                self.fails.pop(username, None)
                u["last_login"] = now_iso()
                V.save()
                V.append_audit({"ts": now_iso(), "user": username, "action": "auth.login",
                                "summary": "Zalogowano" + (" i odblokowano sejf" if was_locked else ""),
                                "changes": [], "stats": {}})
                return {"ok": True, "me": self.me(u), "_session": self.new_session(username)}

        @r("POST", "/api/logout", auth=False)
        def logout(body, query):
            return {"ok": True, "_logout": True}

        @r("POST", "/api/lock", role="admin")
        def lock(body, query):
            self.vault.append_audit({"ts": now_iso(), "user": self.uname, "action": "vault.lock",
                                     "summary": "Zablokowano sejf (wylogowano wszystkich)", "changes": [], "stats": {}})
            V.lock_vault()
            self.sessions.clear()
            self.import_cache.clear()
            return {"ok": True}

        # ---------------- moje konto
        @r("GET", "/api/me", role="viewer")
        def me(body, query):
            return self.me(self.user)

        @r("POST", "/api/me/password", role="viewer")
        def me_password(body, query):
            u = self.user
            new = body.get("new") or ""
            if not V.verify(u["username"], body.get("old") or ""):
                raise ApiError(403, "Obecne hasło jest nieprawidłowe")
            check_password(new, u["username"])
            require(new != body.get("old"), "Nowe hasło musi się różnić od obecnego")
            V.set_password(u["username"], new)
            u["must_change"] = False
            u["password_changed_at"] = now_iso()
            self.save("user.password", f"{u['username']} zmienił swoje hasło")
            return {"ok": True}

        # ---------------- użytkownicy (administrator)
        def admins_left(excluding):
            return sum(1 for x in self.db["users"].values()
                       if x["role"] == "admin" and x.get("active", True) and x["username"] != excluding)

        @r("GET", "/api/users", role="admin")
        def users(body, query):
            active_sessions = {}
            for s_ in self.sessions.values():
                if s_["exp"] > time.time():
                    active_sessions[s_["user"]] = active_sessions.get(s_["user"], 0) + 1
            out = [{**{k: x.get(k) for k in ("username", "display_name", "role", "active", "created_at", "created_by",
                                             "last_login", "must_change", "password_changed_at")},
                    "role_label": ROLE_LABELS[x["role"]], "sessions": active_sessions.get(x["username"], 0),
                    "locked": bool(self.fails.get(x["username"]) and self.fails[x["username"]][1] > time.time())}
                   for x in self.db["users"].values()]
            out.sort(key=lambda x: (not x["active"], x["username"]))
            return {"users": out, "roles": ROLE_LABELS}

        @r("POST", "/api/users", role="admin")
        def user_create(body, query):
            username = clean(body.get("username"), 40).lower()
            require(USER_RE.match(username), "Login: 2–40 znaków, małe litery, cyfry, . _ -")
            require(username not in self.db["users"], "Taki login już istnieje")
            role = body.get("role") or "viewer"
            require(role in ROLES, "Niepoprawna rola")
            pw = body.get("password") or ""
            check_password(pw, username)
            V.set_password(username, pw)
            self.db["users"][username] = {"username": username, "display_name": clean(body.get("display_name"), 100),
                                          "role": role, "active": True, "created_at": now_iso(),
                                          "created_by": self.uname, "last_login": None,
                                          "must_change": bool(body.get("must_change", True))}
            self.save("user.create", f"Utworzono konto {username} ({ROLE_LABELS[role]})")
            return {"ok": True}

        @r("PUT", "/api/users/{username}", role="admin")
        def user_update(body, query, username):
            u = self.db["users"].get(username)
            require(u, "Brak użytkownika", 404)
            if "display_name" in body:
                u["display_name"] = clean(body["display_name"], 100)
            if "role" in body and body["role"] != u["role"]:
                require(body["role"] in ROLES, "Niepoprawna rola")
                require(u["role"] != "admin" or admins_left(username) > 0, "Musi zostać co najmniej jeden administrator")
                u["role"] = body["role"]
            if "active" in body and bool(body["active"]) != u.get("active", True):
                if not body["active"]:
                    require(username != self.uname, "Nie możesz zablokować własnego konta")
                    require(u["role"] != "admin" or admins_left(username) > 0, "Musi zostać co najmniej jeden administrator")
                    u["active"] = False
                    V.remove_slot(username)
                    self.kill_sessions(username)
                else:
                    raise ApiError(400, "Aby odblokować konto, ustaw nowe hasło tymczasowe")
            self.save("user.update", f"Zmieniono konto {username}")
            return {"ok": True}

        @r("POST", "/api/users/{username}/password", role="admin")
        def user_reset(body, query, username):
            u = self.db["users"].get(username)
            require(u, "Brak użytkownika", 404)
            pw = body.get("password") or ""
            check_password(pw, username)
            V.set_password(username, pw)
            u["active"] = True
            u["must_change"] = username != self.uname
            self.fails.pop(username, None)
            self.kill_sessions(username)
            self.save("user.reset", f"Ustawiono hasło tymczasowe dla {username}")
            return {"ok": True}

        @r("DELETE", "/api/users/{username}", role="admin")
        def user_delete(body, query, username):
            u = self.db["users"].get(username)
            require(u, "Brak użytkownika", 404)
            require(username != self.uname, "Nie możesz usunąć własnego konta")
            require(u["role"] != "admin" or admins_left(username) > 0, "Musi zostać co najmniej jeden administrator")
            V.remove_slot(username)
            self.kill_sessions(username)
            del self.db["users"][username]
            self.save("user.delete", f"Usunięto konto {username}")
            return {"ok": True}

        # ---------------- dziennik zmian
        @r("GET", "/api/audit", role="viewer")
        def audit(body, query):
            ent = query.get("entity")
            usr = query.get("user")
            typ = query.get("type")
            q = (query.get("q") or "").lower()
            dfrom, dto = query.get("from") or "", query.get("to") or ""
            limit = min(int(query.get("limit") or 200), 5000)
            offset = int(query.get("offset") or 0)
            out = []
            for e in reversed(V.audit_entries):
                if e.get("corrupt"):
                    if not (ent or usr or typ or q):
                        out.append(e)
                    continue
                if usr and e.get("user") != usr:
                    continue
                if dfrom and e["ts"][:10] < dfrom or dto and e["ts"][:10] > dto:
                    continue
                ch = e.get("changes") or []
                if ent:
                    ch = [c for c in ch if c["id"] == ent or c["id"].startswith(ent + "|") or c["id"].endswith("|" + ent)]
                    if not ch:
                        continue
                if typ:
                    if typ == "auth":
                        if not e["action"].startswith(("auth.", "vault.")):
                            continue
                    else:
                        ch = [c for c in ch if c["type"] == typ]
                        if not ch:
                            continue
                if q and q not in json.dumps(e, ensure_ascii=False).lower():
                    continue
                out.append(dict(e, changes=ch) if (ent or typ) else e)
            total = len(out)
            names = {k: (x.get("display_name") or k) for k, x in self.db["users"].items()}
            return {"entries": out[offset: offset + limit], "total": total, "names": names,
                    "users": sorted({e.get("user") for e in V.audit_entries if e.get("user")})}

        @r("GET", "/api/audit/verify", role="viewer")
        def audit_verify(body, query):
            return V.verify_chain()

        @r("GET", "/api/meta")
        def meta(body, query):
            return {"settings": self.db["settings"], "triage": TRIAGE, "product_status": PRODUCT_STATUS,
                    "status_labels": E.LABELS, "exposure": E.EXPOSURE_LABELS,
                    "fields": [{"id": f, "label": l} for f, l in I.FIELDS], "today": today(),
                    "me": self.me(self.user), "roles": ROLE_LABELS, "app": APP_NAME, "about": ABOUT,
                    "teams": self.db["settings"].get("teams", []), "team_rule_fields": E.TEAM_RULE_FIELDS,
                    "group_fields": E.GROUP_FIELDS, "risk_labels": E.RISK_LABELS,
                    "ticket_defaults": {"subject": T.DEFAULT_SUBJECT, "template": T.DEFAULT_TEMPLATE,
                                        "placeholders": T.PLACEHOLDERS},
                    "companies": sorted({h.get("company") for h in self.db["hosts"].values() if h.get("company")})}

        @r("GET", "/api/dashboard")
        def dashboard(body, query):
            key = (id(self.db), self.vault.rev, date.today().isoformat())
            if self._dash and self._dash[0] == key:
                return self._dash[1]
            res = E.dashboard(self.db)
            self._dash = (key, res)
            return res

        @r("GET", "/api/counts")
        def counts(body, query):
            db = self.db
            pending = sum(1 for c in db["kev"]["entries"] if not (db["cves"].get(c, {}).get("triage") or {}).get("decision"))
            today_ = date.today()
            exc = sum(1 for e in db["exceptions"] if e.get("active", True) and E.parse_date(e.get("review_at"))
                      and E.parse_date(e.get("review_at")) < today_)
            return {"kev_pending": pending, "exceptions_overdue": exc}

        # ---------------- wyszukiwanie
        @r("GET", "/api/search")
        def search(body, query):
            q = (query.get("q") or "").strip().lower()
            require(len(q) >= 2, "Wpisz co najmniej 2 znaki")
            nq = E.norm(q)
            db, st = self.db, self.db["settings"]
            usage = E.product_usage(db)

            def hit(*vals):
                for v in vals:
                    s = str(v or "").lower()
                    if q in s or (nq and len(nq) >= 3 and nq in E.norm(s)):
                        return True
                return False
            prods = [self.product_row(p, usage, {}) for p in db["products"].values()
                     if hit(p["name"], p.get("vendor"), p.get("notes"), *(p.get("aliases") or []))]
            def cve_texts(c):
                k = db["kev"]["entries"].get(c["id"]) or {}
                names = [db["products"].get(r["product_id"], {}).get("name") for r in c.get("rules", [])]
                return [c["id"], c.get("title"), c.get("notes"), (c.get("triage") or {}).get("note"),
                        c.get("description"), k.get("vendorProject"), k.get("product"), k.get("vulnerabilityName"),
                        *names]
            cves = [self.cve_row(c) for c in db["cves"].values() if hit(*cve_texts(c))]
            hosts = [{k: h.get(k) for k in ("id", "hostname", "ip", "owner", "os", "type", "exposure", "company")}
                     for h in db["hosts"].values()
                     if hit(h.get("hostname"), h.get("ip"), h.get("owner"), h.get("admin"), h.get("notes"),
                            h.get("os"), h.get("user"), h.get("company"))]
            known = {c["id"] for c in cves}
            kev = []
            for e in db["kev"]["entries"].values():
                if e["cveID"] in known:
                    continue
                if hit(e["cveID"], e.get("vendorProject"), e.get("product"), e.get("vulnerabilityName")):
                    kev.append({"cve": e["cveID"], "vendor": e.get("vendorProject"), "product": e.get("product"),
                                "name": e.get("vulnerabilityName"), "dateAdded": e.get("dateAdded")})
            kmap = []
            for key, m in db["kev_product_map"].items():
                if hit(m.get("label"), m.get("note")):
                    kmap.append({**m, "stale": E.staleness(m.get("verified_at"), st)})
            return {"products": prods[:50], "cves": cves[:50], "hosts": hosts[:50], "kev": kev[:50],
                    "kev_products": kmap[:30]}

        # ---------------- produkty
        @r("GET", "/api/products")
        def products(body, query):
            usage = E.product_usage(self.db)
            cc = {}
            for c in self.db["cves"].values():
                for rr in c.get("rules", []):
                    cc[rr["product_id"]] = cc.get(rr["product_id"], 0) + 1
            rows = [self.product_row(p, usage, cc) for p in self.db["products"].values()]
            rows.sort(key=lambda x: x["name"].lower())
            return {"products": rows}

        def apply_product(p, b):
            if "name" in b:
                n = clean(b["name"], 200)
                require(n, "Nazwa produktu jest wymagana")
                p["name"] = n
            for f in ("vendor", "category", "notes"):
                if f in b:
                    p[f] = clean(b[f])
            if "team" in b:
                tid = clean(b["team"], 60)
                require(not tid or any(t["id"] == tid for t in self.db["settings"].get("teams", [])),
                        "Nieznany zespół")
                p["team"] = tid
            if "aliases" in b:
                al = b["aliases"]
                if isinstance(al, str):
                    al = [a for a in re.split(r"[,;\n]", al)]
                p["aliases"] = [clean(a, 200) for a in al if clean(a)][:30]
            if "status" in b:
                require(b["status"] in PRODUCT_STATUS, "Niepoprawny status")
                if b["status"] != p.get("status"):
                    p["verified_at"], p["verified_by"] = today(), self.uname
                p["status"] = b["status"]
            if b.get("verify"):
                p["verified_at"], p["verified_by"] = today(), self.uname
            p["updated_at"] = stamp()

        @r("POST", "/api/products")
        def product_create(body, query):
            name = clean(body.get("name"), 200)
            require(name, "Nazwa produktu jest wymagana")
            require(E.norm(name) not in I.product_index(self.db), "Produkt o tej nazwie (lub aliasie) już istnieje")
            pid = I.new_id("p")
            p = {"id": pid, "name": name, "vendor": "", "aliases": [], "category": "", "status": "unknown",
                 "notes": "", "verified_at": today(), "created_at": now_iso()}
            apply_product(p, body)
            self.db["products"][pid] = p
            self.save("product.create", name)
            return {"id": pid}

        @r("PUT", "/api/products/{pid}")
        def product_update(body, query, pid):
            p = self.db["products"].get(pid)
            require(p, "Brak produktu", 404)
            self.check_version(p, body)
            apply_product(p, body)
            self.save("product.update", p["name"])
            return {"ok": True}

        @r("DELETE", "/api/products/{pid}", heavy=True)
        def product_delete(body, query, pid):
            p = self.db["products"].pop(pid, None)
            require(p, "Brak produktu", 404)
            for k in [k for k, i in self.db["inventory"].items() if i["product_id"] == pid]:
                del self.db["inventory"][k]
            for c in self.db["cves"].values():
                c["rules"] = [x for x in c.get("rules", []) if x["product_id"] != pid]
            self.save("product.delete", p["name"], backup=True)
            return {"ok": True}

        @r("POST", "/api/products/{pid}/merge", heavy=True)
        def product_merge(body, query, pid):
            into = body.get("into")
            require(pid != into, "Nie można scalić produktu z samym sobą")
            src, dst = self.db["products"].get(pid), self.db["products"].get(into)
            require(src and dst, "Brak produktu", 404)
            dst["aliases"] = sorted(set((dst.get("aliases") or []) + [src["name"]] + (src.get("aliases") or [])))
            for k, inst in list(self.db["inventory"].items()):
                if inst["product_id"] == pid:
                    del self.db["inventory"][k]
                    base = E.inv_key(inst["host_id"], pid)
                    nk = E.inv_key(inst["host_id"], into) + (k[len(base):] if k.startswith(base) else "")
                    if nk not in self.db["inventory"]:
                        self.db["inventory"][nk] = dict(inst, product_id=into, key=nk)
            for c in self.db["cves"].values():
                rules = c.get("rules", [])
                s = next((x for x in rules if x["product_id"] == pid), None)
                if s:
                    d = next((x for x in rules if x["product_id"] == into), None)
                    if d:
                        have = {b.get("branch") for b in d["branches"]}
                        d["branches"] += [b for b in s["branches"] if b.get("branch") not in have]
                        rules.remove(s)
                    else:
                        s["product_id"] = into
            red = self.db.setdefault("product_redirects", {})
            for k_, v_ in list(red.items()):
                if v_ == pid:
                    red[k_] = into
            red[pid] = into
            for e in self.db["exceptions"]:
                if e.get("product_id") == pid:
                    e["product_id"] = into
            if src.get("notes"):
                dst["notes"] = ((dst.get("notes") or "") + "\n" + src["notes"]).strip()
            del self.db["products"][pid]
            self.save("product.merge", f"{src['name']} -> {dst['name']}", backup=True)
            return {"ok": True}

        @r("GET", "/api/products/{pid}/report")
        def product_report(body, query, pid):
            require(pid in self.db["products"], "Brak produktu", 404)
            return E.product_report(self.db, pid, self.load_obs)

        # ---------------- hosty
        @r("GET", "/api/hosts")
        def hosts(body, query):
            ctx = E.Ctx(self.db)
            rows = [E.host_summary_row(ctx, h) for h in self.db["hosts"].values()]
            rows.sort(key=lambda h: (h["hostname"] or "").lower())
            return {"hosts": rows}

        HOST_FIELDS = ("hostname", "ip", "type", "os", "os_version", "environment", "owner", "admin", "user",
                       "location", "criticality", "exposure", "notes", "company", "team")
        BULK_FIELDS = ("company", "team", "exposure", "environment", "owner", "admin", "location", "criticality", "type")

        def check_team(v):
            require(not v or any(t["id"] == v for t in self.db["settings"].get("teams", [])), "Nieznany zespół")

        @r("PUT", "/api/hosts/bulk")
        def hosts_bulk(body, query):
            ids = [i for i in body.get("ids") or [] if i in self.db["hosts"]]
            require(ids, "Nie zaznaczono hostów")
            fields = {k: clean(v, 200) for k, v in (body.get("fields") or {}).items() if k in BULK_FIELDS}
            require(fields, "Wybierz pole do zmiany")
            if "team" in fields:
                check_team(fields["team"])
            for hid in ids:
                h = self.db["hosts"][hid]
                h.update(fields)
                h["updated_at"] = stamp()
            self.save("host.bulk", f"{len(ids)} hostów: " + ", ".join(f"{k}={v or '—'}" for k, v in fields.items()))
            return {"ok": True, "updated": len(ids)}

        @r("GET", "/api/companies")
        def companies(body, query):
            cnt = {}
            for h in self.db["hosts"].values():
                c = h.get("company") or ""
                cnt[c] = cnt.get(c, 0) + 1
            return {"companies": [{"name": k, "hosts": v} for k, v in sorted(cnt.items(), key=lambda x: x[0].lower())]}

        @r("POST", "/api/teams/test", role="viewer")
        def teams_test(body, query):
            """Ile hostów trafia do którego zespołu przy podanych (lub zapisanych) regułach."""
            db = dict(self.db)
            db["settings"] = dict(self.db["settings"])
            if "team_rules" in body:
                db["settings"]["team_rules"] = body["team_rules"]
            if "teams" in body:
                db["settings"]["teams"] = body["teams"]
            res = E.TeamResolver(db)
            per_rule, per_team, examples = {}, {}, {}
            for h in db["hosts"].values():
                tid, src = res.host_team(h)
                per_team[tid] = per_team.get(tid, 0) + 1
                per_rule[src] = per_rule.get(src, 0) + 1
                examples.setdefault(tid, [])
                if len(examples[tid]) < 5:
                    examples[tid].append(h.get("hostname"))
            return {"per_team": [{"team": k, "label": res.label(k), "hosts": v, "examples": examples.get(k, [])}
                                 for k, v in sorted(per_team.items(), key=lambda x: -x[1])],
                    "per_rule": per_rule}

        @r("POST", "/api/hosts")
        def host_create(body, query):
            hn = clean(body.get("hostname"), 255)
            require(hn, "Nazwa hosta jest wymagana")
            hid = I.new_id("h")
            h = {"id": hid, "mitigations": [], "created_at": now_iso(), "updated_at": now_iso()}
            for f in HOST_FIELDS:
                h[f] = clean(body.get(f))
            check_team(h.get("team"))
            self.db["hosts"][hid] = h
            self.save("host.create", hn)
            return {"id": hid}

        @r("GET", "/api/hosts/{hid}/report")
        def host_report(body, query, hid):
            require(hid in self.db["hosts"], "Brak hosta", 404)
            return E.host_report(self.db, hid)

        @r("PUT", "/api/hosts/{hid}")
        def host_update(body, query, hid):
            h = self.db["hosts"].get(hid)
            require(h, "Brak hosta", 404)
            self.check_version(h, body)
            for f in HOST_FIELDS:
                if f in body:
                    h[f] = clean(body[f])
            require(h.get("hostname"), "Nazwa hosta jest wymagana")
            check_team(h.get("team"))
            h["updated_at"] = stamp()
            self.save("host.update", h["hostname"])
            return {"ok": True}

        @r("DELETE", "/api/hosts/{hid}", heavy=True)
        def host_delete(body, query, hid):
            h = self.db["hosts"].pop(hid, None)
            require(h, "Brak hosta", 404)
            for k in [k for k, i in self.db["inventory"].items() if i["host_id"] == hid]:
                del self.db["inventory"][k]
            self.db["exceptions"] = [e for e in self.db["exceptions"] if e.get("host_id") != hid]
            self.save("host.delete", h["hostname"], backup=True)
            return {"ok": True}

        @r("POST", "/api/hosts/{hid}/mitigations")
        def mitig_add(body, query, hid):
            h = self.db["hosts"].get(hid)
            require(h, "Brak hosta", 404)
            group, cve_id = clean(body.get("group"), 100), clean(body.get("cve_id"), 40).upper()
            require(group or cve_id, "Wybierz grupę podatności albo konkretne CVE")
            m = {"id": I.new_id("m"), "group": group or None, "cve_id": cve_id or None,
                 "product_id": body.get("product_id") or None, "description": clean(body.get("description")),
                 "added_at": today(), "added_by": self.uname}
            h.setdefault("mitigations", []).append(m)
            self.save("host.mitigation.add", f"{h['hostname']}: {group or cve_id}")
            return {"ok": True}

        @r("DELETE", "/api/hosts/{hid}/mitigations/{mid}")
        def mitig_del(body, query, hid, mid):
            h = self.db["hosts"].get(hid)
            require(h, "Brak hosta", 404)
            h["mitigations"] = [m for m in h.get("mitigations", []) if m["id"] != mid]
            self.save("host.mitigation.del", h["hostname"])
            return {"ok": True}

        @r("POST", "/api/hosts/{hid}/installations", heavy=True)
        def inst_add(body, query, hid):
            h = self.db["hosts"].get(hid)
            require(h, "Brak hosta", 404)
            pid = body.get("product_id")
            if not pid:
                name = clean(body.get("product"), 200)
                require(name, "Podaj produkt")
                pid, _ = self.find_or_create_product(name)
            require(pid in self.db["products"], "Brak produktu", 404)
            k = body.get("key") if body.get("key") in self.db["inventory"] else E.inv_key(hid, pid)
            old = self.db["inventory"].get(k) or {}
            ver = clean(body.get("version"), 100)
            hist = list(old.get("history", [])) + [{"import_id": "manual", "version": ver, "date": today()}]
            self.db["inventory"][k] = {"key": k, "host_id": hid, "product_id": pid, "version": ver,
                                       "reported_cves": old.get("reported_cves", []),
                                       "first_seen": old.get("first_seen", now_iso()), "last_seen": now_iso(),
                                       "import_id": "manual", "removed": False, "history": hist[-20:]}
            p = self.db["products"][pid]
            if p.get("status") != "used":
                p["status"], p["verified_at"] = "used", today()
            self.save("inventory.set", f"{h['hostname']} / {p['name']} {ver}")
            return {"ok": True}

        @r("DELETE", "/api/inventory/{hid}/{pid}", heavy=True)
        def inst_remove(body, query, hid, pid):
            key = query.get("key")
            keys = [key] if key else [k for k, i in self.db["inventory"].items()
                                      if i["host_id"] == hid and i["product_id"] == pid and not i.get("removed")]
            keys = [k for k in keys if k in self.db["inventory"]]
            require(keys, "Brak wpisu", 404)
            for k in keys:
                self.db["inventory"][k]["removed"], self.db["inventory"][k]["removed_at"] = True, now_iso()
            self.save("inventory.remove", ", ".join(keys))
            return {"ok": True}

        # ---------------- CVE
        @r("GET", "/api/cves")
        def cves(body, query):
            om = self.open_by_cve()
            rows = [self.cve_row(c, om) for c in self.db["cves"].values()]
            rows.sort(key=lambda x: x["id"], reverse=True)
            return {"cves": rows}

        @r("GET", "/api/cves/{cid}")
        def cve_get(body, query, cid):
            cid = cid.upper()
            c = self.db["cves"].get(cid)
            k = self.db["kev"]["entries"].get(cid)
            if not c:
                return {"exists": False, "cve": {"id": cid, "title": (k or {}).get("vulnerabilityName", ""),
                                                 "description": (k or {}).get("shortDescription", ""),
                                                 "rules": [], "groups": [], "triage": {}},
                        "kev": k, "impact": {"rows": [], "counts": {}}}
            prods = {r["product_id"]: self.db["products"].get(r["product_id"], {}).get("name", "?")
                     for r in c.get("rules", [])}
            return {"exists": True, "cve": c, "kev": k, "impact": E.cve_impact(self.db, cid), "product_names": prods,
                    "stale": E.staleness((c.get("triage") or {}).get("verified_at"), self.db["settings"]),
                    "tickets": [t for t in self.db.get("tickets", []) if t.get("cve") == cid]}

        @r("PUT", "/api/cves/{cid}")
        def cve_put(body, query, cid):
            c = self.ensure_cve(cid)
            self.check_version(c, body)
            for f in ("title", "description", "notes", "severity"):
                if f in body:
                    c[f] = clean(body[f], 8000)
            if "cvss" in body:
                try:
                    c["cvss"] = float(body["cvss"]) if body["cvss"] not in (None, "") else None
                except (TypeError, ValueError):
                    raise ApiError(400, "CVSS musi być liczbą")
            if "groups" in body:
                c["groups"] = [clean(g, 100) for g in body["groups"] or [] if clean(g)]
            if "no_auto_exposure" in body:
                c["no_auto_exposure"] = bool(body["no_auto_exposure"])
            if "assessment" in body and isinstance(body["assessment"], dict):
                a = body["assessment"]
                risk = a.get("risk") or None
                require(risk is None or risk in E.RISK_LABELS, "Niepoprawny poziom ryzyka")
                score = a.get("score")
                if score in (None, ""):
                    score = None
                else:
                    try:
                        score = round(float(str(score).replace(",", ".")), 1)
                    except ValueError:
                        raise ApiError(400, "Ocena musi być liczbą 0–10")
                    require(0 <= score <= 10, "Ocena musi być w zakresie 0–10")
                dl = clean(a.get("deadline"), 10) or None
                require(dl is None or E.parse_date(dl), "Niepoprawna data terminu")
                new = {"risk": risk, "score": score, "impact": clean(a.get("impact"), 8000),
                       "exploitation": clean(a.get("exploitation"), 8000),
                       "recommendation": clean(a.get("recommendation"), 8000), "deadline": dl}
                old = c.get("assessment") or {}
                if any(new.get(k) != old.get(k) for k in new):
                    new.update(assessed_by=self.uname, assessed_at=today())
                    c["assessment"] = new
            if "rules" in body:
                rules = []
                for rr in body["rules"] or []:
                    pid = rr.get("product_id")
                    if not pid and rr.get("product"):
                        pid, _ = self.find_or_create_product(clean(rr["product"], 200), status="unknown")
                    require(pid in self.db["products"], "Nieznany produkt w regule")
                    brs = []
                    for b in rr.get("branches") or []:
                        st = b.get("state") or ("fix" if b.get("fixed") else "nofix")
                        require(st in ("fix", "nofix", "safe"), "Niepoprawny stan gałęzi")
                        require(st != "fix" or clean(b.get("fixed")), "Podaj wersję naprawioną dla gałęzi "
                                + clean(b.get("branch") or "*"))
                        brs.append({"branch": clean(b.get("branch") or "*", 60), "introduced": clean(b.get("introduced"), 60),
                                    "fixed": clean(b.get("fixed"), 100) if st == "fix" else "", "state": st,
                                    "note": clean(b.get("note"), 500), "source": b.get("source") or "manual"})
                    un = rr.get("unlisted") or "review"
                    require(un in ("review", "vulnerable", "not_affected"), "Niepoprawna opcja gałęzi nieopisanych")
                    rules.append({"product_id": pid, "branches": brs, "unlisted": un})
                require(len({x["product_id"] for x in rules}) == len(rules), "Produkt powtarza się w regułach")
                c["rules"] = rules
            if body.get("triage"):
                t = body["triage"]
                require(t.get("decision") in TRIAGE, "Niepoprawna decyzja")
                c["triage"] = {"decision": t["decision"], "note": clean(t.get("note")), "verified_at": today(),
                              "verified_by": self.uname}
            c["updated_at"] = stamp()
            self.save("cve.save", c["id"])
            return {"ok": True, "id": c["id"]}

        @r("DELETE", "/api/cves/{cid}")
        def cve_delete(body, query, cid):
            c = self.db["cves"].pop(cid.upper(), None)
            require(c, "Brak CVE", 404)
            self.save("cve.delete", cid, backup=True)
            return {"ok": True}

        @r("POST", "/api/cves/{cid}/triage")
        def cve_triage(body, query, cid):
            c = self.ensure_cve(cid)
            require(body.get("decision") in TRIAGE, "Niepoprawna decyzja")
            c["triage"] = {"decision": body["decision"], "note": clean(body.get("note")), "verified_at": today(),
                          "verified_by": self.uname}
            c["updated_at"] = stamp()
            self.save("cve.triage", f"{c['id']}: {body['decision']}")
            return {"ok": True}

        @r("GET", "/api/cves/{cid}/nvd")
        def cve_nvd(body, query, cid):
            try:
                raw = feeds.fetch_nvd(cid.upper())
            except ValueError as e:
                raise ApiError(404, str(e))
            except Exception as e:  # noqa: BLE001
                raise ApiError(502, f"Nie udało się pobrać danych z NVD ({e.__class__.__name__}: {e}). "
                                    f"Serwer może nie mieć dostępu do Internetu.")
            return feeds.parse_nvd(self.db, raw)

        # ---------------- KEV
        @r("GET", "/api/kev")
        def kev_list(body, query):
            db, st = self.db, self.db["settings"]
            view = query.get("view") or "pending"
            q = (query.get("q") or "").lower().strip()
            limit = min(int(query.get("limit") or 100), 500)
            usage = E.product_usage(db)
            items = []
            for e in db["kev"]["entries"].values():
                c = db["cves"].get(e["cveID"]) or {}
                t = c.get("triage") or {}
                dec = t.get("decision")
                if view == "pending" and dec and dec != "pending":
                    continue
                if view == "affected" and dec not in ("affected", "used_safe"):
                    continue
                if view == "not_ours" and dec not in ("not_used", "not_applicable"):
                    continue
                if view == "stale" and not (dec and E.staleness(t.get("verified_at"), st)["level"] in ("warn", "crit")):
                    continue
                if q and not any(q in str(e.get(f) or "").lower() for f in
                                 ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")):
                    continue
                items.append((e, c, t))
            items.sort(key=lambda x: (x[0].get("dateAdded") or "", x[0]["cveID"]), reverse=True)
            total = len(items)
            out = []
            for e, c, t in items[:limit]:
                key = E.kev_key(e.get("vendorProject"), e.get("product"))
                prior = db["kev_product_map"].get(key)
                out.append({
                    "cve": e["cveID"], "vendor": e.get("vendorProject"), "product": e.get("product"),
                    "name": e.get("vulnerabilityName"), "description": e.get("shortDescription"),
                    "action": e.get("requiredAction"), "dateAdded": e.get("dateAdded"), "dueDate": e.get("dueDate"),
                    "ransomware": e.get("knownRansomwareCampaignUse") == "Known",
                    "triage": t, "stale": E.staleness(t.get("verified_at"), st) if t.get("decision") else None,
                    "has_rules": bool(c.get("rules")),
                    "candidates": E.kev_candidates(db, e.get("vendorProject"), e.get("product"), usage,
                                                   linked=set((prior or {}).get("product_ids") or [])),
                    "prior": ({**prior, "stale": E.staleness(prior.get("verified_at"), st)} if prior else None),
                })
            return {"items": out, "total": total, "updated_at": db["kev"].get("updated_at"),
                    "catalog_size": len(db["kev"]["entries"]), "catalog_version": db["kev"].get("catalog_version")}

        @r("POST", "/api/kev/fetch")
        def kev_fetch(body, query):
            try:
                data = feeds.fetch_kev()
            except Exception as e:  # noqa: BLE001
                raise ApiError(502, f"Nie udało się pobrać KEV z CISA ({e.__class__.__name__}: {e}). "
                                    f"Pobierz plik JSON ręcznie i wgraj go przyciskiem obok.")
            res = feeds.merge_kev(self.db, data)
            self.save("kev.fetch", f"+{res['added']}")
            return res

        @r("POST", "/api/kev/upload")
        def kev_upload(body, query):
            data = body.get("data")
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except ValueError:
                    raise ApiError(400, "Plik nie jest poprawnym JSON")
            require(isinstance(data, dict), "Brak danych")
            try:
                res = feeds.merge_kev(self.db, data)
            except ValueError as e:
                raise ApiError(400, str(e))
            self.save("kev.upload", f"+{res['added']}")
            return res

        @r("POST", "/api/kev/{cid}/triage")
        def kev_triage(body, query, cid):
            db = self.db
            e = db["kev"]["entries"].get(cid.upper())
            require(e, "Brak wpisu KEV", 404)
            dec = body.get("decision")
            require(dec in TRIAGE, "Niepoprawna decyzja")
            c = self.ensure_cve(cid)
            note = clean(body.get("note"))
            c["triage"] = {"decision": dec, "note": note, "verified_at": today(), "verified_by": self.uname}
            c["updated_at"] = stamp()
            pids = [p for p in body.get("product_ids") or [] if p in db["products"]]
            label = f"{e.get('vendorProject', '')} {e.get('product', '')}".strip()
            if dec == "not_used" and body.get("register_not_used", True) and not pids:
                pid, created = self.find_or_create_product(e.get("product") or label, e.get("vendorProject", ""),
                                                           status="not_used")
                p = db["products"][pid]
                if not created and p.get("status") == "used":
                    raise ApiError(409, f"Produkt „{p['name']}” jest oznaczony jako UŻYWANY "
                                        f"({E.product_usage(db).get(pid, 0)} hostów). Zmień decyzję albo status produktu.")
                p["status"], p["verified_at"], p["verified_by"] = "not_used", today(), self.uname
                if note:
                    p["notes"] = ((p.get("notes") or "") + f"\n[{today()}] {cid}: {note}").strip()
                pids = [pid]
            elif dec == "not_used":
                for pid in pids:
                    db["products"][pid]["status"] = "not_used"
                    db["products"][pid]["verified_at"] = today()
            if dec in ("affected", "used_safe", "pending"):
                for pid in pids:
                    if not any(r["product_id"] == pid for r in c["rules"]):
                        c["rules"].append({"product_id": pid, "branches": [], "unlisted": "review"})
                    p = db["products"][pid]
                    if p.get("status") != "used":
                        p["status"], p["verified_at"] = "used", today()
            db["kev_product_map"][E.kev_key(e.get("vendorProject"), e.get("product"))] = {
                "label": label, "decision": dec, "product_ids": pids, "verified_at": today(), "note": note,
                "verified_by": self.uname,
                "last_cve": c["id"]}
            self.save("kev.triage", f"{c['id']}: {dec}")
            return {"ok": True, "product_ids": pids}

        # ---------------- wyjątki
        @r("GET", "/api/exceptions")
        def exc_list(body, query):
            db = self.db
            out = []
            for e in db["exceptions"]:
                rd = E.parse_date(e.get("review_at"))
                out.append({**e, "hostname": db["hosts"].get(e.get("host_id") or "", {}).get("hostname"),
                            "product": db["products"].get(e.get("product_id") or "", {}).get("name"),
                            "overdue": bool(rd and rd < date.today())})
            out.sort(key=lambda e: (not e["overdue"], e.get("review_at") or "9999"))
            return {"exceptions": out}

        def apply_exc(e, b):
            for f in ("host_id", "product_id"):
                if f in b:
                    e[f] = b[f] or None
            if "cve_id" in b:
                e["cve_id"] = clean(b["cve_id"], 40).upper() or None
            for f in ("reason", "contact", "decided_by", "compensating"):
                if f in b:
                    e[f] = clean(b[f])
            if "review_at" in b:
                e["review_at"] = clean(b["review_at"], 10) or None
            if "active" in b:
                e["active"] = bool(b["active"])
            require(e.get("host_id") or e.get("product_id"), "Wyjątek musi dotyczyć hosta i/lub produktu")
            require(e.get("reason"), "Podaj powód (np. informację od właściciela)")

        @r("POST", "/api/exceptions")
        def exc_create(body, query):
            e = {"id": I.new_id("x"), "created_at": today(), "created_by": self.uname, "active": True}
            apply_exc(e, body)
            self.db["exceptions"].append(e)
            self.save("exception.create", e["reason"][:80])
            return {"id": e["id"]}

        @r("PUT", "/api/exceptions/{xid}")
        def exc_update(body, query, xid):
            e = next((x for x in self.db["exceptions"] if x["id"] == xid), None)
            require(e, "Brak wyjątku", 404)
            apply_exc(e, body)
            e["updated_at"], e["updated_by"] = today(), self.uname
            self.save("exception.update", xid)
            return {"ok": True}

        @r("DELETE", "/api/exceptions/{xid}")
        def exc_delete(body, query, xid):
            n = len(self.db["exceptions"])
            self.db["exceptions"] = [x for x in self.db["exceptions"] if x["id"] != xid]
            require(len(self.db["exceptions"]) < n, "Brak wyjątku", 404)
            self.save("exception.delete", xid)
            return {"ok": True}

        # ---------------- import
        def cached(token):
            c = self.import_cache.get(token or "")
            require(c, "Sesja importu wygasła — wklej dane ponownie", 410)
            return c

        @r("POST", "/api/import/analyze")
        def imp_analyze(body, query):
            try:
                table = I.parse_table(body.get("text"), body.get("xlsx_b64"), body.get("sheet"))
            except ValueError as e:
                raise ApiError(400, str(e))
            except Exception as e:  # noqa: BLE001
                raise ApiError(400, f"Nie udało się odczytać pliku: {e}")
            for k in [k for k, v in self.import_cache.items() if v["ts"] < time.time() - 7200]:
                del self.import_cache[k]
            while len(self.import_cache) >= 10:
                self.import_cache.pop(next(iter(self.import_cache)))
            tok = secrets.token_urlsafe(12)
            self.import_cache[tok] = {"table": table, "ts": time.time()}
            a = I.analyze(self.db, table)
            mapping = [c["field"] for c in a["columns"]]
            prev = imp_run(table, mapping, a["split_product_version"], body.get("options") or {}, None, False)
            prof = self.db["mapping_profiles"].get(a["signature"]) if a["profile_used"] else None
            return {"token": tok, **a, "rows": len(table["rows"]), "sheets": table["sheets"],
                    "has_header": table["has_header"], "warnings": table["warnings"], "preview": prev,
                    "profile_options": (prof or {}).get("options"), "profile_split": (prof or {}).get("split")}

        def imp_opts(opts):
            st = self.db["settings"]
            o = {"update_hosts": True, "replace_scope": False, "unknown": "create",
                 "normalize": st.get("import_normalize", True), "os_as_app": st.get("import_os_as_app", True)}
            o.update({k: v for k, v in (opts or {}).items() if k in o})
            require(o["unknown"] in ("create", "skip"), "Niepoprawna opcja")
            return o

        def imp_run(table, mapping, split, opts, name, commit):
            require(isinstance(mapping, list) and len(mapping) == len(table["headers"]), "Niepoprawne mapowanie")
            recs = I.build_records(table, mapping, split)
            opts = imp_opts(opts)
            if commit:
                self.vault.backup(reason="before-import")
                staged = I.stage(self.db)
                staged["settings"] = dict(self.db["settings"])
                res = I.apply_import(staged, recs, name, dict(opts, user=self.uname))
                self.db.update(staged)
                imp = self.db["imports"][-1]
                obs = imp.pop("observations", [])
                imp["installations"] = len(obs)
                imp["options"] = opts
                self.vault.write_observations(imp["id"], obs)
                keep = int(self.db["settings"].get("history_keep") or 24)
                live = [i for i in self.db["imports"] if not i.get("archived")]
                for old in live[:-keep] if len(live) > keep else []:
                    old["archived"] = True
                    self.vault.delete_observations(old["id"])
                return res
            staged = I.stage(self.db)
            staged["settings"] = dict(self.db["settings"])
            return I.apply_import(staged, recs, name, opts)

        @r("POST", "/api/import/preview")
        def imp_preview(body, query):
            c = cached(body.get("token"))
            return imp_run(c["table"], body.get("mapping"), bool(body.get("split")), body.get("options") or {},
                           None, False)

        @r("POST", "/api/import/commit", heavy=True)
        def imp_commit(body, query):
            c = cached(body.get("token"))
            mapping = body.get("mapping")
            require("product" in mapping or "hostname" in mapping or "ip" in mapping,
                    "Zmapuj co najmniej kolumnę hosta lub produktu")
            res = imp_run(c["table"], mapping, bool(body.get("split")), body.get("options") or {},
                          clean(body.get("name"), 200), True)
            if body.get("save_profile", True) and c["table"]["has_header"]:
                self.db["mapping_profiles"][I.signature(c["table"]["headers"])] = {
                    "mapping": mapping, "headers": c["table"]["headers"], "saved_at": now_iso(),
                    "options": imp_opts(body.get("options")), "split": bool(body.get("split"))}
            self.save("import.commit", f"{res['import_id']}: {res['stats']['records']} wierszy", backup=False)
            self.import_cache.pop(body.get("token"), None)
            return res

        @r("GET", "/api/imports")
        def imports(body, query):
            return {"imports": [{k: i.get(k) for k in ("id", "name", "created_at", "created_by", "rows",
                                                         "new_hosts", "new_products", "archived")}
                                | {"installations": i.get("installations", len(i.get("observations") or []))}
                                for i in reversed(self.db["imports"])]}

        @r("PUT", "/api/imports/{iid}")
        def import_rename(body, query, iid):
            imp = next((i for i in self.db["imports"] if i["id"] == iid), None)
            require(imp, "Brak importu", 404)
            imp["name"] = clean(body.get("name"), 200) or imp["name"]
            self.save("import.rename", iid)
            return {"ok": True}

        @r("GET", "/api/imports/compare")
        def imports_compare(body, query):
            ids = {i["id"] for i in self.db["imports"]}
            a, b = query.get("a"), query.get("b")
            require(a in ids and b in ids, "Wybierz dwa importy")
            imps = {i["id"]: i for i in self.db["imports"]}
            require(not imps[a].get("archived") and not imps[b].get("archived"),
                    "Szczegóły tego importu zostały zarchiwizowane (limit historii w ustawieniach)")
            return E.compare_imports(self.db, a, b, self.load_obs)

        # ---------------- raporty grupowane
        def report_params(b):
            group = b.get("group") or "company"
            require(group in E.GROUP_FIELDS, "Niepoprawne grupowanie")
            pids = [x for x in (b.get("product_ids") or ([b["product_id"]] if b.get("product_id") else []))
                    if x in self.db["products"]]
            cve = clean(b.get("cve_id"), 40).upper() or None
            if cve:
                require(cve in self.db["cves"], f"Brak {cve} w bazie — najpierw dodaj CVE i regułę wersji")
            filters = {k: clean(v, 200) for k, v in (b.get("filters") or {}).items()
                       if k in E.GROUP_FIELDS and v not in (None, "")}
            return dict(group=group, product_ids=pids or None, cve_id=cve, kev_only=bool(b.get("kev_only")),
                        only_open=b.get("only_open", True) is not False, filters=filters)

        def report_title(prm):
            parts = []
            if prm["product_ids"]:
                parts.append(", ".join(self.db["products"][x]["name"] for x in prm["product_ids"]))
            if prm["cve_id"]:
                parts.append(prm["cve_id"])
            if prm["kev_only"]:
                parts.append("tylko KEV")
            for k, v in prm["filters"].items():
                lbl = E.TeamResolver(self.db).label(v) if k == "team" else v
                parts.append(f"{E.GROUP_FIELDS[k]}: {lbl}")
            return f"Raport podatności wg: {E.GROUP_FIELDS[prm['group']].lower()}" + (
                " — " + " · ".join(parts) if parts else "")

        @r("POST", "/api/reports/grouped", role="viewer")
        def report_grouped(body, query):
            prm = report_params(body)
            rep_ = E.grouped_report(self.db, **prm)
            rep_["title"] = report_title(prm)
            limit = int(body.get("row_limit") or 3000)
            for g in rep_["groups"]:
                g["rows_total"] = len(g["rows"])
                g["rows"] = g["rows"][:limit]
            return rep_

        @r("POST", "/api/reports/grouped/xlsx", role="viewer")
        def report_xlsx(body, query):
            prm = report_params(body)
            rep_ = E.grouped_report(self.db, **prm)
            title = report_title(prm)
            try:
                data = X.grouped_xlsx(rep_, title)
            except ImportError:
                raise ApiError(500, "Brak biblioteki openpyxl na serwerze — eksport do Excela niedostępny")
            name = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"vulnbuster-raport-{prm['group']}-{today()}") + ".xlsx"
            return {"_binary": data, "_filename": name,
                    "_ctype": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}

        # ---------------- zgłoszenia do realizatorów
        @r("POST", "/api/tickets/preview", role="viewer")
        def tickets_preview(body, query):
            cve = clean(body.get("cve_id"), 40).upper() or None
            pid = body.get("product_id") or None
            require(cve or pid, "Wybierz CVE albo aplikację")
            if cve:
                require(cve in self.db["cves"], "Brak CVE w bazie")
            if pid:
                require(pid in self.db["products"], "Brak aplikacji")
            split = body.get("split") or "team"
            require(split in ("team", "team_company"), "Niepoprawny podział")
            out = T.build(self.db, cve_id=cve, product_id=pid, split=split)
            for t in out:
                t["rows"] = t["rows"][:500]
            return {"tickets": out, "scope": {"cve": cve, "product": pid,
                                              "product_name": (self.db["products"].get(pid) or {}).get("name")}}

        @r("POST", "/api/tickets/eml", role="viewer")
        def tickets_eml(body, query):
            subject = clean(body.get("subject"), 500)
            data = T.eml(clean(body.get("to"), 500), subject, str(body.get("body") or "")[:200000],
                         body.get("csv") or None, filename=clean(body.get("csv_name"), 100) or "hosty.csv",
                         sender=self.db["settings"].get("ticket_sender") or "")
            name = re.sub(r"[^A-Za-z0-9_.-]+", "_", subject)[:80] or "zgloszenie"
            return {"_binary": data, "_filename": name + ".eml", "_ctype": "message/rfc822"}

        @r("GET", "/api/tickets", role="viewer")
        def tickets_list(body, query):
            out = list(reversed(self.db.get("tickets", [])))
            if query.get("cve"):
                out = [t for t in out if t.get("cve") == query["cve"].upper()]
            if query.get("product"):
                out = [t for t in out if t.get("product") == query["product"]]
            return {"tickets": out[:500]}

        @r("POST", "/api/tickets")
        def tickets_create(body, query):
            cve = clean(body.get("cve_id"), 40).upper() or None
            pid = body.get("product_id") or None
            require(cve or pid, "Brak zakresu zgłoszenia")
            team = clean(body.get("team"), 60)
            t = {"id": I.new_id("t"), "cve": cve, "product": pid, "team": team,
                 "team_label": E.TeamResolver(self.db).label(team), "company": clean(body.get("company"), 200),
                 "ticket_no": clean(body.get("ticket_no"), 100), "subject": clean(body.get("subject"), 500),
                 "hosts": [h for h in body.get("hosts") or [] if h in self.db["hosts"]][:5000],
                 "deadline": clean(body.get("deadline"), 10) or None, "note": clean(body.get("note"), 2000),
                 "created_at": now_iso(), "created_by": self.uname}
            self.db.setdefault("tickets", []).append(t)
            self.save("ticket.create", f"{t['subject'][:120]} {('#' + t['ticket_no']) if t['ticket_no'] else ''}")
            return {"ok": True, "ticket": t}

        @r("DELETE", "/api/tickets/{tid}")
        def tickets_delete(body, query, tid):
            n = len(self.db.get("tickets", []))
            self.db["tickets"] = [t for t in self.db.get("tickets", []) if t["id"] != tid]
            require(len(self.db["tickets"]) < n, "Brak zgłoszenia", 404)
            self.save("ticket.delete", tid)
            return {"ok": True}

        # ---------------- ustawienia
        @r("GET", "/api/settings")
        def settings_get(body, query):
            return self.db["settings"]

        @r("PUT", "/api/settings", role="admin")
        def settings_put(body, query):
            st = self.db["settings"]
            for f in ("stale_warn_days", "stale_crit_days"):
                if f in body:
                    v = int(body[f])
                    require(1 <= v <= 3650, "Niepoprawna liczba dni")
                    st[f] = v
            if "groups" in body:
                groups, ids = [], set()
                for g in body["groups"]:
                    gid = clean(g.get("id"), 60) or E.norm(g.get("name"))[:40]
                    require(gid and gid not in ids, "Identyfikatory grup muszą być unikalne")
                    ids.add(gid)
                    groups.append({"id": gid, "name": clean(g.get("name"), 120) or gid,
                                   "description": clean(g.get("description"), 500)})
                st["groups"] = groups
            if "teams" in body:
                teams, ids = [], set()
                for t in body["teams"]:
                    name = clean(t.get("name"), 120)
                    if not name:
                        continue
                    tid = clean(t.get("id"), 40) or E.norm(name)[:40]
                    require(tid and tid not in ids and tid != E.UNASSIGNED, "Identyfikatory zespołów muszą być unikalne")
                    ids.add(tid)
                    em = clean(t.get("email"), 300)
                    require(not em or all(re.match(r"^[^@\s,;]+@[^@\s,;]+\.[a-z]{2,}$", x.strip(), re.I)
                                          for x in re.split(r"[,;]", em) if x.strip()), f"Niepoprawny e-mail: {em}")
                    teams.append({"id": tid, "name": name, "email": em, "description": clean(t.get("description"), 300)})
                st["teams"] = teams
            if "team_rules" in body:
                ids = {t["id"] for t in st.get("teams", [])}
                rules = []
                for rr in body["team_rules"]:
                    pat = clean(rr.get("pattern"), 500)
                    if not pat:
                        continue
                    require(rr.get("field") in E.TEAM_RULE_FIELDS, "Niepoprawne pole reguły")
                    require(rr.get("team") in ids, f"Nieznany zespół w regule: {rr.get('team')}")
                    rules.append({"field": rr["field"], "pattern": pat, "team": rr["team"]})
                st["team_rules"] = rules
            if "sla_days" in body:
                sla = {}
                for k_, v_ in (body["sla_days"] or {}).items():
                    require(k_ in E.RISK_LABELS, "Niepoprawny poziom ryzyka")
                    v_ = int(v_)
                    require(1 <= v_ <= 3650, "SLA: niepoprawna liczba dni")
                    sla[k_] = v_
                st["sla_days"] = sla
            for f, n in (("ticket_prefix", 40), ("ticket_subject", 500), ("ticket_template", 20000),
                         ("ticket_signature", 2000), ("ticket_sender", 300), ("import_ignore", 5000)):
                if f in body:
                    st[f] = clean(body[f], n) if f != "ticket_template" else str(body[f] or "")[:n]
            for f in ("import_normalize", "import_os_as_app"):
                if f in body:
                    st[f] = bool(body[f])
            if "history_keep" in body:
                v = int(body["history_keep"])
                require(2 <= v <= 500, "Historia importów: 2–500")
                st["history_keep"] = v
            # zespoły usunięte z listy — wyczyść odwołania
            ids = {t["id"] for t in st.get("teams", [])}
            for h in self.db["hosts"].values():
                if h.get("team") and h["team"] not in ids:
                    h["team"] = ""
            for p_ in self.db["products"].values():
                if p_.get("team") and p_["team"] not in ids:
                    p_["team"] = ""
            self.save("settings.update")
            return st



# ================================================================ HTTP
def make_handler(app: App):
    class H(BaseHTTPRequestHandler):
        server_version = f"VulnBuster/{__version__}"
        sys_version = ""

        def log_message(self, fmt, *args):
            if os.environ.get("VULNBUSTER_QUIET"):
                return
            super().log_message(fmt, *args)

        def _headers_common(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                             "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

        def _token(self):
            c = cookies.SimpleCookie(self.headers.get("Cookie") or "")
            return c["vb_session"].value if "vb_session" in c else None

        def _send_json(self, status, obj, set_cookie=None):
            data = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            if set_cookie is not None:
                self.send_header("Set-Cookie", set_cookie)
            self._headers_common()
            self.end_headers()
            self.wfile.write(data)

        def _cookie(self, tok, clear=False):
            sec = "; Secure" if app.secure_cookie else ""
            if clear:
                return f"vb_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{sec}"
            return f"vb_session={tok}; Path=/; HttpOnly; SameSite=Strict{sec}"

        def _static(self, path):
            if path in ("/", "/index.html"):
                path = "/index.html"
            elif not path.startswith("/static/"):
                path = "/index.html"
            else:
                path = path[len("/static"):]
            full = os.path.realpath(os.path.join(STATIC, path.lstrip("/")))
            if not full.startswith(os.path.realpath(STATIC)) or not os.path.isfile(full):
                self.send_error(404)
                return
            with open(full, "rb") as f:
                data = f.read()
            self.send_response(200)
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self._headers_common()
            self.end_headers()
            self.wfile.write(data)

        def _handle(self, method):
            u = urlparse(self.path)
            if not u.path.startswith("/api/"):
                if method == "GET":
                    return self._static(u.path)
                return self._send_json(405, {"error": "Metoda niedozwolona"})
            raw_tok = self._token()
            if method != "GET" and self.headers.get("X-Requested-With") != "vulnbuster":
                return self._send_json(403, {"error": "Brak nagłówka X-Requested-With"})
            # kopia zapasowa — odpowiedź binarna
            if u.path == "/api/backup" and method == "GET":
                with app.vault.lock:
                    u = app.session_user(raw_tok) if app.vault.unlocked else None
                if not u or u["role"] != "admin":
                    return self._send_json(403, {"error": "Kopię zapasową może pobrać tylko administrator"})
                data = app.vault.encrypted_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="vulnbuster-backup-{date.today().isoformat()}.json.enc"')
                self.send_header("Content-Length", str(len(data)))
                self._headers_common()
                self.end_headers()
                self.wfile.write(data)
                return
            body = {}
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send_json(413, {"error": "Za duże dane (limit 60 MB)"})
            if n:
                try:
                    body = json.loads(self.rfile.read(n).decode("utf-8"))
                except ValueError:
                    return self._send_json(400, {"error": "Niepoprawny JSON"})
            query = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                res = app.dispatch(method, u.path, query, body if isinstance(body, dict) else {}, raw_tok)
            except ApiError as e:
                cookie = self._cookie(None, clear=True) if e.status in (401, 423) and raw_tok else None
                return self._send_json(e.status, {"error": e.msg}, cookie)
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                return self._send_json(500, {"error": f"Błąd serwera: {e.__class__.__name__}: {e}"})
            if isinstance(res, dict) and "_binary" in res:
                data = res["_binary"]
                self.send_response(200)
                self.send_header("Content-Type", res.get("_ctype") or "application/octet-stream")
                fn = res.get("_filename") or "plik"
                self.send_header("Content-Disposition", f'attachment; filename="{fn}"')
                self.send_header("Content-Length", str(len(data)))
                self._headers_common()
                self.end_headers()
                self.wfile.write(data)
                return
            cookie = None
            if isinstance(res, dict) and "_session" in res:
                cookie = self._cookie(res.pop("_session"))
            if isinstance(res, dict) and res.pop("_logout", False):
                app.sessions.pop(raw_tok or "", None)
                cookie = self._cookie(None, clear=True)
            self._send_json(200, res, cookie)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_PUT(self):
            self._handle("PUT")

        def do_DELETE(self):
            self._handle("DELETE")

    return H


def serve(data_path, host="127.0.0.1", port=8443, certfile=None, keyfile=None):
    app = App(data_path, secure_cookie=bool(certfile))
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    scheme = "http"
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"{APP_NAME} {__version__} ({__license__}, © {__author__}): {scheme}://{host}:{port}  (dane: {app.vault.path})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return app
