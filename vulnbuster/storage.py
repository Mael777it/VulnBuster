# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Zaszyfrowany magazyn danych z kluczami per użytkownik + szyfrowany dziennik zmian.

Plik danych (JSON):
  {"format": "vulnbuster-vault", "v": 2, "file_id": b64,
   "slots": {slot_id: {"kdf": {...scrypt, salt}, "nonce": b64, "wrapped": b64}},
   "nonce": b64, "ct": b64}

* Dane szyfruje losowy klucz DEK (AES-256-GCM).
* DEK jest „owinięty” osobno dla każdego użytkownika kluczem wyprowadzonym z jego hasła (scrypt) — jak keysloty
  w LUKS. Każdy aktywny użytkownik może więc odblokować sejf po restarcie serwera, a zmiana hasła jednej osoby
  nie wymaga przeszyfrowania danych.
* slot_id = SHA-256(file_id | login) — loginy nie są jawne w nagłówku.

Dziennik zmian (plik *.audit.enc): jedna linia = jeden wpis zaszyfrowany DEK (AES-GCM), tylko dopisywanie.
Wpisy tworzą łańcuch SHA-256 (prev -> hash), więc usunięcie / podmiana wpisu jest wykrywalna.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import threading
import time
import zlib
from collections import OrderedDict
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .engine import DEFAULT_SLA, DEFAULT_TEAM_RULES, DEFAULT_TEAMS

FORMAT = "vulnbuster-vault"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
BACKUP_KEEP = 30
BACKUP_EVERY_S = 3600
GENESIS = "0" * 64


class WrongPassphrase(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def derive_key(password: str, salt: bytes, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def empty_db() -> dict:
    return {
        "schema": 2,
        "created_at": now_iso(),
        "settings": {
            "stale_warn_days": 90,
            "stale_crit_days": 150,
            "groups": [
                {"id": "remote-unauth", "name": "Zdalne bez uwierzytelnienia",
                 "description": "Podatność wykorzystywana przez sieć bez logowania"},
                {"id": "remote-auth", "name": "Zdalne z uwierzytelnieniem",
                 "description": "Wymaga konta / sesji w usłudze"},
                {"id": "local", "name": "Wymaga dostępu lokalnego",
                 "description": "Atakujący musi mieć sesję lub kod na hoście"},
                {"id": "mgmt-ui", "name": "Interfejs zarządzania",
                 "description": "Panel admin / web UI / API zarządzające"},
                {"id": "internet-facing", "name": "Wymaga ekspozycji do Internetu",
                 "description": "Realne ryzyko tylko przy dostępie z Internetu"},
                {"id": "user-interaction", "name": "Wymaga interakcji użytkownika",
                 "description": "Otwarcie pliku, kliknięcie linku itp."},
            ],
            "teams": [dict(t, email="") for t in DEFAULT_TEAMS],
            "team_rules": [dict(r) for r in DEFAULT_TEAM_RULES],
            "import_ignore": "Security Update for *, Update for *, Hotfix for *, *Language Pack*, *(KB*)*, "
                             "Microsoft Visual C++ * Redistributable*, Microsoft .NET * Targeting Pack*",
            "import_normalize": True,
            "import_os_as_app": True,
            "history_keep": 24,
            "sla_days": dict(DEFAULT_SLA),
            "ticket_prefix": "VULN",
            "ticket_subject": "",
            "ticket_template": "",
            "ticket_signature": "Pozdrawiam,\nZespół Bezpieczeństwa IT",
            "ticket_sender": "",
        },
        "users": {},
        "products": {},
        "hosts": {},
        "cves": {},
        "inventory": {},
        "imports": [],
        "exceptions": [],
        "tickets": [],
        "product_redirects": {},
        "kev": {"updated_at": None, "catalog_version": None, "entries": {}},
        "kev_product_map": {},
        "mapping_profiles": {},
    }


class Vault:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        base = self.path[: -len(".json.enc")] if self.path.endswith(".json.enc") else self.path
        self.audit_path = base + ".audit.enc"
        self.backup_dir = os.path.join(os.path.dirname(self.path), "backups")
        self.lock = threading.RLock()
        self._dek: bytes | None = None
        self.file_id: bytes | None = None
        self.slots: dict = {}
        self.db: dict | None = None
        self.audit_entries: list = []
        self._last_backup = 0.0
        self.imports_dir = os.path.join(os.path.dirname(self.path), "imports")
        self._obs_cache: OrderedDict = OrderedDict()
        self.rev = 0                       # licznik zmian (unieważnia pamięci podręczne)

    # ------------------------------------------------------------ stan
    @property
    def initialized(self) -> bool:
        return os.path.exists(self.path)

    @property
    def unlocked(self) -> bool:
        return self._dek is not None and self.db is not None

    # ------------------------------------------------------------ sloty
    def slot_id(self, username: str) -> str:
        return hashlib.sha256(self.file_id + b"|" + username.strip().lower().encode()).hexdigest()[:32]

    def _make_slot(self, username: str, password: str) -> dict:
        sid = self.slot_id(username)
        salt = secrets.token_bytes(16)
        kek = derive_key(password, salt)
        nonce = secrets.token_bytes(12)
        wrapped = AESGCM(kek).encrypt(nonce, self._dek, self._slot_aad(sid))
        return {"kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
                "nonce": _b64(nonce), "wrapped": _b64(wrapped)}

    def _slot_aad(self, sid: str) -> bytes:
        return f"slot|{sid}|{_b64(self.file_id)}".encode()

    def _open_slot(self, slots: dict, username: str, password: str) -> bytes:
        sid = self.slot_id(username)
        s = slots.get(sid)
        if not s:
            # stała praca także dla nieistniejącego loginu (brak wycieku przez czas odpowiedzi)
            derive_key(password, b"\0" * 16)
            raise WrongPassphrase()
        k = s["kdf"]
        kek = derive_key(password, _unb64(k["salt"]), k["n"], k["r"], k["p"])
        try:
            return AESGCM(kek).decrypt(_unb64(s["nonce"]), _unb64(s["wrapped"]), self._slot_aad(sid))
        except InvalidTag:
            raise WrongPassphrase()

    def has_slot(self, username: str) -> bool:
        return self.slot_id(username) in self.slots

    def set_password(self, username: str, password: str):
        with self.lock:
            self._require_unlocked()
            self.slots[self.slot_id(username)] = self._make_slot(username, password)

    def remove_slot(self, username: str):
        with self.lock:
            self.slots.pop(self.slot_id(username), None)

    # ------------------------------------------------------------ cykl życia
    def init(self, username: str, password: str):
        with self.lock:
            if self.initialized:
                raise RuntimeError("Sejf już istnieje")
            self.file_id = secrets.token_bytes(16)
            self._dek = AESGCM.generate_key(bit_length=256)
            self.slots = {}
            self.slots[self.slot_id(username)] = self._make_slot(username, password)
            self.db = empty_db()
            self.audit_entries = []
            if os.path.exists(self.audit_path):
                os.replace(self.audit_path, self.audit_path + f".orphan-{int(time.time())}")
            self.save()

    def unlock(self, username: str, password: str):
        """Odblokowuje sejf (jeśli zablokowany). Zwraca True, gdy hasło pasuje."""
        with self.lock:
            blob = self._read_blob()
            self.file_id = _unb64(blob["file_id"])
            dek = self._open_slot(blob["slots"], username, password)
            db = self._decode(blob, AESGCM(dek).decrypt(_unb64(blob["nonce"]), _unb64(blob["ct"]), self._aad()))
            self._dek, self.slots, self.db = dek, blob["slots"], db
            self._obs_cache.clear()
            self._load_audit()
            if self._migrate():
                self.save(force_backup=True)

    def reload(self):
        """Wycofuje niezapisane zmiany w pamięci (np. po błędzie w trakcie obsługi żądania)."""
        with self.lock:
            self._require_unlocked()
            blob = self._read_blob()
            self.rev += 1
            self.db = self._decode(blob, AESGCM(self._dek).decrypt(_unb64(blob["nonce"]), _unb64(blob["ct"]),
                                                                    self._aad()))
            self.slots = blob["slots"]
            self._migrate()

    def verify(self, username: str, password: str) -> bool:
        """Sprawdza hasło przy otwartym sejfie (logowanie kolejnej osoby)."""
        with self.lock:
            self._require_unlocked()
        try:
            return secrets.compare_digest(self._open_slot(self.slots, username, password), self._dek)
        except WrongPassphrase:
            return False

    def lock_vault(self):
        with self.lock:
            self._dek = None
            self.db = None
            self.audit_entries = []

    def save(self, force_backup: bool = False):
        with self.lock:
            self._require_unlocked()
            self.rev += 1
            self.db["updated_at"] = now_iso()
            nonce = secrets.token_bytes(12)
            raw = json.dumps(self.db, separators=(",", ":")).encode("ascii")   # szybka ścieżka enkodera C
            ct = AESGCM(self._dek).encrypt(nonce, zlib.compress(raw, 3), self._aad())
            blob = {"format": FORMAT, "v": 2, "file_id": _b64(self.file_id), "slots": self.slots, "comp": "zlib",
                    "nonce": _b64(nonce), "ct": _b64(ct)}
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(blob, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            if force_backup or time.time() - self._last_backup > BACKUP_EVERY_S:
                self.backup()

    def backup(self, reason: str = "auto"):
        if not os.path.exists(self.path):
            return
        os.makedirs(self.backup_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copyfile(self.path, os.path.join(self.backup_dir, f"data-{stamp}-{reason}.json.enc"))
        if os.path.exists(self.audit_path):
            shutil.copyfile(self.audit_path, os.path.join(self.backup_dir, f"data-{stamp}-{reason}.audit.enc"))
        self._last_backup = time.time()
        files = sorted(f for f in os.listdir(self.backup_dir) if f.endswith(".json.enc"))
        for old in files[:-BACKUP_KEEP]:
            for fn in (old, old.replace(".json.enc", ".audit.enc")):
                try:
                    os.remove(os.path.join(self.backup_dir, fn))
                except OSError:
                    pass

    def encrypted_bytes(self) -> bytes:
        with open(self.path, "rb") as f:
            return f.read()

    # ------------------------------------------------------------ obserwacje importów (osobne pliki)
    def _obs_path(self, imp_id: str) -> str:
        safe = "".join(ch for ch in imp_id if ch.isalnum() or ch in "_-")
        return os.path.join(self.imports_dir, f"{safe}.obs.enc")

    def write_observations(self, imp_id: str, obs: list):
        """Lista obserwacji importu w osobnym, skompresowanym i zaszyfrowanym pliku (niezmienny po zapisie)."""
        with self.lock:
            self._require_unlocked()
            os.makedirs(self.imports_dir, exist_ok=True)
            nonce = secrets.token_bytes(12)
            ct = AESGCM(self._dek).encrypt(nonce, zlib.compress(canon(obs), 3), b"obs|" + imp_id.encode() + self.file_id)
            path = self._obs_path(imp_id)
            with open(path + ".tmp", "wb") as f:
                f.write(nonce + ct)
                f.flush()
                os.fsync(f.fileno())
            os.replace(path + ".tmp", path)
            self._obs_cache[imp_id] = obs

    def read_observations(self, imp_id: str):
        with self.lock:
            if imp_id in self._obs_cache:
                self._obs_cache.move_to_end(imp_id)
                return self._obs_cache[imp_id]
            path = self._obs_path(imp_id)
            if not os.path.exists(path):
                return None
            raw = open(path, "rb").read()
            obs = json.loads(zlib.decompress(AESGCM(self._dek).decrypt(raw[:12], raw[12:],
                                                                       b"obs|" + imp_id.encode() + self.file_id)))
            self._obs_cache[imp_id] = obs
            while len(self._obs_cache) > 8:
                self._obs_cache.popitem(last=False)
            return obs

    def delete_observations(self, imp_id: str):
        with self.lock:
            self._obs_cache.pop(imp_id, None)
            try:
                os.remove(self._obs_path(imp_id))
            except OSError:
                pass

    # ------------------------------------------------------------ dziennik zmian
    def _audit_aad(self) -> bytes:
        return b"audit|" + self.file_id

    def append_audit(self, entry: dict) -> dict:
        with self.lock:
            self._require_unlocked()
            prev = self.audit_entries[-1].get("hash", GENESIS) if self.audit_entries else GENESIS
            e = dict(entry, seq=len(self.audit_entries) + 1, prev=prev)
            e["hash"] = hashlib.sha256(canon(e)).hexdigest()
            nonce = secrets.token_bytes(12)
            ct = AESGCM(self._dek).encrypt(nonce, canon(e), self._audit_aad())
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"n": _b64(nonce), "c": _b64(ct)}) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.audit_entries.append(e)
            return e

    def _load_audit(self):
        self.audit_entries = []
        if not os.path.exists(self.audit_path):
            return
        aes = AESGCM(self._dek)
        with open(self.audit_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    self.audit_entries.append(json.loads(aes.decrypt(_unb64(rec["n"]), _unb64(rec["c"]),
                                                                     self._audit_aad())))
                except Exception:  # noqa: BLE001
                    self.audit_entries.append({"seq": None, "corrupt": True, "line": i})

    def verify_chain(self) -> dict:
        prev = GENESIS
        for i, e in enumerate(self.audit_entries, 1):
            if e.get("corrupt"):
                return {"ok": False, "count": len(self.audit_entries), "broken_at": i,
                        "reason": f"Wiersz {e['line']} nie daje się odszyfrować (uszkodzony lub podmieniony)"}
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("prev") != prev or e.get("seq") != i:
                return {"ok": False, "count": len(self.audit_entries), "broken_at": i,
                        "reason": f"Przerwany łańcuch przy wpisie {i} (brakujący lub przestawiony wpis)"}
            if hashlib.sha256(canon(body)).hexdigest() != e.get("hash"):
                return {"ok": False, "count": len(self.audit_entries), "broken_at": i,
                        "reason": f"Niezgodny skrót wpisu {i} (treść zmieniona)"}
            prev = e["hash"]
        return {"ok": True, "count": len(self.audit_entries), "last_hash": prev}

    # ------------------------------------------------------------ wnętrzności
    def _aad(self) -> bytes:
        return canon({"format": FORMAT, "v": 2, "file_id": _b64(self.file_id)})

    def _read_blob(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        if blob.get("format") != FORMAT:
            raise ValueError("To nie jest plik sejfu VulnBuster (v2)")
        return blob

    @staticmethod
    def _decode(blob: dict, data: bytes) -> dict:
        if blob.get("comp") == "zlib":
            data = zlib.decompress(data)
        return json.loads(data)

    def _require_unlocked(self):
        if not self.unlocked:
            raise RuntimeError("Sejf zablokowany")

    def _migrate(self) -> bool:
        """Uzupełnia brakujące pola nowszych wersji. Zwraca True, gdy trzeba zapisać bazę."""
        changed = False
        base = empty_db()
        for k, v in base.items():
            if k not in self.db:
                self.db[k] = v
                changed = True
        for k, v in base["settings"].items():
            if k not in self.db["settings"]:
                self.db["settings"][k] = v
                changed = True
        # obserwacje importów przenoszone do osobnych plików (mniejsza baza = szybsze zapisy)
        if self._dek is not None:
            for imp in self.db.get("imports", []):
                if "observations" in imp:
                    obs = imp.pop("observations")
                    imp["installations"] = len(obs)
                    self.write_observations(imp["id"], obs)
                    changed = True
        return changed
