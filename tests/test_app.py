# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Testy: python -m unittest discover -s tests -v"""
import http.cookiejar
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["VULNBUSTER_QUIET"] = "1"

from vulnbuster import engine as E  # noqa: E402
from vulnbuster import importer as I  # noqa: E402
from vulnbuster import versions as V  # noqa: E402
from vulnbuster.server import App, make_handler  # noqa: E402
from vulnbuster.storage import Vault, WrongPassphrase  # noqa: E402

PW = "bardzo-tajne-haslo-123"


class TestVersions(unittest.TestCase):
    def test_compare(self):
        cases = [("14.9", "14.11", -1), ("14.11", "14.11", 0), ("1.0rc1", "1.0", -1), ("9.6p1", "9.6", 1),
                 ("2.4.57-2+deb12u1", "2.4.58", -1), ("15.2(4)M7", "15.2(4)M8", -1),
                 ("10.0.19045.4529", "10.0.19045.4651", -1), ("1.1.1w", "1.1.1t", 1), ("7.2.5", "7.2.10", -1)]
        for a, b, exp in cases:
            self.assertEqual(V.compare(a, b), exp, f"{a} vs {b}")

    def test_rule(self):
        rule = {"branches": [{"branch": "12", "fixed": "12.18"}, {"branch": "14", "fixed": "14.11"},
                             {"branch": "15", "state": "nofix"}, {"branch": "10", "state": "safe"}]}
        ev = lambda v: E.evaluate_rule(rule, v)["status"]  # noqa: E731
        self.assertEqual(ev("14.9"), "vulnerable")
        self.assertEqual(ev("14.11"), "fixed")
        self.assertEqual(ev("15.9"), "vulnerable")
        self.assertEqual(ev("10.23"), "not_affected")
        self.assertEqual(ev("11.22"), "review")
        self.assertEqual(ev("17.0"), "not_affected")
        self.assertEqual(E.evaluate_rule(rule, "14.9")["target"], "14.11")


class TestVault(unittest.TestCase):
    def test_keyslots_audit_chain(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "v.json.enc")
            v = Vault(p)
            v.init("admin", PW)
            v.db["hosts"]["h1"] = {"id": "h1", "hostname": "tajny-serwer"}
            v.set_password("jan", "haslo-jana-123456")
            v.save()
            v.append_audit({"ts": "t", "user": "admin", "action": "x", "summary": "tajny-wpis"})
            v.append_audit({"ts": "t", "user": "jan", "action": "y", "summary": "drugi"})
            for f in (p, v.audit_path):
                raw = open(f, encoding="utf-8").read()
                self.assertNotIn("tajny", raw)
                self.assertNotIn("jan", raw)
            # inny użytkownik odblokowuje ten sam sejf własnym hasłem
            v2 = Vault(p)
            with self.assertRaises(WrongPassphrase):
                v2.unlock("jan", "zle-haslo-12345")
            with self.assertRaises(WrongPassphrase):
                v2.unlock("nieznany", PW)
            v2.unlock("jan", "haslo-jana-123456")
            self.assertEqual(v2.db["hosts"]["h1"]["hostname"], "tajny-serwer")
            self.assertTrue(v2.verify_chain()["ok"])
            self.assertTrue(v2.verify("admin", PW))
            self.assertFalse(v2.verify("admin", "zle-haslo-12345"))
            # usunięcie wpisu z dziennika jest wykrywane
            lines = open(v.audit_path, encoding="utf-8").read().splitlines()
            open(v.audit_path, "w", encoding="utf-8").write(lines[1] + "\n")
            v3 = Vault(p)
            v3.unlock("admin", PW)
            self.assertFalse(v3.verify_chain()["ok"])
            # usunięty slot = brak dostępu
            v3.remove_slot("jan")
            v3.save()
            with self.assertRaises(WrongPassphrase):
                Vault(p).unlock("jan", "haslo-jana-123456")
        finally:
            shutil.rmtree(d)


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.app = App(os.path.join(cls.dir, "data.json.enc"))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.app))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.jar = http.cookiejar.CookieJar()
        cls.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cls.jar))

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.dir)

    def login(self, user, pw, expect=200):
        jar = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        self.call("POST", "/api/login", {"username": user, "password": pw}, expect, opener=op)
        return op

    def call(self, method, path, body=None, expect=200, opener=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "X-Requested-With": "vulnbuster"})
        try:
            with (opener or self.opener).open(req) as r:
                status, payload = r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            status, payload = e.code, json.loads(e.read() or b"{}")
        self.assertEqual(status, expect, payload)
        return payload

    def test_full_flow(self):
        c = self.call
        st = c("GET", "/api/status")
        self.assertEqual((st["initialized"], st["unlocked"], st["app"], st["license"]), (False, False, "VulnBuster", "MIT"))
        c("POST", "/api/init", {"username": "admin", "password": "krotkie"}, 400)
        c("POST", "/api/init", {"username": "admin", "display_name": "Marcin", "password": PW})
        # inna przeglądarka bez sesji nie ma dostępu
        anon = urllib.request.build_opener()
        c("GET", "/api/hosts", expect=401, opener=anon)
        # brak nagłówka CSRF
        req = urllib.request.Request(self.base + "/api/lock", data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.opener.open(req)
        self.assertEqual(cm.exception.code, 403)

        # 1) reguły CVE z wklejki
        a = c("POST", "/api/import/analyze", {"text": "CVE\tAplikacja\tWersja naprawiona\n"
                                                      "CVE-2024-0985\tPostgreSQL\t12.18\n"
                                                      "CVE-2024-0985\tPostgreSQL\t14.11\n"
                                                      "CVE-2024-0985\tPostgreSQL\t16.2\n"})
        mapping = [col["field"] for col in a["columns"]]
        self.assertEqual(mapping, ["cve", "product", "fixed_version"])
        r = c("POST", "/api/import/commit", {"token": a["token"], "mapping": mapping, "name": "reguły"})
        self.assertEqual(r["stats"]["rules_added"], 3)

        # 2) inwentarz
        inv = ("Host\tIP\tTyp\tSystem\tEkspozycja\tAplikacja\tWersja\tWłaściciel\n"
               "db1\t10.0.0.1\tserwer\tRHEL 9\tDMZ\tPostgreSQL\t14.9\tJan\n"
               "db2\t10.0.0.2\tserwer\tRHEL 9\twewnętrzna\tPostgreSQL\t16.4\tJan\n"
               "db3\t10.0.0.3\tserwer\tCentOS 7\twewn\tPostgreSQL\t11.22\tAnna\n"
               "fw1\t10.0.0.254\tfirewall\tFortiOS\tInternet\tFortiOS\t7.2.5\tNOC\n")
        a = c("POST", "/api/import/analyze", {"text": inv})
        mapping = [col["field"] for col in a["columns"]]
        self.assertIn("exposure", mapping)
        self.assertEqual(a["preview"]["stats"]["by_status"].get("vulnerable"), 1)
        self.assertEqual(len(c("GET", "/api/hosts")["hosts"]), 0, "podgląd nie może zapisywać")
        r1 = c("POST", "/api/import/commit", {"token": a["token"], "mapping": mapping, "name": "przed"})
        hosts = {h["hostname"]: h for h in c("GET", "/api/hosts")["hosts"]}
        self.assertEqual(hosts["db1"]["status"], "vulnerable")
        self.assertEqual(hosts["db1"]["exposure"], "dmz")
        self.assertEqual(hosts["db3"]["status"], "review")
        self.assertEqual(hosts["db2"]["status"], "fixed")

        # 3) raport hosta: wersja docelowa
        rep = c("GET", f"/api/hosts/{hosts['db1']['id']}/report")
        self.assertEqual(rep["installations"][0]["summary"]["target"], "14.11")

        # 4) wyjątek dla db3 i mitygacja grupowa
        c("POST", "/api/exceptions", {"host_id": hosts["db3"]["id"], "reason": "System dostawcy wymaga PG 11",
                                      "review_at": "2027-01-01"})
        self.assertEqual({h["hostname"]: h for h in c("GET", "/api/hosts")["hosts"]}["db3"]["status"], "exception")

        # 5) grupa internet-facing + host wewnętrzny = auto-mitygacja
        pid_pg = next(p["id"] for p in c("GET", "/api/products")["products"] if p["name"] == "PostgreSQL")
        c("PUT", "/api/cves/CVE-2099-0001", {"title": "test", "groups": ["internet-facing"],
                                              "rules": [{"product_id": pid_pg, "branches": [
                                                  {"branch": "16", "fixed": "16.9", "state": "fix"},
                                                  {"branch": "14", "state": "safe"}]}]})
        imp = c("GET", "/api/cves/CVE-2099-0001")["impact"]["rows"]
        db2row = next(x for x in imp if x["hostname"] == "db2")
        self.assertEqual(db2row["status"], "mitigated")

        # 6) re-import po patchowaniu + porównanie
        inv2 = inv.replace("14.9", "14.11")
        a = c("POST", "/api/import/analyze", {"text": inv2})
        self.assertTrue(a["profile_used"])
        r2 = c("POST", "/api/import/commit", {"token": a["token"], "mapping": [x["field"] for x in a["columns"]],
                                              "name": "po"})
        cmp = c("GET", f"/api/imports/compare?a={r1['import_id']}&b={r2['import_id']}")
        self.assertEqual(cmp["counts"].get("patched"), 1)

        # 7) KEV: wgranie, decyzja „nie używamy”, wyszukiwanie
        kev = {"catalogVersion": "2026.10.19", "vulnerabilities": [
            {"cveID": "CVE-2025-0282", "vendorProject": "Ivanti", "product": "Connect Secure",
             "vulnerabilityName": "Ivanti Connect Secure Stack Overflow", "dateAdded": "2025-01-08",
             "dueDate": "2025-01-15", "shortDescription": "x", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2024-0985", "vendorProject": "PostgreSQL", "product": "PostgreSQL",
             "vulnerabilityName": "PG", "dateAdded": "2025-02-01", "dueDate": "2025-02-20"}]}
        self.assertEqual(c("POST", "/api/kev/upload", {"data": json.dumps(kev)})["added"], 2)
        lst = c("GET", "/api/kev?view=pending")["items"]
        pg = next(x for x in lst if x["cve"] == "CVE-2024-0985")
        self.assertTrue(pg["candidates"] and pg["candidates"][0]["hosts"] == 3)
        c("POST", "/api/kev/CVE-2025-0282/triage", {"decision": "not_used", "note": "brak w CMDB"})
        s = c("GET", "/api/search?q=ivanti")
        self.assertEqual(s["products"][0]["status"], "not_used")
        self.assertEqual(s["cves"][0]["triage"]["decision"], "not_used")
        # odmowa „nie używamy” dla używanego produktu
        c("POST", "/api/kev/CVE-2024-0985/triage", {"decision": "not_used"}, 409)

        # 8) użytkownicy i role
        c("POST", "/api/users", {"username": "jan", "display_name": "Jan", "role": "viewer",
                                 "password": "tymczasowe-123456"})
        c("POST", "/api/users", {"username": "ola", "role": "editor", "password": "tymczasowe-654321",
                                 "must_change": False})
        jan = self.login("jan", "tymczasowe-123456")
        c("GET", "/api/hosts", expect=403, opener=jan)          # wymuszona zmiana hasła
        c("POST", "/api/me/password", {"old": "tymczasowe-123456", "new": "nowe-haslo-jana-1"}, opener=jan)
        self.assertEqual(len(c("GET", "/api/hosts", opener=jan)["hosts"]), 4)
        c("PUT", f"/api/hosts/{hosts['db1']['id']}", {"owner": "x"}, 403, opener=jan)  # podgląd: bez edycji
        c("GET", "/api/users", expect=403, opener=jan)
        ola = self.login("ola", "tymczasowe-654321")
        # równoczesna edycja: ola zapisuje, admin ze starą wersją dostaje 409
        rep_db1 = c("GET", f"/api/hosts/{hosts['db1']['id']}/report")
        ver = rep_db1["host"]["updated_at"]
        c("PUT", f"/api/hosts/{hosts['db1']['id']}", {"owner": "Ola", "_version": ver}, opener=ola)
        err = c("PUT", f"/api/hosts/{hosts['db1']['id']}", {"owner": "Admin", "_version": ver}, 409)
        self.assertIn("ola", err["error"])
        # dziennik: kto zmienił właściciela db1
        a = c("GET", f"/api/audit?entity={hosts['db1']['id']}")
        e = a["entries"][0]
        self.assertEqual(e["user"], "ola")
        self.assertEqual(e["changes"][0]["fields"]["owner"], ["Jan", "Ola"])
        self.assertTrue(c("GET", "/api/audit/verify")["ok"])
        # blokada konta po 5 błędach
        for _ in range(5):
            self.login("ola", "zle-haslo-xxxxxx", 403)
        self.login("ola", "tymczasowe-654321", 429)
        # dezaktywacja i ochrona ostatniego admina
        c("PUT", "/api/users/jan", {"active": False})
        c("GET", "/api/hosts", expect=401, opener=jan)
        c("PUT", "/api/users/admin", {"role": "viewer"}, 400)

        # 9) zablokowanie sejfu i odblokowanie przez innego użytkownika
        c("POST", "/api/lock")
        c("GET", "/api/hosts", expect=423)
        self.login("admin", "zle-haslo-xxxx", 403)
        self.login("jan", "nowe-haslo-jana-1", 403)        # konto zablokowane
        self.opener = self.login("admin", PW)
        c = self.call
        self.assertEqual(len(c("GET", "/api/hosts")["hosts"]), 4)
        d = c("GET", "/api/dashboard")
        self.assertEqual(d["kev_pending"], 1)
        self.assertTrue(c("GET", "/api/audit/verify")["ok"])
        # strony statyczne
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn(b"VulnBuster", r.read())
            self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])


class TestImporterDetection(unittest.TestCase):
    def test_headerless_and_combined(self):
        t = I.parse_table("srv01;10.0.0.5;nginx 1.24.0\nsrv02;10.0.0.6;nginx 1.25.3\n")
        a = I.analyze({"mapping_profiles": {}}, t)
        self.assertFalse(t["has_header"])
        self.assertEqual([c["field"] for c in a["columns"]], ["hostname", "ip", "product"])
        self.assertTrue(a["split_product_version"])
        recs = I.build_records(t, ["hostname", "ip", "product"], True)
        self.assertEqual((recs[0]["product"], recs[0]["version"]), ("nginx", "1.24.0"))

    def test_exposure_normalize(self):
        for v, e in [("Internet", "internet"), ("tak", "internet"), ("DMZ", "dmz"), ("wewnętrzna", "internal"),
                     ("nie", "internal"), ("LAN", "internal"), ("nieznana", "unknown"), ("?", "")]:
            self.assertEqual(I.normalize_exposure(v), e, v)


if __name__ == "__main__":
    unittest.main()
