# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Silnik oceny: reguły wersji CVE x inwentarz hostów, mitygacje, wyjątki, raporty, porównania."""
from __future__ import annotations

import fnmatch
import re
import unicodedata
from collections import defaultdict
from datetime import date, datetime, timezone

from . import versions as V

ACTION = {"vulnerable", "review"}
ORDER = ["vulnerable", "review", "exception", "mitigated", "fixed", "not_affected", "none"]
LABELS = {
    "vulnerable": "Podatne", "review": "Do weryfikacji", "exception": "Wyjątek",
    "mitigated": "Mitygowane", "fixed": "Załatane", "not_affected": "Niepodatne", "none": "Brak CVE",
}


# ---------------------------------------------------------------- pomocnicze
def norm(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or "")).replace("ł", "l").replace("Ł", "L")
    s = "".join(ch for ch in s if not unicodedata.combining(ch)).lower()
    return re.sub(r"[^a-z0-9]+", "", s)


def words(s) -> set:
    s = unicodedata.normalize("NFKD", str(s or "")).lower()
    return {w for w in re.split(r"[^a-z0-9]+", s) if len(w) >= 3}


def worst(statuses):
    best = "none"
    for s in statuses:
        if ORDER.index(s) < ORDER.index(best):
            best = s
    return best


def parse_date(s):
    if not s:
        return None
    try:
        if len(s) == 10:
            return date.fromisoformat(s)
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def staleness(verified_at, settings) -> dict:
    d = parse_date(verified_at)
    if d is None:
        return {"level": "never", "days": None}
    days = (date.today() - d).days
    lvl = "fresh"
    if days >= settings.get("stale_crit_days", 150):
        lvl = "crit"
    elif days >= settings.get("stale_warn_days", 90):
        lvl = "warn"
    return {"level": lvl, "days": days}


def inv_key(hid, pid):
    return f"{hid}|{pid}"


# ---------------------------------------------------------------- kontekst
class Ctx:
    """Indeksy liczone raz na żądanie."""

    def __init__(self, db: dict):
        self.db = db
        self.by_product = defaultdict(list)
        for c in db["cves"].values():
            for r in c.get("rules", []):
                self.by_product[r["product_id"]].append((c, r))
        self.kev = db["kev"]["entries"]
        self.exceptions = [e for e in db["exceptions"] if e.get("active", True)]
        self.today = date.today()
        self._inv_host = None
        self._inv_prod = None
        self.teams = TeamResolver(db)
        self.fcache = {}
        self.scache = {}

    def _index(self):
        self._inv_host, self._inv_prod = defaultdict(list), defaultdict(list)
        for i in self.db["inventory"].values():
            if not i.get("removed"):
                self._inv_host[i["host_id"]].append(i)
                self._inv_prod[i["product_id"]].append(i)

    def inv_host(self, hid):
        if self._inv_host is None:
            self._index()
        return self._inv_host.get(hid, [])

    def inv_prod(self, pid):
        if self._inv_prod is None:
            self._index()
        return self._inv_prod.get(pid, [])


# ---------------------------------------------------------------- spółki i zespoły (realizatorzy)
DEFAULT_TEAMS = [
    {"id": "windows", "name": "Windows team", "description": "Serwery Windows"},
    {"id": "linux", "name": "Linux team", "description": "Serwery Linux / Unix"},
    {"id": "network", "name": "Networkers", "description": "Switche, routery, firewalle, AP"},
    {"id": "helpdesk", "name": "Helpdesk", "description": "Stacje robocze i laptopy"},
]
DEFAULT_TEAM_RULES = [
    {"field": "type", "pattern": "*switch*, *router*, *firewall*, *access point*, *sieciow*, *network*", "team": "network"},
    {"field": "os", "pattern": "*ios*, *fortios*, *junos*, *pan-os*, *routeros*, *nx-os*, *aruba*", "team": "network"},
    {"field": "os", "pattern": "*server*, win 20*, win20*, windows 20*", "team": "windows"},
    {"field": "os", "pattern": "win 10*, win 11*, windows 10*, windows 11*, *macos*", "team": "helpdesk"},
    {"field": "type", "pattern": "*laptop*, *desktop*, *workstation*, *stacja*, *notebook*", "team": "helpdesk"},
    {"field": "os", "pattern": "*linux*, *ubuntu*, *debian*, *rhel*, *red hat*, *centos*, *rocky*, *alma*, *suse*, *sles*, *oracle linux*", "team": "linux"},
]
TEAM_RULE_FIELDS = {"os": "System", "type": "Typ urządzenia", "hostname": "Nazwa hosta", "company": "Spółka",
                    "environment": "Środowisko", "location": "Lokalizacja", "owner": "Właściciel",
                    "product": "Aplikacja"}
UNASSIGNED = "__none__"


def glob_any(value, patterns) -> bool:
    v = str(value or "").strip().lower()
    if not v:
        return False
    for p in str(patterns or "").split(","):
        p = p.strip().lower()
        if p and fnmatch.fnmatchcase(v, p):
            return True
    return False


class TeamResolver:
    """Kto łata: aplikacja z przypisanym zespołem > reguła po aplikacji > zespół hosta > reguły hosta."""

    def __init__(self, db):
        st = db.get("settings", {})
        self.names = {t["id"]: t["name"] for t in st.get("teams", [])}
        rules = st.get("team_rules", [])
        self.prod_rules = [r for r in rules if r.get("field") == "product"]
        self.host_rules = [r for r in rules if r.get("field") != "product"]
        self.products = db.get("products", {})
        self._host_cache = {}

    def label(self, tid):
        if not tid or tid == UNASSIGNED:
            return "Nieprzypisany"
        return self.names.get(tid, tid)

    def host_team(self, host):
        if not host:
            return UNASSIGNED, "brak hosta"
        hid = host.get("id")
        if hid in self._host_cache:
            return self._host_cache[hid]
        res = (UNASSIGNED, "brak pasującej reguły")
        if host.get("team"):
            res = (host["team"], "ustawione na hoście")
        else:
            for i, r in enumerate(self.host_rules, 1):
                if glob_any(host.get(r["field"]), r.get("pattern")):
                    res = (r["team"], f"reguła {i}: {TEAM_RULE_FIELDS.get(r['field'], r['field'])} ~ {r['pattern'][:40]}")
                    break
        self._host_cache[hid] = res
        return res

    def team(self, host, pid=None):
        if pid:
            p = self.products.get(pid) or {}
            if p.get("team"):
                return p["team"], "przypisane do aplikacji"
            for r in self.prod_rules:
                if glob_any(p.get("name"), r.get("pattern")):
                    return r["team"], f"reguła aplikacji ~ {r['pattern'][:40]}"
        return self.host_team(host)


# ---------------------------------------------------------------- reguły
def _res(status, reason, target=None, branch=None):
    return {"status": status, "reason": reason, "target": target, "branch": branch}


def _prefix_gt(nums, bn):
    a = (nums + [0] * len(bn))[: len(bn)]
    return a > bn


def evaluate_branch(br, parsed, version):
    label = br.get("branch") or "*"
    state = br.get("state") or ("fix" if br.get("fixed") else "nofix")
    if state == "safe":
        return _res("not_affected", f"Gałąź {label} niepodatna", branch=label)
    intro = br.get("introduced")
    if intro and V.parse(intro) is not None and V.compare(parsed, V.parse(intro)) < 0:
        return _res("not_affected", f"Wersja starsza niż wprowadzenie błędu ({intro})", branch=label)
    if state == "nofix":
        return _res("vulnerable", f"Brak poprawki w gałęzi {label} — aktualizacja do nowszej gałęzi lub mitygacja",
                    branch=label)
    fixed = br.get("fixed")
    c = V.compare(parsed, V.parse(fixed))
    if c is None:
        return _res("review", f"Nieczytelna wersja naprawiona „{fixed}”", branch=label)
    if c >= 0:
        return _res("fixed", f"{version} ≥ {fixed}", branch=label)
    return _res("vulnerable", f"{version} < {fixed}", target=fixed, branch=label)


def evaluate_rule(rule: dict, version: str) -> dict:
    p = V.parse(version)
    if p is None:
        return _res("review", f"Nieczytelna wersja „{version or '—'}”")
    branches = rule.get("branches") or []
    if not branches:
        return _res("review", "CVE dotyczy produktu, ale brak danych o wersjach naprawionych")
    nums = V.numeric_prefix(p)
    best, blen, star, listed = None, -1, None, []
    for br in branches:
        if V.is_wildcard(br.get("branch")):
            star = br
            continue
        bn = V.branch_nums(br.get("branch"))
        if not bn:
            continue
        listed.append(bn)
        if nums[: len(bn)] == bn and len(bn) > blen:
            best, blen = br, len(bn)
    br = best or star
    if br is not None:
        return evaluate_branch(br, p, version)
    if listed and all(_prefix_gt(nums, bn) for bn in listed):
        return _res("not_affected", "Wersja nowsza niż wszystkie gałęzie opisane w CVE")
    un = rule.get("unlisted") or "review"
    depth = min(len(b) for b in listed) if listed else 1
    label = ".".join(map(str, nums[:depth]))
    if un == "vulnerable":
        return _res("vulnerable", f"Gałąź {label} nieopisana w CVE — traktowana jako podatna")
    if un == "not_affected":
        return _res("not_affected", f"Gałąź {label} nieopisana w CVE — traktowana jako niepodatna")
    return _res("review", f"Gałąź {label} nieopisana w CVE (EOL?) — uzupełnij regułę")


# ---------------------------------------------------------------- nakładki
def find_exception(ctx, hid, pid, cid):
    for e in ctx.exceptions:
        if not (e.get("host_id") or e.get("product_id")):
            continue
        if e.get("host_id") and e["host_id"] != hid:
            continue
        if e.get("product_id") and e["product_id"] != pid:
            continue
        if e.get("cve_id") and e["cve_id"] != cid:
            continue
        return e
    return None


EXPOSURE_RANK = {"internet": 0, "dmz": 1, "unknown": 2, "": 2, "internal": 3}
EXPOSURE_LABELS = {"internet": "Internet", "dmz": "DMZ", "internal": "Sieć wewnętrzna", "unknown": "Nieznana", "": "—"}


def find_mitigation(host, pid, cve):
    groups = set(cve.get("groups") or [])
    for m in host.get("mitigations") or []:
        if m.get("product_id") and m["product_id"] != pid:
            continue
        if m.get("cve_id"):
            if m["cve_id"] == cve.get("id"):
                return m
            continue
        if m.get("group") and m["group"] in groups:
            return m
    if ("internet-facing" in groups and host.get("exposure") == "internal"
            and not cve.get("no_auto_exposure")):
        return {"id": "auto-exposure", "group": "internet-facing",
                "description": "Automatycznie: host niewystawiony do Internetu (ekspozycja: sieć wewnętrzna)"}
    return None


RISK_LABELS = {"critical": "Krytyczne", "high": "Wysokie", "medium": "Średnie", "low": "Niskie"}
DEFAULT_SLA = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def effective_deadline(cve, kev):
    """Termin załatania: własna ocena > termin CISA KEV."""
    a = (cve or {}).get("assessment") or {}
    if a.get("deadline"):
        return a["deadline"], "ocena"
    if kev and kev.get("dueDate"):
        return kev["dueDate"], "CISA KEV"
    return None, None


def make_finding(ctx, host, pid, cve, ev):
    cid = cve["id"]
    k = ctx.kev.get(cid)
    dl, dls = effective_deadline(cve, k)
    a = cve.get("assessment") or {}
    f = {
        "cve": cid, "title": cve.get("title") or (k or {}).get("vulnerabilityName") or "",
        "cvss": cve.get("cvss"), "kev": bool(k), "kev_due": (k or {}).get("dueDate"),
        "kev_ransomware": (k or {}).get("knownRansomwareCampaignUse") == "Known",
        "base_status": ev["status"], "status": ev["status"], "reason": ev["reason"],
        "target": ev.get("target"), "branch": ev.get("branch"), "overlay": None,
        "deadline": dl, "deadline_source": dls, "risk": a.get("risk"),
        "overdue": bool(dl and parse_date(dl) and parse_date(dl) < ctx.today),
    }
    if ev["status"] in ACTION and host is not None:
        e = find_exception(ctx, host["id"], pid, cid)
        if e:
            rd = parse_date(e.get("review_at"))
            f["status"] = "exception"
            f["overlay"] = {"type": "exception", "id": e["id"], "text": e.get("reason", ""),
                            "contact": e.get("contact", ""), "review_at": e.get("review_at"),
                            "overdue": bool(rd and rd < ctx.today)}
        else:
            m = find_mitigation(host, pid, cve)
            if m:
                f["status"] = "mitigated"
                f["overlay"] = {"type": "mitigation", "id": m["id"], "group": m.get("group"),
                                "text": m.get("description", "")}
    return f


def findings_for(ctx, host, pid, version, reported=()):
    key = ((host or {}).get("id"), pid, version, tuple(reported or ()))
    hit = ctx.fcache.get(key)
    if hit is not None:
        return hit
    out = _findings(ctx, host, pid, version, reported)
    ctx.fcache[key] = out
    return out


def _findings(ctx, host, pid, version, reported=()):
    out, seen = [], set()
    for cve, rule in ctx.by_product.get(pid, []):
        seen.add(cve["id"])
        out.append(make_finding(ctx, host, pid, cve, evaluate_rule(rule, version)))
    for cid in reported or ():
        if cid in seen:
            continue
        seen.add(cid)
        cve = ctx.db["cves"].get(cid) or {"id": cid}
        out.append(make_finding(ctx, host, pid, cve,
                                _res("review", "Zgłoszone w imporcie — brak reguły wersji dla tego produktu w CVE")))
    out.sort(key=lambda f: (ORDER.index(f["status"]), not f["kev"], f["cve"]))
    return out


def summarize(findings, ctx=None):
    if ctx is not None:
        hit = ctx.scache.get(id(findings))
        if hit is not None and hit[0] is findings:
            return hit[1]
        res = _summarize(findings)
        ctx.scache[id(findings)] = (findings, res)
        return res
    return _summarize(findings)


def _summarize(findings):
    st = worst(f["status"] for f in findings) if findings else "none"
    targets = [f["target"] for f in findings if f["base_status"] == "vulnerable" and f["target"]]
    nofix = any(f["base_status"] == "vulnerable" and not f["target"] for f in findings
                if f["status"] in ACTION)
    return {
        "status": st,
        "open": sum(1 for f in findings if f["status"] in ACTION),
        "open_kev": sum(1 for f in findings if f["status"] in ACTION and f["kev"]),
        "target": V.max_version(targets),
        "nofix": nofix,
        "counts": {s: sum(1 for f in findings if f["status"] == s) for s in ORDER if s != "none"},
    }


def installation_view(ctx, inst):
    db = ctx.db
    host = db["hosts"].get(inst["host_id"])
    prod = db["products"].get(inst["product_id"]) or {"id": inst["product_id"], "name": "?"}
    fs = findings_for(ctx, host, inst["product_id"], inst.get("version"), inst.get("reported_cves"))
    return {
        "key": inst.get("key") or inv_key(inst["host_id"], inst["product_id"]),
        "host_id": inst["host_id"], "hostname": (host or {}).get("hostname", "?"),
        "product_id": prod["id"], "product": prod.get("name"), "vendor": prod.get("vendor", ""),
        "version": inst.get("version"), "last_seen": inst.get("last_seen"),
        "history": inst.get("history", [])[-6:], "findings": fs, "summary": summarize(fs, ctx),
    }


def host_installations(db, hid, ctx=None):
    if ctx is not None:
        return ctx.inv_host(hid)
    return [i for i in db["inventory"].values() if i["host_id"] == hid and not i.get("removed")]


def product_installations(db, pid, ctx=None):
    if ctx is not None:
        return ctx.inv_prod(pid)
    return [i for i in db["inventory"].values() if i["product_id"] == pid and not i.get("removed")]


# ---------------------------------------------------------------- widoki
def host_summary_row(ctx, host):
    sums = []
    for i in host_installations(ctx.db, host["id"], ctx):
        fs = findings_for(ctx, host, i["product_id"], i.get("version"), i.get("reported_cves"))
        sums.append(summarize(fs, ctx))
    s = {"status": worst(x["status"] for x in sums) if sums else "none",
         "open": sum(x["open"] for x in sums), "open_kev": sum(x["open_kev"] for x in sums)}
    insts = sums
    tid, tsrc = ctx.teams.host_team(host)
    return {k: host.get(k, "") for k in ("id", "hostname", "ip", "type", "os", "environment", "owner",
                                          "admin", "criticality", "location", "exposure", "company")} | {
        "team": tid, "team_label": ctx.teams.label(tid), "team_source": tsrc,
        "apps": len(insts), "status": s["status"], "open": s["open"], "open_kev": s["open_kev"],
        "mitigations": len(host.get("mitigations") or []), "updated_at": host.get("updated_at"),
    }


def host_report(db, hid):
    ctx = Ctx(db)
    host = db["hosts"][hid]
    insts = sorted((installation_view(ctx, i) for i in host_installations(db, hid, ctx)),
                   key=lambda x: (ORDER.index(x["summary"]["status"]), (x["product"] or "").lower()))
    for iv in insts:
        tid, tsrc = ctx.teams.team(host, iv["product_id"])
        iv.update(team=tid, team_label=ctx.teams.label(tid), team_source=tsrc)
    allf = [f for iv in insts for f in iv["findings"]]
    exc = [e for e in db["exceptions"] if e.get("host_id") == hid]
    tid, tsrc = ctx.teams.host_team(host)
    return {"host": host, "installations": insts, "summary": summarize(allf),
            "exceptions": exc, "groups": db["settings"]["groups"],
            "team": {"id": tid, "label": ctx.teams.label(tid), "source": tsrc}}


def product_report(db, pid, load_obs=None):
    ctx = Ctx(db)
    prod = db["products"][pid]
    insts = [installation_view(ctx, i) for i in product_installations(db, pid, ctx)]
    for iv in insts:
        h = db["hosts"].get(iv["host_id"], {})
        tid, _ = ctx.teams.team(h, pid)
        iv.update({"owner": h.get("owner", ""), "admin": h.get("admin", ""), "type": h.get("type", ""),
                   "exposure": h.get("exposure", ""), "company": h.get("company", ""),
                   "team": tid, "team_label": ctx.teams.label(tid),
                   "environment": h.get("environment", ""), "ip": h.get("ip", "")})
    insts.sort(key=lambda x: (ORDER.index(x["summary"]["status"]), x["hostname"].lower()))
    # podsumowanie per gałąź wersji
    branches = defaultdict(lambda: {"hosts": 0, "open": 0, "versions": set(), "target": None})
    for iv in insts:
        nums = V.numeric_prefix(iv["version"])
        key = ".".join(map(str, nums[:2] if len(nums) > 2 else nums[:1])) or "?"
        b = branches[key]
        b["hosts"] += 1
        b["open"] += 1 if iv["summary"]["status"] in ACTION else 0
        b["versions"].add(iv["version"])
        if iv["summary"]["target"]:
            b["target"] = V.max_version([x for x in (b["target"], iv["summary"]["target"]) if x])
    br = [{"branch": k, "hosts": v["hosts"], "open": v["open"], "versions": sorted(v["versions"], key=V.sort_key()),
           "target": v["target"]} for k, v in branches.items()]
    br.sort(key=lambda x: V.numeric_prefix(x["branch"]) or [0])
    cves = sorted({cve["id"] for cve, _ in ctx.by_product.get(pid, [])})
    total = len(insts)
    done = sum(1 for iv in insts if iv["summary"]["status"] not in ACTION)
    return {"product": prod, "installations": insts, "branches": br, "cves": cves,
            "progress": {"total": total, "ok": done, "open": total - done},
            "trend": product_trend(db, ctx, pid, load_obs),
            "exceptions": [e for e in db["exceptions"] if e.get("product_id") == pid]}


def _default_obs(imp):
    return imp.get("observations")


def product_trend(db, ctx, pid, load_obs=None):
    load_obs = load_obs or _default_obs
    out = []
    for imp in db["imports"][-12:]:
        allobs = load_obs(imp)
        if not allobs:
            continue
        obs = [o for o in allobs if o["p"] == pid]
        if not obs:
            continue
        open_ = 0
        for o in obs:
            fs = findings_for(ctx, db["hosts"].get(o["h"]), pid, o["v"], o.get("c"))
            open_ += 1 if any(f["status"] in ACTION for f in fs) else 0
        out.append({"import_id": imp["id"], "name": imp["name"], "date": imp["created_at"],
                    "hosts": len(obs), "open": open_})
    return out


def cve_impact(db, cid):
    ctx = Ctx(db)
    cve = db["cves"][cid]
    rows = []
    pids = {r["product_id"] for r in cve.get("rules", [])}
    cand = [i for pid in pids for i in ctx.inv_prod(pid)]
    cand += [i for i in db["inventory"].values() if not i.get("removed") and i["product_id"] not in pids
             and cid in (i.get("reported_cves") or [])]
    for inst in cand:
        host = db["hosts"].get(inst["host_id"])
        fs = [f for f in findings_for(ctx, host, inst["product_id"], inst.get("version"), inst.get("reported_cves"))
              if f["cve"] == cid]
        if not fs:
            continue
        f = fs[0]
        prod = db["products"].get(inst["product_id"], {})
        tid, _ = ctx.teams.team(host, inst["product_id"])
        rows.append({"host_id": inst["host_id"], "hostname": (host or {}).get("hostname", "?"),
                     "owner": (host or {}).get("owner", ""), "company": (host or {}).get("company", ""),
                     "team": ctx.teams.label(tid), "product_id": inst["product_id"],
                     "product": prod.get("name", "?"), "version": inst.get("version"), **{
                         k: f[k] for k in ("status", "base_status", "reason", "target", "overlay", "branch")}})
    rows.sort(key=lambda r: (ORDER.index(r["status"]), r["product"], r["hostname"]))
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ORDER if s != "none"}
    return {"rows": rows, "counts": counts}


def product_usage(db):
    """pid -> liczba hostów"""
    use = defaultdict(int)
    for i in db["inventory"].values():
        if not i.get("removed"):
            use[i["product_id"]] += 1
    return use


def dashboard(db):
    ctx = Ctx(db)
    st = db["settings"]
    hosts = [host_summary_row(ctx, h) for h in db["hosts"].values()]
    open_total = sum(h["open"] for h in hosts)
    status_counts = defaultdict(int)
    for h in hosts:
        status_counts[h["status"]] += 1
    kev = db["kev"]["entries"]
    pending = [c for c in kev if not (db["cves"].get(c, {}).get("triage") or {}).get("decision")]
    stale = []
    for c in db["cves"].values():
        t = c.get("triage") or {}
        if t.get("decision"):
            s = staleness(t.get("verified_at"), st)
            if s["level"] in ("warn", "crit"):
                stale.append({"cve": c["id"], "decision": t["decision"], **s})
    for p in db["products"].values():
        if p.get("status") == "not_used":
            s = staleness(p.get("verified_at"), st)
            if s["level"] in ("warn", "crit", "never"):
                stale.append({"product_id": p["id"], "product": p["name"], "decision": "not_used", **s})
    exc_overdue = [e for e in db["exceptions"] if e.get("active", True) and parse_date(e.get("review_at"))
                   and parse_date(e.get("review_at")) < ctx.today]
    recent_kev = sorted(kev.values(), key=lambda e: e.get("dateAdded", ""), reverse=True)[:8]
    rep_team = grouped_report(db, group="team", with_rows=False, ctx=ctx)
    by_team = [{k: g[k] for k in ("key", "label", "hosts", "installations", "open", "open_kev", "progress")}
               for g in rep_team["groups"]]
    return {
        "hosts": len(hosts), "products_used": sum(1 for p in db["products"].values() if p.get("status") == "used"),
        "products_not_used": sum(1 for p in db["products"].values() if p.get("status") == "not_used"),
        "installations": sum(1 for i in db["inventory"].values() if not i.get("removed")),
        "cves": len(db["cves"]), "open_findings": open_total,
        "open_kev": sum(h["open_kev"] for h in hosts),
        "host_status": dict(status_counts),
        "top_hosts": sorted([h for h in hosts if h["open"]],
                            key=lambda h: (EXPOSURE_RANK.get(h.get("exposure") or "", 3), -h["open_kev"], -h["open"]))[:10],
        "kev_total": len(kev), "kev_pending": len(pending), "kev_updated_at": db["kev"].get("updated_at"),
        "recent_kev": [{"cve": e["cveID"], "vendor": e.get("vendorProject"), "product": e.get("product"),
                        "dateAdded": e.get("dateAdded"),
                        "decision": (db["cves"].get(e["cveID"], {}).get("triage") or {}).get("decision")}
                       for e in recent_kev],
        "stale": sorted(stale, key=lambda s: -(s["days"] or 99999))[:15],
        "exceptions_overdue": exc_overdue,
        "imports": [{k: i[k] for k in ("id", "name", "created_at", "rows")} for i in db["imports"][-5:]][::-1],
        "by_company": breakdown(db, "company", ctx)[:12],
        "by_team": by_team[:12],
        "overdue": rep_team["totals"]["overdue"],
    }


# ---------------------------------------------------------------- porównanie importów
def compare_imports(db, a_id, b_id, load_obs=None):
    """Porównanie dwóch importów na poziomie para host+aplikacja (kilka gałęzi = jedna pozycja)."""
    load_obs = load_obs or _default_obs
    ctx = Ctx(db)
    imps = {i["id"]: i for i in db["imports"]}
    A, B = imps[a_id], imps[b_id]
    obs_a, obs_b = load_obs(A) or [], load_obs(B) or []

    def group(obs):
        g = defaultdict(list)
        for o in obs:
            g[(o["h"], o["p"])].append(o)
        return g

    def state(lst):
        host = db["hosts"].get(lst[0]["h"])
        open_, fs_all = set(), []
        for o in lst:
            fs = findings_for(ctx, host, o["p"], o["v"], o.get("c"))
            fs_all += fs
            open_ |= {f["cve"] for f in fs if f["status"] in ACTION}
        return open_, fs_all

    ga, gb = group(obs_a), group(obs_b)
    units = []          # (klucz pary, lista A, lista B)
    kk = lambda o: o.get("k") or inv_key(o["h"], o["p"])  # noqa: E731
    for key in sorted(set(ga) | set(gb)):
        la, lb = ga.get(key) or [], gb.get(key) or []
        ka, kb = {kk(o) for o in la}, {kk(o) for o in lb}
        if la and lb and ka == kb and len(ka) > 1:       # te same gałęzie w obu importach — porównanie per gałąź
            for k in sorted(ka):
                units.append((key, [o for o in la if kk(o) == k], [o for o in lb if kk(o) == k]))
        else:
            units.append((key, la, lb))
    rows = []
    for key, la, lb in units:
        la, lb = la or None, lb or None
        host = db["hosts"].get(key[0])
        if host is None:
            continue
        prod = db["products"].get(key[1], {})
        ra, _ = state(la) if la else (set(), [])
        rb, fb = state(lb) if lb else (set(), [])
        if la and not lb:
            cat = "missing"
        elif lb and not la:
            cat = "new_vuln" if rb else "new_ok"
        elif ra and not rb:
            cat = "patched"
        elif ra and rb:
            cat = "still" if not (rb - ra) else "worse"
        elif rb:
            cat = "new_vuln"
        else:
            cat = "ok"
        vers = lambda lst: ", ".join(sorted({o["v"] or "?" for o in lst}, key=V.sort_key())) if lst else None  # noqa: E731
        tid, _ = ctx.teams.team(host, key[1])
        rows.append({"key": inv_key(*key), "host_id": key[0], "hostname": host.get("hostname", "?"),
                     "owner": host.get("owner", ""), "company": host.get("company", ""),
                     "team": ctx.teams.label(tid), "product": prod.get("name", "?"),
                     "va": vers(la), "vb": vers(lb),
                     "open_a": sorted(ra), "open_b": sorted(rb), "fixed_cves": sorted(ra - rb),
                     "target": summarize(fb)["target"] if lb else None, "category": cat})
    cats = defaultdict(int)
    for r in rows:
        cats[r["category"]] += 1
    order = ["worse", "new_vuln", "still", "patched", "missing", "new_ok", "ok"]
    rows.sort(key=lambda r: (order.index(r["category"]), r["product"], r["hostname"]))
    return {"a": {k: A[k] for k in ("id", "name", "created_at")}, "b": {k: B[k] for k in ("id", "name", "created_at")},
            "counts": dict(cats), "rows": rows}


# ---------------------------------------------------------------- KEV
GENERIC = {"the", "and", "for", "server", "client", "software", "system", "systems", "multiple", "products",
           "product", "service", "services", "edition", "enterprise", "inc", "corporation", "corp"}


# słowa z katalogu KEV -> słowa, pod którymi produkt zwykle występuje w inwentarzu
KEV_SYNONYMS = {
    "chromium": {"chrome", "edge", "chromium", "brave", "opera"}, "win32k": {"windows"}, "smbv1": {"windows"},
    "exchange": {"exchange"}, "sharepoint": {"sharepoint"}, "office": {"office", "word", "excel", "outlook", "365"},
    "acrobat": {"acrobat", "reader"}, "reader": {"acrobat", "reader"}, "jre": {"java"}, "java": {"java", "jre", "jdk"},
    "ios": {"ios"}, "fortios": {"fortios", "fortigate"}, "pan-os": {"pan", "panos"}, "esxi": {"esxi", "vmware"},
    "vcenter": {"vcenter", "vmware"}, "httpd": {"apache", "httpd"}, "http": {"apache", "httpd"},
}


def kev_candidates(db, vendor, product, usage=None, linked=()):
    usage = usage if usage is not None else product_usage(db)
    nprod, nvend = norm(product), norm(vendor)
    pw = words(product) - GENERIC
    for w in list(pw):
        pw |= KEV_SYNONYMS.get(w, set())
    vw = words(vendor) - GENERIC
    out = []
    for p in db["products"].values():
        names = [p.get("name", "")] + list(p.get("aliases") or [])
        score = 0.0
        for n in names:
            nn = norm(n)
            if not nn:
                continue
            if nn == nprod or nn == nvend + nprod:
                score = max(score, 1.0)
            elif len(nprod) >= 4 and (nprod in nn or (len(nn) >= 4 and nn in nprod)):
                score = max(score, 0.8)
            else:
                ow = words(n) - GENERIC
                if pw and ow & pw:
                    s = 0.45 + 0.4 * len(ow & pw) / len(pw)
                    if vw and (vw & (ow | words(p.get("vendor")))):
                        s += 0.15
                    score = max(score, min(s, 0.9))
        if p["id"] in linked:
            score = 1.0
        if score >= 0.5:
            out.append({"product_id": p["id"], "name": p["name"], "vendor": p.get("vendor", ""),
                        "linked": p["id"] in linked,
                        "status": p.get("status"), "hosts": usage.get(p["id"], 0),
                        "verified_at": p.get("verified_at"), "score": round(score, 2)})
    out.sort(key=lambda x: (-x["score"], -x["hosts"]))
    return out[:8]


def kev_key(vendor, product):
    return f"{norm(vendor)}|{norm(product)}"


# ---------------------------------------------------------------- raporty grupowane
GROUP_FIELDS = {"company": "Spółka", "team": "Zespół (realizator)", "type": "Typ urządzenia", "os": "System",
                "environment": "Środowisko", "location": "Lokalizacja", "owner": "Właściciel", "product": "Aplikacja",
                "exposure": "Ekspozycja"}


def grouped_report(db, group="company", product_ids=None, cve_id=None, kev_only=False, only_open=True,
                   filters=None, with_rows=True, ctx=None):
    """Instalacje (host × aplikacja) pogrupowane wg spółki / zespołu / typu itd.

    product_ids: zawęża do aplikacji; cve_id: tylko instalacje, których dotyczy CVE (ocena tylko tego CVE);
    kev_only: liczone są tylko podatności z KEV; only_open: w wierszach tylko instalacje wymagające działań;
    filters: {"company": ..., "team": ..., "type": ...} — dokładne dopasowanie.
    """
    ctx = ctx or Ctx(db)
    group = group if group in GROUP_FIELDS else "company"
    filters = {k: v for k, v in (filters or {}).items() if v}
    if product_ids:
        insts = [i for pid in product_ids for i in ctx.inv_prod(pid)]
    elif cve_id and cve_id in db["cves"]:
        pids = {r["product_id"] for r in db["cves"][cve_id].get("rules", [])}
        insts = [i for pid in pids for i in ctx.inv_prod(pid)]
        insts += [i for i in db["inventory"].values() if not i.get("removed") and i["product_id"] not in pids
                  and cve_id in (i.get("reported_cves") or [])]
    else:
        insts = [i for i in db["inventory"].values() if not i.get("removed")]
    groups = {}
    hosts_seen = defaultdict(set)
    for inst in insts:
        host = db["hosts"].get(inst["host_id"])
        if not host:
            continue
        pid = inst["product_id"]
        tid, tsrc = ctx.teams.team(host, pid)
        attrs = {"company": host.get("company") or "", "team": tid, "type": host.get("type") or "",
                 "os": host.get("os") or "", "environment": host.get("environment") or "",
                 "location": host.get("location") or "", "owner": host.get("owner") or "",
                 "exposure": host.get("exposure") or "", "product": pid}
        if any(attrs.get(k, "") != v for k, v in filters.items()):
            continue
        fs = findings_for(ctx, host, pid, inst.get("version"), inst.get("reported_cves"))
        if cve_id:
            fs = [f for f in fs if f["cve"] == cve_id]
        if kev_only:
            fs = [f for f in fs if f["kev"]]
        if (cve_id or kev_only) and not fs:
            continue
        s = summarize(fs, ctx)
        key = attrs[group] or UNASSIGNED
        if group == "team":
            label = ctx.teams.label(key)
        elif group == "product":
            label = (db["products"].get(pid) or {}).get("name", "?")
        elif group == "exposure":
            label = EXPOSURE_LABELS.get(key if key != UNASSIGNED else "", key)
        else:
            label = key if key != UNASSIGNED else "(nie przypisano)"
        g = groups.setdefault(key, {"key": key, "label": label, "hosts": 0, "installations": 0, "open": 0,
                                    "open_findings": 0, "open_kev": 0, "overdue": 0, "ok": 0,
                                    "exception": 0, "mitigated": 0, "rows": []})
        hosts_seen[key].add(host["id"])
        g["installations"] += 1
        is_open = s["status"] in ACTION
        open_f = [f for f in fs if f["status"] in ACTION]
        due = sorted(f["deadline"] for f in open_f if f.get("deadline"))
        overdue = bool(due and parse_date(due[0]) and parse_date(due[0]) < ctx.today)
        risks = [f["risk"] for f in open_f if f.get("risk")]
        risk = min(risks, key=lambda r: list(RISK_LABELS).index(r)) if risks else None
        if is_open:
            g["open"] += 1
            g["open_findings"] += len(open_f)
            g["open_kev"] += sum(1 for f in open_f if f["kev"])
            g["overdue"] += 1 if overdue else 0
        else:
            g["ok"] += 1
        g["exception"] += 1 if s["status"] == "exception" else 0
        g["mitigated"] += 1 if s["status"] == "mitigated" else 0
        if with_rows and (is_open or not only_open):
            prod = db["products"].get(pid) or {}
            g["rows"].append({
                "host_id": host["id"], "hostname": host.get("hostname", ""), "ip": host.get("ip", ""),
                "type": host.get("type", ""), "os": host.get("os", ""), "company": host.get("company", ""),
                "team": ctx.teams.label(tid), "team_source": tsrc, "environment": host.get("environment", ""),
                "exposure": host.get("exposure", ""), "owner": host.get("owner", ""), "admin": host.get("admin", ""),
                "product_id": pid, "product": prod.get("name", "?"), "version": inst.get("version", ""),
                "status": s["status"], "target": s["target"], "nofix": s["nofix"],
                "cves": [f["cve"] for f in open_f], "kev": [f["cve"] for f in open_f if f["kev"]],
                "deadline": due[0] if due else None, "overdue": overdue, "risk": risk,
                "reason": "; ".join(f"{f['cve']}: {f['reason']}" for f in open_f[:3]) if open_f else
                          "; ".join(f"{f['cve']}: {(f.get('overlay') or {}).get('text') or f['reason']}" for f in fs[:2]),
            })
    out = []
    for key, g in groups.items():
        g["hosts"] = len(hosts_seen[key])
        g["progress"] = round(100 * g["ok"] / g["installations"]) if g["installations"] else 100
        g["rows"].sort(key=lambda r: (not r["overdue"], -len(r["kev"]), r["hostname"].lower(), r["product"]))
        out.append(g)
    out.sort(key=lambda g: (g["key"] == UNASSIGNED, -g["open_kev"], -g["open"], g["label"].lower()))
    tot = {k: sum(g[k] for g in out) for k in ("installations", "open", "open_findings", "open_kev", "overdue",
                                                "ok", "exception", "mitigated")}
    tot["hosts"] = len(set().union(*hosts_seen.values())) if hosts_seen else 0
    tot["progress"] = round(100 * tot["ok"] / tot["installations"]) if tot["installations"] else 100
    return {"group": group, "group_label": GROUP_FIELDS[group], "groups": out, "totals": tot}


def breakdown(db, group, ctx=None):
    r = grouped_report(db, group=group, with_rows=False, ctx=ctx)
    return [{k: g[k] for k in ("key", "label", "hosts", "installations", "open", "open_kev", "progress")}
            for g in r["groups"]]
