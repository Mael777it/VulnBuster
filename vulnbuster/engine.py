# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Silnik oceny: reguły wersji CVE x inwentarz hostów, mitygacje, wyjątki, raporty, porównania."""
from __future__ import annotations

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


def make_finding(ctx, host, pid, cve, ev):
    cid = cve["id"]
    k = ctx.kev.get(cid)
    f = {
        "cve": cid, "title": cve.get("title") or (k or {}).get("vulnerabilityName") or "",
        "cvss": cve.get("cvss"), "kev": bool(k), "kev_due": (k or {}).get("dueDate"),
        "kev_ransomware": (k or {}).get("knownRansomwareCampaignUse") == "Known",
        "base_status": ev["status"], "status": ev["status"], "reason": ev["reason"],
        "target": ev.get("target"), "branch": ev.get("branch"), "overlay": None,
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


def summarize(findings):
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
        "host_id": inst["host_id"], "hostname": (host or {}).get("hostname", "?"),
        "product_id": prod["id"], "product": prod.get("name"), "vendor": prod.get("vendor", ""),
        "version": inst.get("version"), "last_seen": inst.get("last_seen"),
        "history": inst.get("history", [])[-6:], "findings": fs, "summary": summarize(fs),
    }


def host_installations(db, hid):
    return [i for i in db["inventory"].values() if i["host_id"] == hid and not i.get("removed")]


def product_installations(db, pid):
    return [i for i in db["inventory"].values() if i["product_id"] == pid and not i.get("removed")]


# ---------------------------------------------------------------- widoki
def host_summary_row(ctx, host):
    insts = [installation_view(ctx, i) for i in host_installations(ctx.db, host["id"])]
    allf = [f for iv in insts for f in iv["findings"]]
    s = summarize(allf)
    return {k: host.get(k, "") for k in ("id", "hostname", "ip", "type", "os", "environment", "owner",
                                          "admin", "criticality", "location", "exposure")} | {
        "apps": len(insts), "status": s["status"], "open": s["open"], "open_kev": s["open_kev"],
        "mitigations": len(host.get("mitigations") or []), "updated_at": host.get("updated_at"),
    }


def host_report(db, hid):
    ctx = Ctx(db)
    host = db["hosts"][hid]
    insts = sorted((installation_view(ctx, i) for i in host_installations(db, hid)),
                   key=lambda x: (ORDER.index(x["summary"]["status"]), (x["product"] or "").lower()))
    allf = [f for iv in insts for f in iv["findings"]]
    exc = [e for e in db["exceptions"] if e.get("host_id") == hid]
    return {"host": host, "installations": insts, "summary": summarize(allf),
            "exceptions": exc, "groups": db["settings"]["groups"]}


def product_report(db, pid):
    ctx = Ctx(db)
    prod = db["products"][pid]
    insts = [installation_view(ctx, i) for i in product_installations(db, pid)]
    for iv in insts:
        h = db["hosts"].get(iv["host_id"], {})
        iv.update({"owner": h.get("owner", ""), "admin": h.get("admin", ""), "type": h.get("type", ""),
                   "exposure": h.get("exposure", ""),
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
            "trend": product_trend(db, ctx, pid),
            "exceptions": [e for e in db["exceptions"] if e.get("product_id") == pid]}


def product_trend(db, ctx, pid):
    out = []
    for imp in db["imports"]:
        obs = [o for o in imp.get("observations", []) if o["p"] == pid]
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
    for inst in db["inventory"].values():
        if inst.get("removed"):
            continue
        if inst["product_id"] not in pids and cid not in (inst.get("reported_cves") or []):
            continue
        host = db["hosts"].get(inst["host_id"])
        fs = [f for f in findings_for(ctx, host, inst["product_id"], inst.get("version"), inst.get("reported_cves"))
              if f["cve"] == cid]
        if not fs:
            continue
        f = fs[0]
        prod = db["products"].get(inst["product_id"], {})
        rows.append({"host_id": inst["host_id"], "hostname": (host or {}).get("hostname", "?"),
                     "owner": (host or {}).get("owner", ""), "product_id": inst["product_id"],
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
    }


# ---------------------------------------------------------------- porównanie importów
def compare_imports(db, a_id, b_id):
    ctx = Ctx(db)
    imps = {i["id"]: i for i in db["imports"]}
    A, B = imps[a_id], imps[b_id]

    def state(o):
        host = db["hosts"].get(o["h"])
        fs = findings_for(ctx, host, o["p"], o["v"], o.get("c"))
        return {f["cve"] for f in fs if f["status"] in ACTION}, fs

    ma = {inv_key(o["h"], o["p"]): o for o in A.get("observations", [])}
    mb = {inv_key(o["h"], o["p"]): o for o in B.get("observations", [])}
    rows = []
    for k in sorted(set(ma) | set(mb)):
        oa, ob = ma.get(k), mb.get(k)
        o = ob or oa
        host = db["hosts"].get(o["h"], {})
        prod = db["products"].get(o["p"], {})
        ra, _ = state(oa) if oa else (set(), [])
        rb, fb = state(ob) if ob else (set(), [])
        if oa and not ob:
            cat = "missing"
        elif ob and not oa:
            cat = "new_vuln" if rb else "new_ok"
        elif ra and not rb:
            cat = "patched"
        elif ra and rb:
            cat = "still" if not (rb - ra) else "worse"
        elif rb:
            cat = "new_vuln"
        else:
            cat = "ok"
        rows.append({"key": k, "host_id": o["h"], "hostname": host.get("hostname", "?"),
                     "owner": host.get("owner", ""), "product": prod.get("name", "?"),
                     "va": oa["v"] if oa else None, "vb": ob["v"] if ob else None,
                     "open_a": sorted(ra), "open_b": sorted(rb), "fixed_cves": sorted(ra - rb),
                     "target": summarize(fb)["target"] if ob else None, "category": cat})
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


def kev_candidates(db, vendor, product, usage=None):
    usage = usage if usage is not None else product_usage(db)
    nprod, nvend = norm(product), norm(vendor)
    pw = words(product) - GENERIC
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
        if score >= 0.5:
            out.append({"product_id": p["id"], "name": p["name"], "vendor": p.get("vendor", ""),
                        "status": p.get("status"), "hosts": usage.get(p["id"], 0),
                        "verified_at": p.get("verified_at"), "score": round(score, 2)})
    out.sort(key=lambda x: (-x["score"], -x["hosts"]))
    return out[:8]


def kev_key(vendor, product):
    return f"{norm(vendor)}|{norm(product)}"
