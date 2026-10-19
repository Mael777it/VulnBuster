# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Źródła zewnętrzne (opcjonalne, gdy serwer ma dostęp do Internetu): CISA KEV i NVD."""
from __future__ import annotations

import json
import re
import urllib.request
from collections import OrderedDict

from . import engine as E
from . import versions as V
from .storage import now_iso

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
UA = {"User-Agent": "vulnbuster/1.0 (on-prem vulnerability tracker)"}
KEV_FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
              "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes", "cwes")


def http_json(url: str, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_kev():
    return http_json(KEV_URL, timeout=60)


def merge_kev(db, data: dict) -> dict:
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("To nie wygląda na katalog KEV (brak pola 'vulnerabilities')")
    entries = db["kev"]["entries"]
    added = []
    ts = now_iso()
    for v in vulns:
        cid = str(v.get("cveID", "")).upper().strip()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cid):
            continue
        e = {k: v.get(k) for k in KEV_FIELDS if k in v}
        e["cveID"] = cid
        if cid not in entries:
            e["_first_seen"] = ts
            added.append(cid)
        else:
            e["_first_seen"] = entries[cid].get("_first_seen", ts)
        entries[cid] = e
    db["kev"]["updated_at"] = ts
    db["kev"]["catalog_version"] = data.get("catalogVersion")
    return {"total": len(entries), "added": len(added), "added_ids": added[:50],
            "catalog_version": data.get("catalogVersion")}


# ---------------------------------------------------------------- NVD
def fetch_nvd(cid: str) -> dict:
    data = http_json(NVD_URL.format(cid))
    vs = data.get("vulnerabilities") or []
    if not vs:
        raise ValueError(f"NVD nie zna {cid}")
    return vs[0]["cve"]


def _cvss(metrics: dict):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lst = metrics.get(key) or []
        if lst:
            primary = next((m for m in lst if m.get("type") == "Primary"), lst[0])
            d = primary.get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity") or primary.get("baseSeverity"), d.get("vectorString")
    return None, None, None


def parse_nvd(db, cve: dict) -> dict:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, sev, vector = _cvss(cve.get("metrics", {}))
    groups = []
    if vector and ("AV:N" in vector) and ("PR:N" in vector):
        groups.append("remote-unauth")
    elif vector and "AV:N" in vector:
        groups.append("remote-auth")
    elif vector and ("AV:L" in vector or "AV:P" in vector):
        groups.append("local")
    if vector and "UI:R" in vector or (vector and "UI:A" in vector) or (vector and "UI:P" in vector):
        groups.append("user-interaction")
    products = OrderedDict()
    usage = E.product_usage(db)
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, prod, ver = parts[3], parts[4], parts[5]
                key = (vendor, prod)
                p = products.setdefault(key, {"vendor": vendor, "product": prod, "branches": [], "exact": []})
                start = m.get("versionStartIncluding") or m.get("versionStartExcluding") or ""
                end_ex, end_in = m.get("versionEndExcluding"), m.get("versionEndIncluding")
                if end_ex:
                    p["branches"].append({"branch": V.derive_branch(end_ex), "introduced": start,
                                          "fixed": end_ex, "state": "fix", "note": "NVD"})
                elif end_in:
                    p["branches"].append({"branch": V.derive_branch(end_in), "introduced": start, "fixed": "",
                                          "state": "nofix", "note": f"NVD: podatne do {end_in} włącznie, "
                                                                    f"brak wersji naprawionej — uzupełnij"})
                elif ver not in ("*", "-", ""):
                    p["exact"].append(ver)
    sugg = []
    for (vendor, prod), p in products.items():
        # deduplikacja gałęzi
        seen, br = set(), []
        for b in p["branches"]:
            k = (b["branch"], b["fixed"])
            if k not in seen:
                seen.add(k)
                br.append(b)
        br.sort(key=lambda b: V.numeric_prefix(b["branch"]) or [0])
        name = prod.replace("_", " ")
        sugg.append({"vendor": vendor.replace("_", " "), "product": name, "branches": br,
                     "exact_versions": p["exact"][:30],
                     "candidates": E.kev_candidates(db, vendor.replace("_", " "), name, usage)})
    return {"id": cve.get("id"), "description": desc, "cvss": score, "severity": sev, "vector": vector,
            "published": cve.get("published"), "groups": groups, "products": sugg[:15]}
