# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""Zgłoszenia do realizatorów: gotowe treści ticketów / maili per zespół (i opcjonalnie per spółka)."""
from __future__ import annotations

import csv
import io
from collections import OrderedDict
from datetime import date
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import engine as E
from . import versions as V

DEFAULT_PREFIX = "VULN"
DEFAULT_SUBJECT = "[{prefiks}] {cve} — {tytul} — {zespol}{spolka_sufiks} (termin: {termin})"
DEFAULT_TEMPLATE = """Dzień dobry,

prosimy o usunięcie podatności {cve} na hostach wymienionych poniżej.

OCENA RYZYKA: {ryzyko} ({wynik}/10) · CVSS {cvss}
CISA KEV (aktywnie wykorzystywana): {kev}
TERMIN REALIZACJI: {termin}

OPIS PODATNOŚCI:
{opis}

JAK MOŻE ZOSTAĆ WYKORZYSTANA:
{wykorzystanie}

WPŁYW NA ORGANIZACJĘ:
{wplyw}

WYMAGANE DZIAŁANIE:
{zalecenie}

HOSTY DO ZAŁATANIA ({liczba_hostow}):
{hosty}

Jeżeli aktualizacja nie jest możliwa w terminie, prosimy o informację zwrotną z uzasadnieniem,
proponowanym terminem oraz zastosowanymi środkami kompensującymi.

{podpis}
"""
DEFAULT_SIGNATURE = "Pozdrawiam,\nZespół Bezpieczeństwa IT"
PLACEHOLDERS = {
    "prefiks": "prefiks zgłoszeń z ustawień", "cve": "identyfikator(y) CVE", "tytul": "tytuł podatności",
    "opis": "opis CVE", "ryzyko": "Twoja wycena ryzyka (poziom)", "wynik": "Twoja ocena 0–10", "cvss": "CVSS",
    "kev": "czy w CISA KEV (+ ransomware)", "wplyw": "wpływ na organizację", "wykorzystanie": "jak może zostać wykorzystana",
    "zalecenie": "wymagane działanie / wersje docelowe", "termin": "termin załatania", "zespol": "zespół realizujący",
    "spolka": "spółka (przy podziale na spółki)", "spolka_sufiks": "„ — spółka” przy podziale na spółki",
    "aplikacja": "aplikacja(e)", "liczba_hostow": "liczba hostów", "hosty": "lista hostów", "podpis": "podpis",
    "data": "data przygotowania",
}


class _Safe(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _txt(v, empty="—"):
    v = (v or "").strip() if isinstance(v, str) else v
    return v if v not in (None, "") else empty


def _section(cves, field, fallback=None):
    """Treść pola dla jednego lub wielu CVE (przy wielu — z nagłówkami)."""
    parts = []
    for c in cves:
        a = c.get("assessment") or {}
        val = a.get(field) if field in ("impact", "exploitation", "recommendation") else c.get(field)
        if not val and fallback:
            val = fallback(c)
        if val:
            parts.append((c["id"], str(val).strip()))
    if not parts:
        return "—"
    if len(cves) == 1:
        return parts[0][1]
    return "\n\n".join(f"{cid}:\n{txt}" for cid, txt in parts)


def _recommendation(cves, rows, kev_entries):
    own = _section(cves, "recommendation")
    groups = OrderedDict()           # (aplikacja, gałąź) -> {target, hosts, nofix}
    for r in rows:
        if r.get("target"):
            br = V.derive_branch(r["target"])
        else:
            n = V.numeric_prefix(r.get("version"))
            br = str(n[0]) if n else "?"
        g = groups.setdefault((r["product"], br), {"targets": set(), "hosts": set(), "nofix": False, "review": False})
        g["hosts"].add(r["host_id"])
        if r.get("target"):
            g["targets"].add(r["target"])
        elif r.get("nofix"):
            g["nofix"] = True
        else:
            g["review"] = True
    lines = []
    for (prod, br), g in sorted(groups.items(), key=lambda x: (x[0][0], V.numeric_prefix(x[0][1]) or [0])):
        label = f"{prod} {br}.x" if br not in ("*", "?") else prod
        n = len(g["hosts"])
        hosts = f"{n} {'host' if n == 1 else 'hostów'}"
        if g["targets"]:
            lines.append(f"- {label}: aktualizacja co najmniej do {V.max_version(list(g['targets']))} ({hosts})")
        elif g["nofix"]:
            lines.append(f"- {label}: gałąź bez poprawki — migracja do wspieranej wersji ({hosts})")
        else:
            lines.append(f"- {label}: weryfikacja wersji i aktualizacja do wersji z poprawką producenta ({hosts})")
    kev_act = "; ".join(sorted({kev_entries[c["id"]].get("requiredAction", "") for c in cves
                                if c["id"] in kev_entries and kev_entries[c["id"]].get("requiredAction")}))
    parts = [x for x in (own if own != "—" else "", "\n".join(lines), f"Zalecenie CISA: {kev_act}" if kev_act else "") if x]
    return "\n".join(parts) or "Aktualizacja do wersji zawierającej poprawkę producenta."


def host_lines(rows):
    out = []
    for r in rows:
        tgt = r.get("target") or ("migracja" if r.get("nofix") else "?")
        kev = " [KEV]" if r.get("kev") else ""
        comp = f" — {r['company']}" if r.get("company") else ""
        ip = f" ({r['ip']})" if r.get("ip") else ""
        out.append(f"- {r['hostname']}{ip}{comp} — {r['product']} {r['version'] or '?'} → {tgt}{kev}")
    return "\n".join(out) or "—"


def csv_text(rows):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Host", "IP", "Spółka", "Typ", "System", "Środowisko", "Właściciel", "Administrator", "Aplikacja",
                "Wersja obecna", "Wersja docelowa", "CVE", "KEV", "Termin"])
    for r in rows:
        w.writerow([r["hostname"], r.get("ip", ""), r.get("company", ""), r.get("type", ""), r.get("os", ""),
                    r.get("environment", ""), r.get("owner", ""), r.get("admin", ""), r["product"], r["version"],
                    r.get("target") or ("migracja" if r.get("nofix") else ""), " ".join(r.get("cves", [])),
                    " ".join(r.get("kev", [])), r.get("deadline") or ""])
    return "﻿" + buf.getvalue()


def build(db, cve_id=None, product_id=None, split="team", only_teams=None):
    """Zwraca listę zgłoszeń: jedno na zespół (split='team') lub zespół+spółkę (split='team_company')."""
    st = db["settings"]
    if not cve_id and not product_id:
        raise ValueError("Wybierz CVE albo aplikację")
    rep = E.grouped_report(db, group="team", product_ids=[product_id] if product_id else None, cve_id=cve_id)
    teams = {t["id"]: t for t in st.get("teams", [])}
    kev = db["kev"]["entries"]
    out = []
    for g in rep["groups"]:
        if not g["rows"]:
            continue
        if only_teams and g["key"] not in only_teams:
            continue
        buckets = OrderedDict()
        if split == "team_company":
            for r in g["rows"]:
                buckets.setdefault(r.get("company") or "", []).append(r)
        else:
            buckets[""] = g["rows"]
        for company, rows in buckets.items():
            cids = sorted({c for r in rows for c in r["cves"]})
            cves = [db["cves"].get(c) or {"id": c} for c in cids]
            assess = [c.get("assessment") or {} for c in cves]
            risks = [a.get("risk") for a in assess if a.get("risk")]
            risk = min(risks, key=lambda r: list(E.RISK_LABELS).index(r)) if risks else None
            scores = [float(a["score"]) for a in assess if a.get("score") not in (None, "")]
            cvss = [c.get("cvss") for c in cves if c.get("cvss") is not None]
            deadlines = sorted(r["deadline"] for r in rows if r.get("deadline"))
            in_kev = [c for c in cids if c in kev]
            ransom = any(kev[c].get("knownRansomwareCampaignUse") == "Known" for c in in_kev)
            team = teams.get(g["key"], {})
            products = sorted({r["product"] for r in rows})
            title = (cves[0].get("title") or (kev.get(cids[0]) or {}).get("vulnerabilityName") or "") if len(cves) == 1 \
                else f"{len(cves)} podatności w {', '.join(products)}"
            vars_ = _Safe({
                "prefiks": st.get("ticket_prefix") or DEFAULT_PREFIX,
                "cve": ", ".join(cids) or (cve_id or ""),
                "tytul": _txt(title, products[0] if products else ""),
                "opis": _section(cves, "description", lambda c: (kev.get(c["id"]) or {}).get("shortDescription")),
                "ryzyko": E.RISK_LABELS.get(risk, "nieocenione"),
                "wynik": f"{max(scores):g}" if scores else "—",
                "cvss": f"{max(cvss):g}" if cvss else "—",
                "kev": ("TAK" + (" — wykorzystywana w kampaniach ransomware" if ransom else "")) if in_kev else "nie",
                "wplyw": _section(cves, "impact"),
                "wykorzystanie": _section(cves, "exploitation"),
                "zalecenie": _recommendation(cves, rows, kev),
                "termin": deadlines[0] if deadlines else "wg SLA",
                "zespol": g["label"],
                "spolka": company or "",
                "spolka_sufiks": f" — {company}" if company else "",
                "aplikacja": ", ".join(products),
                "liczba_hostow": str(len({r["host_id"] for r in rows})),
                "hosty": host_lines(rows),
                "podpis": st.get("ticket_signature") or DEFAULT_SIGNATURE,
                "data": date.today().isoformat(),
            })
            subject = (st.get("ticket_subject") or DEFAULT_SUBJECT).format_map(vars_).strip()
            body = (st.get("ticket_template") or DEFAULT_TEMPLATE).format_map(vars_).strip() + "\n"
            prev = [t for t in db.get("tickets", []) if t.get("team") == g["key"]
                    and (t.get("cve") == cve_id if cve_id else t.get("product") == product_id)
                    and (t.get("company") or "") == company]
            out.append({"team": g["key"], "team_label": g["label"], "company": company,
                        "email": team.get("email", ""), "subject": subject, "body": body,
                        "hosts": len({r["host_id"] for r in rows}), "installations": len(rows),
                        "cves": cids, "deadline": deadlines[0] if deadlines else None, "risk": risk,
                        "rows": rows, "csv": csv_text(rows), "sent": prev[-1] if prev else None})
    return out


def eml(to, subject, body, csv_rows_text=None, filename="hosty.csv", sender=""):
    """Wiadomość .eml jako szkic (X-Unsent: 1 — Outlook otwiera ją do edycji i wysłania)."""
    m = EmailMessage()
    m["Subject"] = subject
    m["To"] = to or ""
    if sender:
        m["From"] = sender
    m["Date"] = formatdate(localtime=True)
    m["Message-ID"] = make_msgid(domain="vulnbuster.local")
    m["X-Unsent"] = "1"
    m.set_content(body, charset="utf-8")
    if csv_rows_text:
        m.add_attachment(csv_rows_text.encode("utf-8"), maintype="text", subtype="csv", filename=filename)
    return bytes(m)
