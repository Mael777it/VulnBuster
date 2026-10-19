/* SPDX-License-Identifier: MIT · Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com> */
/* VulnBuster — wspólne funkcje: API, formatowanie, odznaki, CSV, router */
'use strict';

const App = { meta: null, products: null, routes: [] };

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = encodeURIComponent;

async function api(method, path, body) {
  const opt = { method, headers: { 'X-Requested-With': 'vulnbuster' }, credentials: 'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let data = {};
  try { data = await r.json(); } catch (e) { /* brak treści */ }
  if ((r.status === 401 || r.status === 423) && !path.startsWith('/api/unlock') && !path.startsWith('/api/init')) {
    App.meta = null;
    showLogin();
    throw new Error(data.error || 'Wymagane logowanie');
  }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}
const GET = (p) => api('GET', p);
const POST = (p, b) => api('POST', p, b ?? {});
const PUT = (p, b) => api('PUT', p, b ?? {});
const DEL = (p) => api('DELETE', p);

let toastTimer;
function toast(msg, err = false) {
  let t = $('.toast');
  if (!t) { t = document.createElement('div'); document.body.append(t); }
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), err ? 7000 : 3200);
}
async function guard(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { toast(e.message, true); return undefined; }
}

/* ---------- formatowanie ---------- */
const fmtDate = (s) => (s ? String(s).slice(0, 10) : '—');
const fmtDT = (s) => (s ? String(s).slice(0, 16).replace('T', ' ') : '—');
function daysTxt(d) {
  if (d === null || d === undefined) return 'nigdy';
  if (d === 0) return 'dziś';
  if (d === 1) return 'wczoraj';
  if (d < 60) return d + ' dni temu';
  return Math.round(d / 30) + ' mies. temu';
}
const STATUS = {
  vulnerable: 'Podatne', review: 'Do weryfikacji', exception: 'Wyjątek', mitigated: 'Mitygowane',
  fixed: 'Załatane', not_affected: 'Niepodatne', none: 'Brak CVE', rule: 'Reguła CVE', host: 'Dane hosta', skip: 'Pominięte',
};
const badge = (s) => `<span class="b ${esc(s)}">${esc(STATUS[s] || s)}</span>`;
function staleBadge(st, prefix = '') {
  if (!st) return '';
  const cls = { fresh: 'fresh', warn: 'warn', crit: 'crit', never: 'never' }[st.level];
  const icon = st.level === 'fresh' ? '' : '⚠ ';
  return `<span class="b ${cls}" title="Data ostatniej weryfikacji">${icon}${esc(prefix)}${esc(daysTxt(st.days))}</span>`;
}
function expBadge(e) {
  const L = { internet: 'Internet', dmz: 'DMZ', internal: 'Wewnętrzna', unknown: 'Nieznana' };
  if (!e) return '<span class="faint">—</span>';
  return `<span class="b exp-${esc(e)}">${esc(L[e] || e)}</span>`;
}
function triageBadge(t) {
  if (!t || !t.decision) return '<span class="b outline">bez decyzji</span>';
  const L = { affected: 'Dotyczy nas', used_safe: 'Używamy — niepodatne', not_used: 'Nie używamy', not_applicable: 'Nie dotyczy', pending: 'W analizie' };
  return `<span class="b t-${esc(t.decision)}">${esc(L[t.decision] || t.decision)}</span>`;
}
function prodBadge(s) {
  const L = { used: '✔ Używamy', not_used: '✖ Nie używamy', unknown: '? Nie wiadomo' };
  return `<span class="b ${esc(s || 'unknown')}">${esc(L[s] || L.unknown)}</span>`;
}
const canEdit = () => App.meta && App.meta.me.role !== 'viewer';
const RISK = { critical: 'Krytyczne', high: 'Wysokie', medium: 'Średnie', low: 'Niskie' };
const RISK_OPTS = [['critical', 'Krytyczne'], ['high', 'Wysokie'], ['medium', 'Średnie'], ['low', 'Niskie']];
const riskBadge = (r) => (r ? `<span class="b risk-${esc(r)}">${esc(RISK[r] || r)}</span>` : '');
function deadlineBadge(d, overdue, src) {
  if (!d) return '';
  const days = Math.round((new Date(d) - new Date(App.meta.today)) / 86400000);
  const txt = overdue || days < 0 ? `po terminie ${-days} d` : days === 0 ? 'dziś' : `za ${days} d`;
  const cls = overdue || days < 0 ? 'red' : days <= 7 ? 'amber' : 'outline';
  return `<span class="b ${cls}" title="Termin${src ? ' (' + esc(src) + ')' : ''}">⏱ ${esc(d)} · ${txt}</span>`;
}
const teamName = (id) => {
  if (!id || id === '__none__') return 'Nieprzypisany';
  const t = (App.meta.teams || []).find((x) => x.id === id);
  return t ? t.name : id;
};
const teamOpts = (empty) => [...(empty !== undefined ? [['', empty]] : []), ...(App.meta.teams || []).map((t) => [t.id, t.name])];
function companyDatalist(id = 'complist') {
  return `<datalist id="${id}">${(App.meta.companies || []).map((c) => `<option value="${esc(c)}">`).join('')}</datalist>`;
}
const GROUP_OPTS = [['company', 'Spółka'], ['team', 'Zespół (realizator)'], ['type', 'Typ urządzenia'], ['os', 'System'],
  ['environment', 'Środowisko'], ['location', 'Lokalizacja'], ['owner', 'Właściciel'], ['exposure', 'Ekspozycja'], ['product', 'Aplikacja']];

/* pobranie pliku z odpowiedzi POST (Excel, .eml) */
async function downloadPost(path, body, fallbackName) {
  const r = await fetch(path, { method: 'POST', credentials: 'same-origin',
    headers: { 'X-Requested-With': 'vulnbuster', 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  if (!r.ok) {
    let msg = 'HTTP ' + r.status;
    try { msg = (await r.json()).error || msg; } catch (e) { /* brak treści */ }
    throw new Error(msg);
  }
  const cd = r.headers.get('Content-Disposition') || '';
  const m = cd.match(/filename="([^"]+)"/);
  const blob = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1] : (fallbackName || 'plik');
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch (e) {
    const t = document.createElement('textarea'); t.value = text; document.body.append(t); t.select();
    let ok = false; try { ok = document.execCommand('copy'); } catch (e2) { ok = false; }
    t.remove(); return ok;
  }
}
const byTxt = (u) => (u ? ` <span class="small faint">· ${esc(u)}</span>` : '');
const kevBadge = (k, ransom) => (k ? '<span class="b kev">KEV</span>' : '') + (ransom ? ' <span class="b ransom">ransomware</span>' : '');
const cveLink = (id) => `<a class="mono" href="#/cve/${enc(id)}">${esc(id)}</a>`;
const hostLink = (id, name) => `<a href="#/host/${enc(id)}">${esc(name)}</a>`;
const prodLink = (id, name) => `<a href="#/product/${enc(id)}">${esc(name)}</a>`;
function options(list, sel, withEmpty) {
  return (withEmpty ? `<option value="">${esc(withEmpty)}</option>` : '') +
    list.map(([v, l]) => `<option value="${esc(v)}"${v === sel ? ' selected' : ''}>${esc(l)}</option>`).join('');
}
const EXPOSURE_OPTS = [['', '— nie określono —'], ['internet', 'Internet (wystawiony na zewnątrz)'], ['dmz', 'DMZ'], ['internal', 'Sieć wewnętrzna'], ['unknown', 'Nieznana']];
const TRIAGE_OPTS = [['affected', 'Dotyczy nas'], ['used_safe', 'Używamy — niepodatne'], ['not_used', 'Nie używamy'], ['not_applicable', 'Nie dotyczy (inny powód)'], ['pending', 'W analizie']];
const PSTATUS_OPTS = [['used', 'Używamy'], ['not_used', 'Nie używamy'], ['unknown', 'Nie wiadomo']];

function applyWidths(root) { $$('[data-w]', root).forEach((e) => { e.style.width = Math.max(0, Math.min(100, +e.dataset.w)) + '%'; }); }
function progressBar(ok, total) {
  const pct = total ? Math.round((ok / total) * 100) : 100;
  return `<div class="row"><div class="bar"><i data-w="${pct}"></i></div><span class="small muted">${ok}/${total} (${pct}%)</span></div>`;
}

/* ---------- CSV (Excel PL: średnik + BOM) ---------- */
function downloadCSV(name, headers, rows) {
  const q = (v) => { const s = String(v ?? ''); return /[;"\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const text = '﻿' + [headers, ...rows].map((r) => r.map(q).join(';')).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

/* ---------- produkty (cache) ---------- */
async function loadProducts(force) {
  if (!App.products || force) App.products = (await GET('/api/products')).products;
  return App.products;
}
function productByName(name) {
  const n = String(name || '').trim().toLowerCase();
  if (!n) return null;
  return (App.products || []).find((p) => p.name.toLowerCase() === n || (p.aliases || []).some((a) => a.toLowerCase() === n)) || null;
}
function productDatalist(id = 'prodlist') {
  return `<datalist id="${id}">${(App.products || []).map((p) => `<option value="${esc(p.name)}">`).join('')}</datalist>`;
}

/* ---------- wersje (lustro logiki serwera, do szybkiego wpisywania) ---------- */
function deriveBranch(fixed) {
  const m = String(fixed || '').match(/^\s*v?(\d+(?:\.\d+)*)/);
  if (!m) return '*';
  const n = m[1].split('.');
  if (n.length >= 4) return n.slice(0, 3).join('.');
  if (n.length === 3) return n.slice(0, 2).join('.');
  if (n.length === 2) return n[0];
  return '*';
}
function parseQuickBranches(text) {
  const out = [];
  for (let part of String(text).split(/[\n,;]+/)) {
    part = part.trim();
    if (!part) continue;
    const m = part.match(/^([^:=>]+?)\s*(?::|=>|->|=|>)\s*(.+)$/);
    let branch, val;
    if (m) { branch = m[1].trim(); val = m[2].trim(); } else { val = part; branch = deriveBranch(part); }
    const low = val.toLowerCase();
    if (/^(brak|nofix|none|-|eol|brak poprawki)$/.test(low)) out.push({ branch, introduced: '', fixed: '', state: 'nofix', note: '' });
    else if (/^(niepodatne|niepodatna|safe|n\/a|nie dotyczy|ok)$/.test(low)) out.push({ branch, introduced: '', fixed: '', state: 'safe', note: '' });
    else out.push({ branch, introduced: '', fixed: val, state: 'fix', note: '' });
  }
  return out;
}

/* ---------- router ---------- */
function route(rx, fn, nav) { App.routes.push({ rx, fn, nav }); }
function parseHash() {
  const h = location.hash || '#/';
  const [path, qs] = h.slice(1).split('?');
  const query = Object.fromEntries(new URLSearchParams(qs || ''));
  return { path: path || '/', query };
}
async function render() {
  if (!App.meta) return;
  const { path, query } = parseHash();
  const content = $('#content');
  if (!content) return;
  for (const r of App.routes) {
    const m = path.match(r.rx);
    if (!m) continue;
    $$('.nav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === r.nav));
    const el = document.createElement('div');
    el.innerHTML = '<div class="spinner">Ładowanie…</div>';
    content.replaceChildren(el);
    window.scrollTo(0, 0);
    try {
      await r.fn(el, m.slice(1).map(decodeURIComponent), query);
      applyWidths(el);
    } catch (e) {
      el.innerHTML = `<div class="callout bad">${esc(e.message)}</div>`;
    }
    return;
  }
  content.innerHTML = '<div class="empty">Nie znaleziono strony</div>';
}

/* klik w wiersz tabeli z data-href */
document.addEventListener('click', (e) => {
  const tr = e.target.closest('[data-href]');
  if (!tr || e.target.closest('a, button, input, select, textarea, label')) return;
  location.hash = tr.dataset.href;
});

/* pomocnik: delegacja akcji w obrębie widoku */
function onAct(root, handlers) {
  root.addEventListener('click', (e) => {
    const t = e.target.closest('[data-act]');
    if (!t || !root.contains(t)) return;
    const fn = handlers[t.dataset.act];
    if (fn) { e.preventDefault(); fn(t, e); }
  });
}
function formData(form) {
  const o = {};
  $$('[name]', form).forEach((i) => {
    if (i.type === 'checkbox') o[i.name] = i.checked;
    else o[i.name] = i.value;
  });
  return o;
}
function fileToBase64(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(String(r.result).split(',')[1]);
    r.onerror = rej;
    r.readAsDataURL(file);
  });
}
function fileToText(file) {
  return new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsText(file); });
}
