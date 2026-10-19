/* SPDX-License-Identifier: MIT · Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com> */
/* Widoki: użytkownicy, moje konto, dziennik zmian, historia obiektu */
'use strict';

const ACTION_LABELS = {
  'vault.init': 'Utworzenie sejfu', 'vault.lock': 'Zablokowanie sejfu', 'auth.login': 'Logowanie',
  'auth.fail': 'Nieudane logowanie', 'auth.lockout': 'Blokada konta (błędne hasła)',
  'user.create': 'Nowe konto', 'user.update': 'Zmiana konta', 'user.reset': 'Reset hasła', 'user.delete': 'Usunięcie konta',
  'user.password': 'Zmiana własnego hasła',
  'product.create': 'Nowa aplikacja', 'product.update': 'Edycja aplikacji', 'product.delete': 'Usunięcie aplikacji',
  'product.merge': 'Scalenie aplikacji', 'host.create': 'Nowy host', 'host.update': 'Edycja hosta', 'host.delete': 'Usunięcie hosta',
  'host.mitigation.add': 'Dodanie mitygacji', 'host.mitigation.del': 'Usunięcie mitygacji',
  'inventory.set': 'Ręczna zmiana instalacji', 'inventory.remove': 'Odinstalowanie aplikacji',
  'cve.save': 'Zapis CVE / reguł', 'cve.delete': 'Usunięcie CVE', 'cve.triage': 'Decyzja dla CVE',
  'kev.fetch': 'Pobranie katalogu KEV', 'kev.upload': 'Wgranie katalogu KEV', 'kev.triage': 'Decyzja KEV',
  'exception.create': 'Nowy wyjątek', 'exception.update': 'Zmiana wyjątku', 'exception.delete': 'Usunięcie wyjątku',
  'import.commit': 'Import z Excela', 'import.rename': 'Zmiana nazwy importu', 'settings.update': 'Zmiana ustawień',
};
const TYPE_LABELS = {
  host: 'Host', product: 'Aplikacja', cve: 'CVE', exception: 'Wyjątek', installation: 'Instalacja', user: 'Użytkownik',
  kev_decision: 'Decyzja KEV (produkt)', settings: 'Ustawienia',
};
const FIELD_LABELS = {
  hostname: 'Nazwa', ip: 'IP', type: 'Typ', os: 'System', environment: 'Środowisko', owner: 'Właściciel', admin: 'Administrator',
  user: 'Użytkownik', location: 'Lokalizacja', criticality: 'Krytyczność', exposure: 'Ekspozycja', notes: 'Notatki',
  mitigations: 'Mitygacje', name: 'Nazwa', vendor: 'Producent', aliases: 'Aliasy', status: 'Status', category: 'Kategoria',
  verified_at: 'Zweryfikowano', verified_by: 'Zweryfikował', title: 'Tytuł', description: 'Opis', cvss: 'CVSS',
  severity: 'Ważność', groups: 'Grupy', rules: 'Reguły wersji', triage: 'Decyzja', version: 'Wersja', removed: 'Usunięta',
  reported_cves: 'CVE z importu', reason: 'Powód', review_at: 'Przegląd', active: 'Aktywne', role: 'Rola',
  display_name: 'Nazwa wyświetlana', must_change: 'Wymuszona zmiana hasła', decision: 'Decyzja', note: 'Notatka',
  product_ids: 'Aplikacje', contact: 'Od kogo', compensating: 'Kompensacja', no_auto_exposure: 'Bez auto-mitygacji',
};
const OP = { create: ['dodano', 'green'], update: ['zmieniono', 'blue'], delete: ['usunięto', 'red'] };

function fmtVal(v) {
  if (v === null || v === undefined || v === '') return '<span class="faint">—</span>';
  return `<span class="mono">${esc(typeof v === 'string' ? v : JSON.stringify(v))}</span>`;
}
function changeHtml(c) {
  const [opl, cls] = OP[c.op] || [c.op, 'gray'];
  const f = Object.entries(c.fields || {});
  const body = c.op === 'update'
    ? f.map(([k, [o, n]]) => `<div class="chg"><span class="muted">${esc(FIELD_LABELS[k] || k)}:</span> ${fmtVal(o)} <span class="arrow">→</span> ${fmtVal(n)}</div>`).join('')
    : f.slice(0, 8).map(([k, v]) => `<div class="chg"><span class="muted">${esc(FIELD_LABELS[k] || k)}:</span> ${fmtVal(v)}</div>`).join('');
  return `<div class="change"><span class="b ${cls}">${opl}</span> <span class="muted small">${esc(TYPE_LABELS[c.type] || c.type)}</span> <b>${esc(c.label)}</b>${body}</div>`;
}
function entryHtml(e, names, withChanges = true) {
  if (e.corrupt) return `<tr><td colspan="4"><span class="b red">Uszkodzony wpis (wiersz ${e.line})</span></td></tr>`;
  const who = names[e.user] ? `${esc(names[e.user])} <span class="faint">(${esc(e.user)})</span>` : esc(e.user);
  const ch = e.changes || [];
  const auth = /^(auth|vault)\./.test(e.action);
  return `<tr><td class="nowrap small">${esc(fmtDT(e.ts))}<div class="faint">#${e.seq}</div></td><td class="nowrap">${who}</td>
    <td><span class="b ${auth ? 'gray' : 'outline'}">${esc(ACTION_LABELS[e.action] || e.action)}</span><div class="small">${esc(e.summary || '')}</div></td>
    <td>${withChanges && ch.length ? (ch.length > 3 ? `<details><summary class="small">${ch.length} zmian${e.truncated ? ` (+${e.truncated} niezapisanych szczegółów)` : ''}</summary>${ch.map(changeHtml).join('')}</details>` : ch.map(changeHtml).join(''))
      : (Object.keys(e.stats || {}).length ? `<span class="small muted">${esc(Object.entries(e.stats).map(([t, s]) => `${TYPE_LABELS[t] || t}: +${s.create} ~${s.update} −${s.delete}`).join(', '))}</span>` : '')}</td></tr>`;
}

/* historia zmian obiektu — wstawiana na stronach CVE / hosta / aplikacji */
async function historyPanel(container, entityId) {
  try {
    const r = await GET(`/api/audit?entity=${enc(entityId)}&limit=40`);
    container.innerHTML = `<div class="panel tight"><div class="panel-head"><h2>Historia zmian</h2>
      <a class="small" href="#/audit?q=${enc(entityId)}">pełny dziennik →</a></div>
      ${r.entries.length ? `<div class="tbl-wrap"><table><tbody>${r.entries.map((e) => entryHtml(e, r.names)).join('')}</tbody></table></div>` : '<div class="empty">Brak zmian w dzienniku</div>'}</div>`;
  } catch (e) { container.innerHTML = ''; }
}

/* =================================================================== DZIENNIK */
async function viewAudit(el, _, q) {
  const params = new URLSearchParams({ limit: q.limit || 200 });
  ['user', 'type', 'q', 'from', 'to'].forEach((k) => { if (q[k]) params.set(k, q[k]); });
  const [r, chain] = await Promise.all([GET('/api/audit?' + params), GET('/api/audit/verify')]);
  el.innerHTML = `
  <div class="page-head"><div><h1>Dziennik zmian</h1><div class="muted">Kto, kiedy i co zmienił — wpisy zaszyfrowane, połączone łańcuchem SHA-256</div></div>
    <div class="actions">${chain.ok ? `<span class="b green" title="Ostatni skrót: ${esc(chain.last_hash)}">✔ łańcuch spójny · ${chain.count} wpisów</span>`
      : `<span class="b red">✖ ${esc(chain.reason)}</span>`}<button class="btn sm" data-act="csv">CSV</button></div></div>
  <div class="panel" id="af"><div class="row">
    <select name="user">${options([['', 'Wszyscy użytkownicy'], ...r.users.map((u) => [u, r.names[u] ? `${r.names[u]} (${u})` : u])], q.user || '')}</select>
    <select name="type">${options([['', 'Wszystkie obiekty'], ...Object.entries(TYPE_LABELS), ['auth', 'Logowania i sejf']], q.type || '')}</select>
    <input type="search" name="q" placeholder="Szukaj w treści (nazwa hosta, CVE…)" value="${esc(q.q || '')}">
    <label class="row small">od <input type="date" name="from" value="${esc(q.from || '')}"></label>
    <label class="row small">do <input type="date" name="to" value="${esc(q.to || '')}"></label>
    <button class="btn primary sm" data-act="filter">Filtruj</button><a class="btn sm ghost" href="#/audit">wyczyść</a></div></div>
  ${!chain.ok ? '<div class="callout bad">Wykryto naruszenie integralności dziennika. Porównaj z kopią zapasową z katalogu <code>backups/</code> i sprawdź, kto ma dostęp do plików danych na serwerze.</div>' : ''}
  <div class="panel tight"><div class="panel-head"><h2>${r.total} wpisów</h2>${r.total > r.entries.length ? `<span class="small muted">pokazano ${r.entries.length}</span>` : ''}</div>
    <div class="tbl-wrap"><table><thead><tr><th>Kiedy (UTC)</th><th>Kto</th><th>Co</th><th>Szczegóły</th></tr></thead>
    <tbody>${r.entries.map((e) => entryHtml(e, r.names)).join('') || '<tr><td colspan="4" class="empty">Brak wpisów</td></tr>'}</tbody></table></div>
    ${r.total > r.entries.length ? '<div class="row addrow"><button class="btn sm" data-act="more">Pokaż więcej</button></div>' : ''}</div>`;
  const go = (extra = {}) => {
    const f = formData($('#af', el));
    const nq = Object.fromEntries(Object.entries({ ...f, ...extra }).filter(([, v]) => v));
    location.hash = '#/audit?' + new URLSearchParams(nq);
  };
  $('#af input[name=q]', el).addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  onAct(el, {
    filter: () => go(),
    more: () => go({ limit: (+(q.limit || 200)) + 500 }),
    csv: () => {
      const rows = [];
      r.entries.forEach((e) => {
        const base = [e.ts, e.user, r.names[e.user] || '', ACTION_LABELS[e.action] || e.action, e.summary || ''];
        if (!(e.changes || []).length) rows.push([...base, '', '', '', '', '', '']);
        (e.changes || []).forEach((c) => {
          const fs = Object.entries(c.fields || {});
          if (!fs.length) rows.push([...base, c.op, TYPE_LABELS[c.type] || c.type, c.label, '', '', '']);
          fs.forEach(([k, v]) => rows.push([...base, c.op, TYPE_LABELS[c.type] || c.type, c.label, FIELD_LABELS[k] || k,
            Array.isArray(v) && c.op === 'update' ? v[0] ?? '' : '', Array.isArray(v) && c.op === 'update' ? v[1] ?? '' : (typeof v === 'string' ? v : JSON.stringify(v))]));
        });
      });
      downloadCSV(`dziennik-zmian-${App.meta.today}.csv`, ['Czas (UTC)', 'Login', 'Użytkownik', 'Akcja', 'Opis', 'Operacja', 'Typ', 'Obiekt', 'Pole', 'Było', 'Jest'], rows);
    },
  });
}

/* =================================================================== MOJE KONTO */
async function viewAccount(el) {
  const me = App.meta.me;
  el.innerHTML = `
  <div class="page-head"><div><h1>Moje konto</h1><div class="muted">${esc(me.display_name)} · ${esc(me.username)} · ${esc(me.role_label)}</div></div></div>
  <div class="grid g2">
    <div class="panel" id="pwform"><h2>Zmiana hasła</h2><div class="form">
      <label class="wide">Obecne hasło<input type="password" name="old" autocomplete="current-password"></label>
      <label>Nowe hasło (min. 12 znaków)<input type="password" name="new" autocomplete="new-password"></label>
      <label>Powtórz nowe<input type="password" name="new2" autocomplete="new-password"></label>
    </div><div class="row end mt8"><button class="btn primary" data-act="pw">Zmień hasło</button></div>
      <p class="small muted mt8">Twoje hasło odblokowuje Twój klucz do zaszyfrowanych danych. Zmiana nie wpływa na innych użytkowników.</p></div>
    <div id="myhist"></div>
  </div>`;
  onAct(el, {
    pw: async () => {
      const f = formData($('#pwform', el));
      if (f.new !== f.new2) { toast('Nowe hasła się różnią', true); return; }
      if (await guard(() => POST('/api/me/password', { old: f.old, new: f.new }), 'Hasło zmienione')) $$('#pwform input', el).forEach((i) => { i.value = ''; });
    },
  });
  const r = await GET(`/api/audit?user=${enc(me.username)}&limit=15`);
  $('#myhist', el).innerHTML = `<div class="panel tight"><div class="panel-head"><h2>Moja ostatnia aktywność</h2><a class="small" href="#/audit?user=${enc(me.username)}">wszystko →</a></div>
    <div class="tbl-wrap"><table><tbody>${r.entries.map((e) => entryHtml(e, r.names, false)).join('')}</tbody></table></div></div>`;
}

/* =================================================================== UŻYTKOWNICY */
function randomPassword() {
  const abc = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const a = new Uint32Array(16); crypto.getRandomValues(a);
  return [...a].map((x) => abc[x % abc.length]).join('').replace(/(.{4})(?!$)/g, '$1-');
}

async function viewUsers(el) {
  const r = await GET('/api/users');
  const flash = App.flash; App.flash = null;
  const roleOpts = Object.entries(r.roles);
  const me = App.meta.me.username;
  el.innerHTML = `
  <div class="page-head"><div><h1>Użytkownicy</h1><div class="muted">Każde konto ma własny klucz do sejfu — blokada lub usunięcie konta odbiera dostęp do danych</div></div></div>
  <div class="panel" id="newu"><h2>Nowe konto</h2><div class="form">
    <label>Login<input type="text" name="username" placeholder="np. jkowalski" autocomplete="off"></label>
    <label>Imię i nazwisko<input type="text" name="display_name"></label>
    <label>Rola<select name="role">${options(roleOpts, 'viewer')}</select></label>
    <label>Hasło tymczasowe<span class="row"><input type="text" name="password" class="mono grow" autocomplete="off"><button class="btn sm" data-act="gen">losuj</button></span></label>
    <label class="wide checks"><span><input type="checkbox" name="must_change" checked> wymuś zmianę hasła przy pierwszym logowaniu</span></label>
  </div><div class="row end mt8"><button class="btn primary" data-act="create">Utwórz konto</button></div>
    <p class="small muted">Role: <b>Podgląd</b> — odczyt, raporty, CSV · <b>Analityk</b> — edycja danych, importy, decyzje KEV · <b>Administrator</b> — wszystko + konta, ustawienia, blokada sejfu.</p></div>
  <div id="pwbox"></div>
  <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th>Login</th><th>Nazwa</th><th>Rola</th><th>Stan</th><th>Ostatnie logowanie</th><th>Utworzył</th><th></th></tr></thead><tbody>
  ${r.users.map((u) => `<tr data-u="${esc(u.username)}">
    <td class="mono">${esc(u.username)}${u.username === me ? ' <span class="b outline">Ty</span>' : ''}</td>
    <td><input type="text" data-f="display_name" value="${esc(u.display_name || '')}"></td>
    <td><select data-f="role">${options(roleOpts, u.role)}</select></td>
    <td>${u.active ? '<span class="b green">aktywne</span>' : '<span class="b gray">zablokowane</span>'}
      ${u.must_change ? ' <span class="b amber">hasło tymczasowe</span>' : ''}${u.locked ? ' <span class="b red">blokada po błędach</span>' : ''}
      ${u.sessions ? ` <span class="b blue">${u.sessions} sesja</span>` : ''}</td>
    <td class="small">${esc(fmtDT(u.last_login))}</td><td class="small muted">${esc(u.created_by || '')}<div>${esc(fmtDate(u.created_at))}</div></td>
    <td class="nowrap"><button class="btn sm" data-act="save">Zapisz</button>
      <button class="btn sm" data-act="reset">${u.active ? 'Reset hasła' : 'Odblokuj'}</button>
      ${u.username !== me ? `${u.active ? '<button class="btn sm" data-act="disable">Zablokuj</button>' : ''} <button class="btn sm ghost danger" data-act="del">✕</button>` : ''}</td></tr>`).join('')}
  </tbody></table></div></div>`;
  const row = (b) => b.closest('tr');
  if (flash) {
    $('#pwbox', el).innerHTML = `<div class="callout ok">Hasło tymczasowe dla <b>${esc(flash.user)}</b>: <code class="pw">${esc(flash.pw)}</code>
      — przekaż je bezpiecznym kanałem. Użytkownik ustawi własne przy pierwszym logowaniu.</div>`;
  }
  const showPw = (user, pw) => { App.flash = { user, pw }; render(); };
  onAct(el, {
    gen: () => { $('#newu [name=password]', el).value = randomPassword(); },
    create: async () => {
      const f = formData($('#newu', el));
      if (!f.password) f.password = randomPassword();
      if (await guard(() => POST('/api/users', f), 'Konto utworzone')) showPw(f.username.toLowerCase(), f.password);
    },
    save: async (b) => {
      const tr = row(b), u = tr.dataset.u;
      const body = { display_name: $('[data-f=display_name]', tr).value, role: $('[data-f=role]', tr).value };
      if (await guard(() => PUT('/api/users/' + enc(u), body), 'Zapisano')) render();
    },
    reset: async (b) => {
      const u = row(b).dataset.u;
      if (!confirm(`Ustawić nowe hasło tymczasowe dla ${u}? Jego bieżące sesje zostaną zakończone.`)) return;
      const pw = randomPassword();
      if (await guard(() => POST(`/api/users/${enc(u)}/password`, { password: pw }), 'Ustawiono hasło tymczasowe')) showPw(u, pw);
    },
    disable: async (b) => {
      const u = row(b).dataset.u;
      if (!confirm(`Zablokować konto ${u}? Klucz użytkownika zostanie usunięty, sesje zakończone. Odblokowanie wymaga nowego hasła.`)) return;
      if (await guard(() => PUT('/api/users/' + enc(u), { active: false }), 'Konto zablokowane')) render();
    },
    del: async (b) => {
      const u = row(b).dataset.u;
      if (!confirm(`Usunąć konto ${u}? Wpisy w dzienniku zmian pozostaną.`)) return;
      if (await guard(() => DEL('/api/users/' + enc(u)), 'Usunięto')) render();
    },
  });
}
