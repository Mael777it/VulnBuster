/* SPDX-License-Identifier: MIT · Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com> */
/* Logowanie, układ, trasy */
'use strict';

route(/^\/$/, viewDashboard, 'dash');
route(/^\/search$/, viewSearch, '');
route(/^\/kev$/, viewKev, 'kev');
route(/^\/cves$/, viewCves, 'cves');
route(/^\/cve\/(.+)$/, viewCve, 'cves');
route(/^\/products$/, viewProducts, 'products');
route(/^\/product\/(.+)$/, viewProduct, 'products');
route(/^\/hosts$/, viewHosts, 'hosts');
route(/^\/host\/(.+)$/, viewHost, 'hosts');
route(/^\/import$/, viewImport, 'import');
route(/^\/imports$/, viewImports, 'import');
route(/^\/compare$/, viewCompare, 'compare');
route(/^\/exceptions$/, viewExceptions, 'exceptions');
route(/^\/audit$/, viewAudit, 'audit');
route(/^\/reports$/, viewReports, 'reports');
route(/^\/tickets$/, viewTickets, 'tickets');
route(/^\/users$/, viewUsers, 'users');
route(/^\/account$/, viewAccount, '');
route(/^\/settings$/, viewSettings, 'settings');
route(/^\/report\/host\/(.+)$/, viewHostReport, 'hosts');
route(/^\/report\/product\/(.+)$/, viewProductReport, 'products');

const LOGO = '<img class="logo" src="/static/logo.svg" alt="">';
function aboutLine(a) {
  if (!a) return '';
  return `<div class="about">VulnBuster v${esc(a.version)} · <a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">licencja ${esc(a.license)}</a><br>© 2026 ${esc(a.author)}</div>`;
}

function showShell() {
  const me = App.meta.me;
  document.body.classList.toggle('ro', me.role === 'viewer');
  document.body.classList.toggle('is-admin', me.role === 'admin');
  $('#app').innerHTML = `
  <div class="shell">
    <aside class="side">
      <div class="brand">${LOGO}<div>VulnBuster<small>who you gonna patch?</small></div></div>
      <nav class="nav">
        <a href="#/" data-nav="dash">Pulpit</a>
        <a href="#/kev" data-nav="kev">Przegląd KEV <span class="count hidden" id="kevcount"></span></a>
        <a href="#/cves" data-nav="cves">CVE i reguły wersji</a>
        <div class="sep"></div>
        <a href="#/products" data-nav="products">Aplikacje</a>
        <a href="#/hosts" data-nav="hosts">Hosty i urządzenia</a>
        <a href="#/exceptions" data-nav="exceptions">Wyjątki <span class="count hidden" id="exccount"></span></a>
        <div class="sep"></div>
        <a href="#/reports" data-nav="reports">Raporty (spółki, zespoły)</a>
        <a href="#/tickets" data-nav="tickets">Zgłoszenia do realizatorów</a>
        <div class="sep"></div>
        <a href="#/import" data-nav="import" class="w">Import z Excela</a>
        <a href="#/compare" data-nav="compare">Porównanie importów</a>
        <a href="#/audit" data-nav="audit">Dziennik zmian</a>
        <div class="sep admin-only"></div>
        <a href="#/users" data-nav="users" class="admin-only">Użytkownicy</a>
        <a href="#/settings" data-nav="settings" class="admin-only">Ustawienia</a>
      </nav>
      <div class="side-foot"><button class="btn sm admin-only" id="lockbtn" title="Usuwa klucz z pamięci serwera i wylogowuje wszystkich">🔒 Zablokuj sejf</button>
        ${aboutLine(App.meta.about)}</div>
    </aside>
    <div class="main">
      <div class="topbar"><input type="search" id="gsearch" placeholder="Szukaj: aplikacja, CVE, host, notatka…  ( / )" autocomplete="off">
        <span class="grow"></span>
        <a class="userchip" href="#/account" title="Moje konto"><b>${esc(me.display_name)}</b> <span class="b outline">${esc(me.role_label)}</span></a>
        <button class="btn sm ghost" id="logout">Wyloguj</button></div>
      <div class="content" id="content"></div>
    </div>
  </div>`;
  $('#gsearch').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.value.trim().length >= 2) location.hash = '#/search?q=' + enc(e.target.value.trim());
  });
  $('#lockbtn').addEventListener('click', async () => {
    if (!confirm('Zablokować sejf? Wszyscy użytkownicy zostaną wylogowani, a dane pozostaną zaszyfrowane do następnego logowania.')) return;
    await guard(() => POST('/api/lock'));
    App.meta = null; showLogin();
  });
  $('#logout').addEventListener('click', async () => { await guard(() => POST('/api/logout')); App.meta = null; showLogin(); });
}
document.addEventListener('keydown', (e) => {
  const s = $('#gsearch');
  if (s && e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) { e.preventDefault(); s.focus(); }
});

async function refreshCounts() {
  try {
    const d = await GET('/api/counts');
    const k = $('#kevcount'), x = $('#exccount');
    if (k) { k.textContent = d.kev_pending; k.classList.toggle('hidden', !d.kev_pending); }
    if (x) { x.textContent = d.exceptions_overdue; x.classList.toggle('hidden', !d.exceptions_overdue); }
  } catch (e) { /* ignoruj */ }
}

function loginFrame(inner) {
  $('#app').innerHTML = `<div class="login"><div class="panel">
    <div class="brand login-brand">${LOGO}<div><b>VulnBuster</b><small class="muted">zarządzanie podatnościami</small></div></div>
    ${inner}<div id="err" class="callout bad hidden"></div></div>${aboutLine(App.status)}</div>`;
}
function bindLogin(submit) {
  const go = async () => {
    const err = $('#err'); err.classList.add('hidden');
    const b = $('#go'); const label = b.textContent; b.disabled = true; b.textContent = 'Sprawdzanie…';
    try { await submit(); } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); b.disabled = false; b.textContent = label; }
  };
  $('#go').addEventListener('click', go);
  $$('#app input').forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); }));
  const f = $('#app input'); if (f) f.focus();
}

async function showLogin() {
  let st = { initialized: true };
  try { st = await GET('/api/status'); App.status = st; } catch (e) { /* ignoruj */ }
  if (!st.initialized) {
    loginFrame(`<h2>Pierwsze uruchomienie</h2>
      <p class="small muted">Utwórz konto administratora. Jego hasło (i każdego kolejnego użytkownika) chroni klucz do zaszyfrowanych danych —
      <b>nie da się go odzyskać</b>, ale inny administrator może ustawić nowe.</p>
      <label class="small muted">Login<input type="text" id="u" autocomplete="username" placeholder="np. mlewandowski"></label>
      <label class="small muted">Imię i nazwisko<input type="text" id="dn"></label>
      <label class="small muted">Hasło (min. 12 znaków)<input type="password" id="pw" autocomplete="new-password"></label>
      <label class="small muted">Powtórz hasło<input type="password" id="pw2" autocomplete="new-password"></label>
      <button class="btn primary" id="go">Utwórz sejf i konto</button>`);
    bindLogin(async () => {
      if ($('#pw').value !== $('#pw2').value) throw new Error('Hasła się różnią');
      await POST('/api/init', { username: $('#u').value, display_name: $('#dn').value, password: $('#pw').value });
      await start();
    });
    return;
  }
  loginFrame(`<h2>Logowanie</h2>
    <p class="small muted">${st.unlocked ? 'Zaloguj się swoim kontem.' : 'Sejf jest zablokowany (np. po restarcie serwera) — pierwsze poprawne logowanie go odblokuje.'}</p>
    <label class="small muted">Login<input type="text" id="u" autocomplete="username"></label>
    <label class="small muted">Hasło<input type="password" id="pw" autocomplete="current-password"></label>
    <button class="btn primary" id="go">Zaloguj</button>`);
  bindLogin(async () => {
    const r = await POST('/api/login', { username: $('#u').value, password: $('#pw').value });
    if (r.me && r.me.must_change) showChangePassword(r.me);
    else await start();
  });
}

function showChangePassword(me) {
  loginFrame(`<h2>Ustaw własne hasło</h2>
    <p class="small muted">Cześć ${esc(me.display_name)} — administrator nadał Ci hasło tymczasowe. Ustaw własne (min. 12 znaków), aby kontynuować.</p>
    <label class="small muted">Hasło tymczasowe<input type="password" id="old" autocomplete="current-password"></label>
    <label class="small muted">Nowe hasło<input type="password" id="pw" autocomplete="new-password"></label>
    <label class="small muted">Powtórz nowe hasło<input type="password" id="pw2" autocomplete="new-password"></label>
    <button class="btn primary" id="go">Zapisz i przejdź dalej</button>`);
  bindLogin(async () => {
    if ($('#pw').value !== $('#pw2').value) throw new Error('Hasła się różnią');
    await POST('/api/me/password', { old: $('#old').value, new: $('#pw').value });
    await start();
  });
}

async function start() {
  try {
    App.meta = await GET('/api/meta');
  } catch (e) {
    if (/zmień hasło/i.test(e.message)) {
      try { showChangePassword(await GET('/api/me')); } catch (e2) { showLogin(); }
    }
    return;
  }
  App.products = null;
  showShell();
  refreshCounts();
  render();
}

window.addEventListener('hashchange', render);
start();
