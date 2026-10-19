/* SPDX-License-Identifier: MIT · Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com> */
/* Widoki: aplikacje, hosty, wyjątki, ustawienia */
'use strict';

/* =================================================================== APLIKACJE */
async function viewProducts(el, _, q) {
  const prods = await loadProducts(true);
  const tab = q.tab || 'all';
  const counts = { all: prods.length, used: 0, not_used: 0, unknown: 0 };
  prods.forEach((p) => { counts[p.status || 'unknown'] = (counts[p.status || 'unknown'] || 0) + 1; });
  const tabs = [['all', 'Wszystkie'], ['used', 'Używamy'], ['not_used', 'Nie używamy'], ['unknown', 'Nie wiadomo']];
  el.innerHTML = `
  <div class="page-head"><div><h1>Aplikacje i produkty</h1><div class="muted">Rejestr: co używamy, czego nie — z datą ostatniej weryfikacji</div></div></div>
  <div class="panel w" id="newp"><h2>Dodaj aplikację</h2>
    <div class="form">
      <label>Nazwa<input type="text" name="name" value="${esc(q.new || '')}" placeholder="np. Ivanti Connect Secure"></label>
      <label>Producent<input type="text" name="vendor"></label>
      <label>Status<select name="status">${options(PSTATUS_OPTS, q.new ? 'not_used' : 'used')}</select></label>
      <label>Aliasy (po przecinku)<input type="text" name="aliases" placeholder="Pulse Secure, ICS"></label>
      <label class="wide">Notatka (na jakiej podstawie)<input type="text" name="notes" placeholder="np. sprawdzone w CMDB i u zespołu sieci — brak"></label>
    </div><div class="row end mt8"><button class="btn primary w" data-act="create">Dodaj</button></div></div>
  <div class="row mb12">
    <div class="seg">${tabs.map(([k, l]) => `<button data-act="tab" data-v="${k}" class="${k === tab ? 'on' : ''}">${l} (${counts[k] || 0})</button>`).join('')}</div>
    <input type="search" id="pq" placeholder="Filtruj…">
    <label class="row small"><input type="checkbox" id="pstale"> tylko nieaktualne weryfikacje</label>
  </div>
  <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th>Aplikacja</th><th>Status</th><th>Weryfikacja</th><th class="num">Hosty</th><th class="num">CVE</th><th>Notatka</th><th></th></tr></thead>
    <tbody id="pbody"></tbody></table></div></div>`;
  const draw = () => {
    const f = $('#pq', el).value.toLowerCase(), onlyStale = $('#pstale', el).checked;
    const rows = prods.filter((p) => (tab === 'all' || (p.status || 'unknown') === tab)
      && (!f || (p.name + ' ' + p.vendor + ' ' + (p.aliases || []).join(' ') + ' ' + p.notes).toLowerCase().includes(f))
      && (!onlyStale || ['warn', 'crit', 'never'].includes(p.stale.level)));
    $('#pbody', el).innerHTML = rows.length ? rows.map((p) => `<tr class="clickable" data-href="#/product/${enc(p.id)}">
      <td>${prodLink(p.id, p.name)}<div class="small faint">${esc(p.vendor || '')}${(p.aliases || []).length ? ' · ' + esc(p.aliases.join(', ')) : ''}</div></td>
      <td><select class="pstatus" data-id="${esc(p.id)}"${canEdit() ? '' : ' disabled'}>${options(PSTATUS_OPTS, p.status || 'unknown')}</select></td>
      <td>${staleBadge(p.stale)}<div class="small faint">${esc(p.verified_at || '')}</div></td>
      <td class="num">${p.hosts}</td><td class="num">${p.cves}</td><td class="small">${esc((p.notes || '').slice(0, 140))}</td>
      <td><button class="btn sm w" data-act="verify" data-id="${esc(p.id)}" title="Potwierdź, że status jest aktualny">✓ aktualne</button></td></tr>`).join('')
      : '<tr><td colspan="7" class="empty">Brak aplikacji</td></tr>';
  };
  draw();
  $('#pq', el).addEventListener('input', draw);
  $('#pstale', el).addEventListener('input', draw);
  el.addEventListener('change', async (e) => {
    if (!e.target.classList.contains('pstatus')) return;
    const p = prods.find((x) => x.id === e.target.dataset.id);
    if (e.target.value === 'not_used' && p.hosts) {
      if (!confirm(`„${p.name}” występuje na ${p.hosts} hostach w inwentarzu. Na pewno oznaczyć jako nieużywane?`)) { e.target.value = p.status; return; }
    }
    if (await guard(() => PUT('/api/products/' + enc(p.id), { status: e.target.value }), 'Status zapisany z dzisiejszą datą')) {
      p.status = e.target.value; p.stale = { level: 'fresh', days: 0 }; p.verified_at = App.meta.today; draw();
    }
  });
  onAct(el, {
    tab: (b) => { location.hash = '#/products?tab=' + b.dataset.v; },
    create: async () => {
      const f = formData($('#newp', el));
      const r = await guard(() => POST('/api/products', f), 'Dodano aplikację');
      if (r) { App.products = null; location.hash = '#/product/' + r.id; }
    },
    verify: async (b) => {
      const p = prods.find((x) => x.id === b.dataset.id);
      if (await guard(() => PUT('/api/products/' + enc(p.id), { verify: true }), `Potwierdzono status „${p.name}”`)) {
        p.stale = { level: 'fresh', days: 0 }; p.verified_at = App.meta.today; draw();
      }
    },
  });
}

async function viewProduct(el, [pid]) {
  const r = await GET(`/api/products/${enc(pid)}/report`);
  await loadProducts(true);
  const p = r.product;
  const st = App.products.find((x) => x.id === pid);
  el.innerHTML = `
  <div class="page-head"><div><h1>${esc(p.name)} ${prodBadge(p.status)}</h1><div class="muted">${p.vendor ? esc(p.vendor) + ' · ' : ''}weryfikacja ${staleBadge(st && st.stale)} ${esc(p.verified_at || '')}${byTxt(p.verified_by)}</div></div>
    <div class="actions"><a class="btn primary" href="#/tickets?product=${enc(pid)}">Zgłoszenia do realizatorów</a>
      <a class="btn" href="#/reports?product=${enc(pid)}&group=company">Raport per spółka</a>
      <a class="btn" href="#/reports?product=${enc(pid)}&group=team">Raport per zespół</a>
      <a class="btn" href="#/report/product/${enc(pid)}">Do druku</a><button class="btn" data-act="csv">CSV</button></div></div>
  <div class="grid g2">
    <div class="panel" id="pform"><h2>Dane i status</h2><div class="form">
      <label>Nazwa<input type="text" name="name" value="${esc(p.name)}"></label>
      <label>Producent<input type="text" name="vendor" value="${esc(p.vendor || '')}"></label>
      <label>Status<select name="status">${options(PSTATUS_OPTS, p.status || 'unknown')}</select></label>
      <label>Kategoria<input type="text" name="category" value="${esc(p.category || '')}" placeholder="baza danych, VPN, system…"></label>
      <label class="wide">Kto łata tę aplikację<select name="team">${options(teamOpts('— zespół hosta (wg reguł / ustawień hosta) —'), p.team || '')}</select>
        <span class="small faint">Ustaw np. „DBA” dla PostgreSQL, jeśli aplikację aktualizuje inny zespół niż ten, który utrzymuje serwer.</span></label>
      <label class="wide">Aliasy (po przecinku — nazwy z Excela/KEV)<input type="text" name="aliases" value="${esc((p.aliases || []).join(', '))}"></label>
      <label class="wide">Notatki<textarea name="notes" rows="4">${esc(p.notes || '')}</textarea></label>
      <label class="wide checks"><span><input type="checkbox" name="verify"> potwierdzam, że status jest aktualny na dziś</span></label>
    </div><div class="row end mt8"><button class="btn danger w" data-act="del">Usuń</button><button class="btn primary w" data-act="save">Zapisz</button></div>
      <div class="w"><h3>Scal z inną aplikacją (duplikat nazwy)</h3>
      <div class="row"><select id="mergeinto">${options(App.products.filter((x) => x.id !== pid).map((x) => [x.id, x.name]), '', '— wybierz docelową —')}</select>
        <button class="btn sm w" data-act="merge">Scal</button></div>
      <p class="small muted">Instalacje, reguły CVE i wyjątki zostaną przeniesione, a „${esc(p.name)}” stanie się aliasem.</p></div>
    </div>
    <div class="panel"><h2>Postęp patchowania</h2>
      ${progressBar(r.progress.ok, r.progress.total)}
      <h3>Gałęzie wersji</h3>
      ${r.branches.length ? `<table><thead><tr><th>Gałąź</th><th class="num">Hosty</th><th class="num">Do akcji</th><th>Wersje</th><th>Docelowa</th></tr></thead><tbody>
        ${r.branches.map((b) => `<tr><td class="mono">${esc(b.branch)}</td><td class="num">${b.hosts}</td><td class="num">${b.open ? `<span class="b vulnerable">${b.open}</span>` : '0'}</td>
          <td class="mono small">${esc(b.versions.join(', '))}</td><td class="mono">${esc(b.target || '')}</td></tr>`).join('')}</tbody></table>` : '<div class="muted">Brak instalacji w inwentarzu</div>'}
      <h3>Historia (wg importów)</h3>
      ${r.trend.length ? `<table><tbody>${r.trend.map((t) => `<tr><td>${esc(t.name)}</td><td class="small muted">${esc(fmtDate(t.date))}</td><td class="num">${t.hosts} hostów</td>
        <td class="num">${t.open ? `<span class="b vulnerable">${t.open} do akcji</span>` : '<span class="b fixed">0 do akcji</span>'}</td></tr>`).join('')}</tbody></table>` : '<div class="muted">—</div>'}
      <h3>CVE z regułami (${r.cves.length})</h3><div class="chips">${r.cves.map((c) => `<a class="chip mono" href="#/cve/${enc(c)}">${esc(c)}</a>`).join('') || '<span class="muted">brak</span>'}</div>
    </div>
  </div>
  <div class="panel tight"><div class="panel-head"><h2>Instalacje (${r.installations.length})</h2></div>${installTable(r.installations, true)}</div>
  <div id="hist"></div>`;
  historyPanel($('#hist', el), pid);
  onAct(el, {
    save: async () => {
      const f = { ...formData($('#pform', el)), _version: p.updated_at };
      if (await guard(() => PUT('/api/products/' + enc(pid), f), 'Zapisano')) render();
    },
    del: async () => {
      if (!confirm(`Usunąć „${p.name}”? Usunięte zostaną też instalacje w inwentarzu i reguły CVE dla tej aplikacji.`)) return;
      if (await guard(() => DEL('/api/products/' + enc(pid)), 'Usunięto')) location.hash = '#/products';
    },
    merge: async () => {
      const into = $('#mergeinto', el).value; if (!into) return;
      if (!confirm('Scalić? Tej operacji nie da się cofnąć (poza kopią zapasową).')) return;
      if (await guard(() => POST(`/api/products/${enc(pid)}/merge`, { into }), 'Scalono')) location.hash = '#/product/' + into;
    },
    csv: () => downloadCSV(`${p.name}-instalacje.csv`, ['Host', 'IP', 'Spółka', 'Zespół', 'Typ', 'Ekspozycja', 'Właściciel', 'Wersja', 'Status', 'Wersja docelowa', 'Otwarte CVE'],
      r.installations.map((i) => [i.hostname, i.ip, i.company, i.team_label, i.type, i.exposure, i.owner, i.version, STATUS[i.summary.status], i.summary.target || '',
        i.findings.filter((f) => ['vulnerable', 'review'].includes(f.status)).map((f) => f.cve).join(' ')])),
  });
}

function findingsList(fs) {
  if (!fs.length) return '<span class="faint small">brak CVE z regułami</span>';
  return `<ul class="findings">${fs.map((f) => `<li>${badge(f.status)} ${cveLink(f.cve)} ${kevBadge(f.kev, f.kev_ransomware)}
    ${['vulnerable', 'review'].includes(f.status) ? riskBadge(f.risk) + ' ' + deadlineBadge(f.deadline, f.overdue, f.deadline_source) : ''}
    <span class="muted">${esc(f.reason)}</span>${f.overlay ? `<span class="faint">— ${f.overlay.type === 'exception' ? 'wyjątek' : 'mitygacja'}: ${esc(f.overlay.text)}${f.overlay.overdue ? ' <span class="b violet">przegląd po terminie</span>' : ''}</span>` : ''}</li>`).join('')}</ul>`;
}

function installTable(insts, byHost) {
  if (!insts.length) return '<div class="empty">Brak instalacji</div>';
  return `<div class="tbl-wrap"><table><thead><tr><th>${byHost ? 'Host' : 'Aplikacja'}</th><th>Wersja</th><th>Status</th><th>Docelowa</th><th>Podatności</th>${byHost ? '<th>Właściciel</th>' : '<th></th>'}</tr></thead><tbody>
  ${insts.map((i) => `<tr><td>${byHost ? hostLink(i.host_id, i.hostname) + `<div>${expBadge(i.exposure)} <span class="small faint">${esc(i.type || '')}${i.company ? ' · ' + esc(i.company) : ''}${i.team_label ? ' · ' + esc(i.team_label) : ''}</span></div>`
    : prodLink(i.product_id, i.product) + (i.team_label ? `<div class="small faint" title="${esc(i.team_source || '')}">łata: ${esc(i.team_label)}</div>` : '')}</td>
    <td class="mono nowrap">${esc(i.version || '—')}${i.history && i.history.length > 1 ? `<div class="small faint">poprz. ${esc(i.history[i.history.length - 2].version)}</div>` : ''}</td>
    <td>${badge(i.summary.status)}</td><td class="mono">${esc(i.summary.target || (i.summary.nofix ? 'brak poprawki' : ''))}</td>
    <td>${findingsList(i.findings)}</td>${byHost ? `<td>${esc(i.owner)}</td>` : `<td><button class="btn sm ghost w" data-act="rminst" data-p="${esc(i.product_id)}" data-key="${esc(i.key || '')}" title="Oznacz jako odinstalowane">usuń</button></td>`}</tr>`).join('')}
  </tbody></table></div>`;
}

/* =================================================================== HOSTY */
async function viewHosts(el, _, q) {
  const r = await GET('/api/hosts');
  const uniq = (k) => [...new Set(r.hosts.map((h) => h[k]).filter(Boolean))].sort((x, y) => x.localeCompare(y, 'pl'));
  const types = uniq('type'), comps = uniq('company');
  const teamsUsed = [...new Set(r.hosts.map((h) => h.team))];
  const LIMIT = 800;
  let showAll = false;
  const sel = new Set();
  el.innerHTML = `
  <div class="page-head"><div><h1>Hosty i urządzenia</h1><div class="muted">${r.hosts.length} pozycji · zespół wyliczany z reguł w Ustawieniach, chyba że ustawisz go ręcznie</div></div>
    <div class="actions"><button class="btn w" data-act="new">Dodaj ręcznie</button><button class="btn" data-act="csv">CSV</button></div></div>
  <div class="panel hidden" id="newh"><h2>Nowy host / urządzenie</h2>${hostForm({})}
    <div class="row end mt8"><button class="btn primary w" data-act="create">Dodaj</button></div></div>
  <div class="row mb12">
    <input type="search" id="hq" placeholder="Filtruj: nazwa, IP, właściciel, spółka…" value="${esc(q.q || '')}">
    <select id="hc">${options([['', 'Wszystkie spółki'], ['__none__', '(bez spółki)'], ...comps.map((c) => [c, c])], q.company || '')}</select>
    <select id="hm">${options([['', 'Wszystkie zespoły'], ...teamsUsed.map((t) => [t, teamName(t)])], q.team || '')}</select>
    <select id="ht">${options([['', 'Wszystkie typy'], ...types.map((t) => [t, t])], '')}</select>
    <select id="he">${options([['', 'Każda ekspozycja'], ...EXPOSURE_OPTS.slice(1)], '')}</select>
    <select id="hs">${options([['', 'Każdy status'], ['open', 'Wymaga działań'], ['kev', 'Z otwartym KEV'], ['ok', 'Bez działań']], q.f || '')}</select>
  </div>
  <div class="panel bulkbar hidden w" id="bulk"><div class="row">
    <b id="bulkn"></b>
    <select id="bf">${options([['company', 'Spółka'], ['team', 'Zespół (realizator)'], ['exposure', 'Ekspozycja'], ['environment', 'Środowisko'],
      ['owner', 'Właściciel'], ['admin', 'Administrator'], ['location', 'Lokalizacja'], ['criticality', 'Krytyczność'], ['type', 'Typ']], 'company')}</select>
    <span id="bvwrap"></span>
    <button class="btn primary sm" data-act="bulk">Ustaw dla zaznaczonych</button>
    <button class="btn sm ghost" data-act="unsel">odznacz</button></div></div>
  <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th class="w"><input type="checkbox" id="selall" title="zaznacz widoczne"></th>
    <th>Host</th><th>IP</th><th>Spółka</th><th>Zespół</th><th>Typ / system</th><th>Ekspozycja</th><th>Status</th><th class="num">Otwarte</th><th class="num">Aplikacje</th><th>Właściciel</th></tr></thead>
    <tbody id="hbody"></tbody></table></div><div id="more"></div></div>
  ${companyDatalist()}`;
  let rows = [];
  const bulkValue = () => {
    const f = $('#bf', el).value;
    const w = $('#bvwrap', el);
    if (f === 'team') w.innerHTML = `<select id="bv">${options(teamOpts('— automatycznie (wg reguł) —'), '')}</select>`;
    else if (f === 'exposure') w.innerHTML = `<select id="bv">${options(EXPOSURE_OPTS, '')}</select>`;
    else w.innerHTML = `<input type="text" id="bv" ${f === 'company' ? 'list="complist"' : ''} placeholder="nowa wartość (puste = wyczyść)">`;
  };
  bulkValue();
  $('#bf', el).addEventListener('change', bulkValue);
  const updBulk = () => {
    $('#bulk', el).classList.toggle('hidden', !sel.size);
    $('#bulkn', el).textContent = `Zaznaczono: ${sel.size}`;
  };
  const draw = () => {
    const f = $('#hq', el).value.toLowerCase(), c = $('#hc', el).value, m = $('#hm', el).value,
      t = $('#ht', el).value, e = $('#he', el).value, s = $('#hs', el).value;
    rows = r.hosts.filter((h) => (!f || [h.hostname, h.ip, h.owner, h.admin, h.os, h.company].join(' ').toLowerCase().includes(f))
      && (!c || (c === '__none__' ? !h.company : h.company === c)) && (!m || h.team === m)
      && (!t || h.type === t) && (!e || h.exposure === e) && (!s || (s === 'open' ? h.open : s === 'kev' ? h.open_kev : !h.open)));
    const shown = showAll ? rows : rows.slice(0, LIMIT);
    $('#hbody', el).innerHTML = shown.length ? shown.map((h) => `<tr class="clickable" data-href="#/host/${enc(h.id)}">
      <td class="w"><input type="checkbox" class="hsel" value="${esc(h.id)}"${sel.has(h.id) ? ' checked' : ''}></td>
      <td>${hostLink(h.id, h.hostname)}${h.mitigations ? ` <span class="b blue" title="zdefiniowane mitygacje">🛡 ${h.mitigations}</span>` : ''}</td><td class="mono small">${esc(h.ip)}</td>
      <td class="small">${esc(h.company || '')}</td>
      <td class="small" title="${esc(h.team_source)}">${h.team === '__none__' ? '<span class="faint">—</span>' : esc(h.team_label)}</td>
      <td>${esc(h.type)} <span class="small faint">${esc(h.os)}</span></td><td>${expBadge(h.exposure)}</td><td>${badge(h.status)}</td>
      <td class="num">${h.open}${h.open_kev ? ` <span class="b kev">${h.open_kev}</span>` : ''}</td><td class="num">${h.apps}</td><td>${esc(h.owner)}</td></tr>`).join('')
      : '<tr><td colspan="11" class="empty">Brak hostów — <a href="#/import">zaimportuj z Excela</a></td></tr>';
    $('#more', el).innerHTML = rows.length > shown.length
      ? `<div class="row addrow"><span class="muted small">Pokazano ${shown.length} z ${rows.length}</span><button class="btn sm" data-act="all">Pokaż wszystkie</button></div>` : '';
  };
  draw();
  ['#hq', '#hc', '#hm', '#ht', '#he', '#hs'].forEach((x) => $(x, el).addEventListener('input', draw));
  el.addEventListener('change', (e) => {
    if (e.target.classList.contains('hsel')) {
      if (e.target.checked) sel.add(e.target.value); else sel.delete(e.target.value);
      updBulk();
    }
    if (e.target.id === 'selall') {
      const vis = $$('.hsel', el);
      vis.forEach((cb) => { cb.checked = e.target.checked; if (cb.checked) sel.add(cb.value); else sel.delete(cb.value); });
      updBulk();
    }
  });
  onAct(el, {
    new: () => $('#newh', el).classList.toggle('hidden'),
    all: () => { showAll = true; draw(); },
    unsel: () => { sel.clear(); $('#selall', el).checked = false; draw(); updBulk(); },
    bulk: async () => {
      const field = $('#bf', el).value, value = $('#bv', el).value;
      if (!confirm(`Ustawić „${field}” = „${value || '(puste)'}” dla ${sel.size} hostów?`)) return;
      if (await guard(() => PUT('/api/hosts/bulk', { ids: [...sel], fields: { [field]: value } }), `Zaktualizowano ${sel.size} hostów`)) {
        App.meta = await GET('/api/meta'); render();
      }
    },
    create: async () => {
      const res = await guard(() => POST('/api/hosts', formData($('#newh', el))), 'Dodano');
      if (res) location.hash = '#/host/' + res.id;
    },
    csv: () => downloadCSV('hosty.csv', ['Host', 'IP', 'Spółka', 'Zespół', 'Typ', 'System', 'Ekspozycja', 'Status', 'Otwarte', 'Otwarte KEV', 'Aplikacje', 'Właściciel', 'Administrator'],
      rows.map((h) => [h.hostname, h.ip, h.company, h.team_label, h.type, h.os, h.exposure, STATUS[h.status], h.open, h.open_kev, h.apps, h.owner, h.admin])),
  });
}

function hostForm(h, autoTeam) {
  const f = (n, l, ph = '', extra = '') => `<label>${l}<input type="text" name="${n}" value="${esc(h[n] || '')}" placeholder="${esc(ph)}" ${extra}></label>`;
  return `<div class="form">
    ${f('hostname', 'Nazwa hosta / urządzenia')}${f('ip', 'Adres IP')}
    ${f('company', 'Spółka', 'np. WB Electronics', 'list="complist"')}
    <label>Zespół (realizator)<select name="team">${options(teamOpts(`— automatycznie${autoTeam ? ': ' + autoTeam : ' (wg reguł)'} —`), h.team || '')}</select></label>
    ${f('type', 'Typ', 'serwer, switch, firewall…')}${f('os', 'System / firmware')}${f('os_version', 'Wersja / build systemu', 'np. 10.0.17763.6414')}
    <label>Ekspozycja<select name="exposure">${options(EXPOSURE_OPTS, h.exposure || '')}</select></label>
    ${f('environment', 'Środowisko', 'prod / test')}${f('criticality', 'Krytyczność')}${f('location', 'Lokalizacja')}
    ${f('owner', 'Właściciel / odpowiedzialny')}${f('admin', 'Administrator')}${f('user', 'Użytkownik')}
    <label class="wide">Notatki<textarea name="notes" rows="2">${esc(h.notes || '')}</textarea></label></div>`;
}

async function viewHost(el, [hid]) {
  const r = await GET(`/api/hosts/${enc(hid)}/report`);
  await loadProducts();
  const h = r.host, s = r.summary;
  r.installations.forEach((i) => { if (i.team === r.team.id) i.team_label = ''; });   // pokazuj tylko, gdy łata inny zespół niż hosta
  const groups = App.meta.settings.groups;
  const gname = (id) => (groups.find((g) => g.id === id) || { name: id }).name;
  el.innerHTML = `
  <div class="page-head"><div><h1>${esc(h.hostname)} ${expBadge(h.exposure)}</h1>
      <div class="muted">${esc(h.type || '')} ${esc(h.os || '')} · <span class="mono">${esc(h.ip || '')}</span> · ${h.company ? 'spółka: <b>' + esc(h.company) + '</b> · ' : ''}zespół: <b title="${esc(r.team.source)}">${esc(r.team.label)}</b> · właściciel: ${esc(h.owner || '—')}</div></div>
    <div class="actions"><a class="btn primary" href="#/report/host/${enc(hid)}">Raport na okno serwisowe</a></div></div>
  <div class="tiles">
    <div class="tile ${s.open ? 'red' : 'green'}"><div class="v">${s.open}</div><div class="l">otwarte podatności</div></div>
    <div class="tile ${s.open_kev ? 'red' : 'green'}"><div class="v">${s.open_kev}</div><div class="l">w tym KEV</div></div>
    <div class="tile violet"><div class="v">${s.counts.exception || 0}</div><div class="l">objęte wyjątkiem</div></div>
    <div class="tile"><div class="v">${s.counts.mitigated || 0}</div><div class="l">mitygowane</div></div>
    <div class="tile green"><div class="v">${s.counts.fixed || 0}</div><div class="l">załatane</div></div>
  </div>
  <div class="panel tight"><div class="panel-head"><h2>Aplikacje i podatności</h2></div>${installTable(r.installations, false)}
    <div class="addrow row w" id="addinst">
      <input type="text" list="prodlist" name="product" placeholder="aplikacja"><input type="text" name="version" placeholder="wersja" class="mono">
      <button class="btn sm w" data-act="addinst">Dodaj / zmień wersję ręcznie</button></div></div>
  <div class="grid g2">
    <div class="panel"><h2>Zabezpieczenia hosta (mitygacje)</h2>
      <p class="small muted">Podatności z wybranej grupy (albo konkretne CVE) nie będą liczone jako „do działań” na tym hoście.</p>
      ${(h.mitigations || []).length ? `<table><tbody>${h.mitigations.map((m) => `<tr><td>${m.group ? `<span class="b blue">${esc(gname(m.group))}</span>` : cveLink(m.cve_id)}
        ${m.product_id ? `<div class="small faint">tylko: ${esc((App.products.find((p) => p.id === m.product_id) || {}).name || '?')}</div>` : ''}</td>
        <td>${esc(m.description)}</td><td class="small muted nowrap">${esc(m.added_at)}${byTxt(m.added_by)}</td><td><button class="btn sm ghost w" data-act="delmit" data-id="${esc(m.id)}">✕</button></td></tr>`).join('')}</tbody></table>` : '<div class="muted small">Brak</div>'}
      ${h.exposure === 'internal' ? '<div class="callout info small">Host w sieci wewnętrznej — CVE z grupą „Wymaga ekspozycji do Internetu” są mitygowane automatycznie.</div>' : ''}
      <div class="w"><h3>Dodaj</h3><div class="form" id="mitform">
        <label>Grupa podatności<select name="group">${options(groups.map((g) => [g.id, g.name]), '', '— lub konkretne CVE —')}</select></label>
        <label>…albo CVE<input type="text" name="cve_id" class="mono" placeholder="CVE-2024-…"></label>
        <label>Tylko dla aplikacji (opc.)<select name="product_id">${options(r.installations.map((i) => [i.product_id, i.product]), '', '— wszystkie —')}</select></label>
        <label class="wide">Opis zabezpieczenia<input type="text" name="description" placeholder="np. port zarządzania dostępny tylko z VLAN admin, ACL na FW"></label>
      </div><div class="row end mt8"><button class="btn primary sm w" data-act="addmit">Dodaj mitygację</button></div></div>
    </div>
    <div class="panel"><h2>Wyjątki (informacja od właściciela)</h2>
      ${r.exceptions.length ? `<table><tbody>${r.exceptions.map((x) => `<tr><td>${esc((App.products.find((p) => p.id === x.product_id) || {}).name || 'wszystkie aplikacje')} ${x.cve_id ? cveLink(x.cve_id) : ''}
        <div class="small">${esc(x.reason)}</div><div class="small faint">${esc(x.contact || '')} ${x.compensating ? '· ' + esc(x.compensating) : ''}${x.created_by ? ' · wpisał ' + esc(x.created_by) : ''}</div></td>
        <td class="nowrap small">${x.review_at ? `przegląd ${esc(x.review_at)}` : ''}${x.active === false ? ' <span class="b gray">nieaktywny</span>' : ''}</td></tr>`).join('')}</tbody></table>` : '<div class="muted small">Brak</div>'}
      <div class="w"><h3>Dodaj wyjątek</h3><div class="form" id="excform">
        <label>Aplikacja<select name="product_id">${options(r.installations.map((i) => [i.product_id, i.product]), '', '— wszystkie na hoście —')}</select></label>
        <label>CVE (puste = wszystkie)<input type="text" name="cve_id" class="mono"></label>
        <label class="wide">Powód / informacja od właściciela<textarea name="reason" rows="2" placeholder="np. dostawca systemu nie certyfikuje PostgreSQL 16 — aktualizacja po migracji w Q2"></textarea></label>
        <label>Kto przekazał<input type="text" name="contact"></label>
        <label>Środki kompensujące<input type="text" name="compensating"></label>
        <label>Data przeglądu<input type="date" name="review_at"></label>
      </div><div class="row end mt8"><button class="btn primary sm w" data-act="addexc">Dodaj wyjątek</button></div></div>
    </div>
  </div>
  <div class="panel" id="hform"><h2>Dane hosta</h2>${hostForm(h, h.team ? '' : r.team.label + ' (' + r.team.source + ')')}
    <div class="row end mt8"><button class="btn danger w" data-act="delhost">Usuń host</button><button class="btn primary w" data-act="savehost">Zapisz</button></div></div>
  <div id="hist"></div>
  ${productDatalist()}${companyDatalist()}`;
  historyPanel($('#hist', el), hid);
  onAct(el, {
    savehost: async () => { if (await guard(() => PUT('/api/hosts/' + enc(hid), { ...formData($('#hform', el)), _version: h.updated_at }), 'Zapisano')) render(); },
    delhost: async () => {
      if (!confirm(`Usunąć ${h.hostname} wraz z inwentarzem i wyjątkami?`)) return;
      if (await guard(() => DEL('/api/hosts/' + enc(hid)), 'Usunięto')) location.hash = '#/hosts';
    },
    addmit: async () => { if (await guard(() => POST(`/api/hosts/${enc(hid)}/mitigations`, formData($('#mitform', el))), 'Dodano mitygację')) render(); },
    delmit: async (b) => { if (await guard(() => DEL(`/api/hosts/${enc(hid)}/mitigations/${enc(b.dataset.id)}`))) render(); },
    addexc: async () => { if (await guard(() => POST('/api/exceptions', { ...formData($('#excform', el)), host_id: hid }), 'Dodano wyjątek')) render(); },
    addinst: async () => {
      const f = formData($('#addinst', el));
      const p = productByName(f.product);
      if (await guard(() => POST(`/api/hosts/${enc(hid)}/installations`, p ? { product_id: p.id, version: f.version } : f), 'Zapisano')) { App.products = null; render(); }
    },
    rminst: async (b) => {
      if (!confirm('Oznaczyć aplikację jako odinstalowaną z tego hosta?')) return;
      if (await guard(() => DEL(`/api/inventory/${enc(hid)}/${enc(b.dataset.p)}${b.dataset.key ? '?key=' + enc(b.dataset.key) : ''}`), 'Oznaczono jako usunięte')) render();
    },
  });
}

/* =================================================================== WYJĄTKI */
async function viewExceptions(el) {
  const r = await GET('/api/exceptions');
  el.innerHTML = `
  <div class="page-head"><div><h1>Wyjątki i akceptacje ryzyka</h1><div class="muted">Sytuacje, w których aktualizacja nie jest możliwa — z datą ponownego przeglądu</div></div>
    <div class="actions"><button class="btn" data-act="csv">CSV</button></div></div>
  <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th>Zakres</th><th>Powód</th><th>Od kogo</th><th>Utworzono</th><th>Przegląd</th><th>Aktywny</th><th></th></tr></thead><tbody>
  ${r.exceptions.length ? r.exceptions.map((x) => `<tr>
    <td>${x.host_id ? hostLink(x.host_id, x.hostname || '?') : '<i>wszystkie hosty</i>'} · ${x.product_id ? prodLink(x.product_id, x.product || '?') : '<i>wszystkie aplikacje</i>'}${x.cve_id ? ' · ' + cveLink(x.cve_id) : ''}</td>
    <td><textarea rows="2" data-id="${esc(x.id)}" data-f="reason">${esc(x.reason)}</textarea>${x.compensating ? `<div class="small faint">kompensacja: ${esc(x.compensating)}</div>` : ''}</td>
    <td class="small">${esc(x.contact || '')}</td><td class="small nowrap">${esc(x.created_at)}${byTxt(x.created_by)}</td>
    <td><input type="date" value="${esc(x.review_at || '')}" data-id="${esc(x.id)}" data-f="review_at">${x.overdue ? '<div><span class="b violet">po terminie</span></div>' : ''}</td>
    <td><input type="checkbox" data-id="${esc(x.id)}" data-f="active"${x.active !== false ? ' checked' : ''}></td>
    <td class="nowrap"><button class="btn sm w" data-act="save" data-id="${esc(x.id)}">Zapisz</button> <button class="btn sm ghost danger w" data-act="del" data-id="${esc(x.id)}">✕</button></td></tr>`).join('')
    : '<tr><td colspan="7" class="empty">Brak wyjątków. Dodasz je na stronie hosta.</td></tr>'}
  </tbody></table></div></div>`;
  onAct(el, {
    save: async (b) => {
      const id = b.dataset.id, body = {};
      $$(`[data-id="${id}"][data-f]`, el).forEach((i) => { body[i.dataset.f] = i.type === 'checkbox' ? i.checked : i.value; });
      if (await guard(() => PUT('/api/exceptions/' + enc(id), body), 'Zapisano')) render();
    },
    del: async (b) => { if (confirm('Usunąć wyjątek?') && await guard(() => DEL('/api/exceptions/' + enc(b.dataset.id)), 'Usunięto')) render(); },
    csv: () => downloadCSV('wyjatki.csv', ['Host', 'Aplikacja', 'CVE', 'Powód', 'Od kogo', 'Kompensacja', 'Utworzono', 'Przegląd', 'Aktywny'],
      r.exceptions.map((x) => [x.hostname || 'wszystkie', x.product || 'wszystkie', x.cve_id || '', x.reason, x.contact, x.compensating, x.created_at, x.review_at, x.active !== false ? 'tak' : 'nie'])),
  });
}

/* =================================================================== USTAWIENIA */
async function viewSettings(el) {
  const s = await GET('/api/settings');
  const td = App.meta.ticket_defaults;
  const FIELDS = Object.entries(App.meta.team_rule_fields);
  const st = { teams: (s.teams || []).map((t) => ({ ...t })), rules: (s.team_rules || []).map((r) => ({ ...r })) };
  el.innerHTML = `
  <div class="page-head"><div><h1>Ustawienia</h1><div class="muted">Zespoły i reguły przypisania, terminy (SLA), szablon zgłoszeń, import</div></div></div>
  <div class="panel"><div class="panel-head"><h2>Zespoły (realizatorzy)</h2><div class="row"><button class="btn sm" data-act="addteam">+ zespół</button>
      <button class="btn primary sm" data-act="saveteams">Zapisz zespoły i reguły</button></div></div>
    <p class="small muted">Adres e-mail trafia do pola „Do” w zgłoszeniu (.eml). Może być kilka adresów po przecinku, np. kolejka helpdesku.</p>
    <table id="teamtbl"><thead><tr><th>ID</th><th>Nazwa</th><th>E-mail (helpdesk / kolejka)</th><th>Opis</th><th></th></tr></thead><tbody></tbody></table>
    <h3>Reguły przypisania hostów do zespołów</h3>
    <p class="small muted">Sprawdzane od góry — wygrywa pierwsza pasująca. Wzorce rozdzielasz przecinkami, <code>*</code> = dowolny ciąg, wielkość liter bez znaczenia.
      Kolejność: zespół ustawiony na aplikacji (np. DBA dla PostgreSQL) → reguły „Aplikacja” → zespół ustawiony ręcznie na hoście → pozostałe reguły.</p>
    <table id="ruletbl"><thead><tr><th>#</th><th>Pole</th><th>Wzorzec</th><th>Zespół</th><th></th></tr></thead><tbody></tbody></table>
    <div class="row mt8"><button class="btn sm" data-act="addrule">+ reguła</button><button class="btn sm" data-act="testrules">Sprawdź przypisanie hostów</button></div>
    <div id="ruletest"></div>
  </div>
  <div class="grid g2">
    <div class="panel" id="slaform"><h2>Terminy załatania (SLA)</h2>
      <p class="small muted">Podpowiedź terminu przy ocenie CVE: data oceny + liczba dni dla poziomu ryzyka. Dla wpisów KEV bez własnej oceny obowiązuje termin CISA.</p>
      <div class="form">${RISK_OPTS.map(([k, l]) => `<label>${l} (dni)<input type="number" min="1" name="${k}" value="${esc((s.sla_days || {})[k] || '')}"></label>`).join('')}</div>
      <div class="row end mt8"><button class="btn primary sm" data-act="savesla">Zapisz SLA</button></div>
      <h3>Aktualność weryfikacji</h3>
      <div class="form" id="sform">
        <label>Ostrzeżenie po (dniach)<input type="number" name="stale_warn_days" value="${s.stale_warn_days}" min="1"></label>
        <label>Alarm po (dniach)<input type="number" name="stale_crit_days" value="${s.stale_crit_days}" min="1"></label>
      </div>
      <div class="row end mt8"><button class="btn primary sm" data-act="savestale">Zapisz</button></div>
    </div>
    <div class="panel" id="impform"><h2>Import (Lansweeper, CMDB, Excel)</h2>
      <label class="field wide">Pomijaj aplikacje pasujące do wzorców (po przecinku)
        <textarea name="import_ignore" rows="4" class="mono">${esc(s.import_ignore || '')}</textarea></label>
      <div class="checks mt8">
        <label><input type="checkbox" name="import_normalize"${s.import_normalize ? ' checked' : ''}> upraszczaj nazwy aplikacji („PostgreSQL 14” → „PostgreSQL”, „7-Zip 23.01 (x64)” → „7-Zip”)</label>
        <label><input type="checkbox" name="import_os_as_app"${s.import_os_as_app ? ' checked' : ''}> traktuj system operacyjny jako aplikację (Windows Server 2019, Cisco IOS XE… — do oceny CVE systemów)</label>
      </div>
      <label class="field mt8">Ile ostatnich importów trzymać ze szczegółami (do porównań)<input type="number" name="history_keep" min="2" max="500" value="${esc(s.history_keep || 24)}"></label>
      <div class="row end mt8"><button class="btn primary sm" data-act="saveimp">Zapisz</button></div>
    </div>
  </div>
  <div class="panel" id="tplform"><div class="panel-head"><h2>Szablon zgłoszenia do realizatorów</h2>
      <div class="row"><button class="btn sm" data-act="tpldefault">Przywróć domyślny</button><button class="btn primary sm" data-act="savetpl">Zapisz szablon</button></div></div>
    <div class="form">
      <label>Prefiks w temacie<input type="text" name="ticket_prefix" value="${esc(s.ticket_prefix || 'VULN')}"></label>
      <label>Nadawca (opcjonalnie, pole „Od” w .eml)<input type="text" name="ticket_sender" value="${esc(s.ticket_sender || '')}" placeholder="security@firma.pl"></label>
      <label class="wide">Temat<input type="text" name="ticket_subject" class="mono" value="${esc(s.ticket_subject || td.subject)}"></label>
      <label class="wide">Treść<textarea name="ticket_template" rows="18" class="mono">${esc(s.ticket_template || td.template)}</textarea></label>
      <label class="wide">Podpis ({podpis})<textarea name="ticket_signature" rows="3">${esc(s.ticket_signature || '')}</textarea></label>
    </div>
    <details class="mt8"><summary class="small">Dostępne pola (wstawiane z oceny CVE i listy hostów)</summary>
      <table class="mt8"><tbody>${Object.entries(td.placeholders).map(([k, v]) => `<tr><td class="mono">{${esc(k)}}</td><td class="small">${esc(v)}</td></tr>`).join('')}</tbody></table></details>
  </div>
  <div class="grid g2">
    <div class="panel"><div class="panel-head"><h2>Grupy podatności (mitygacje)</h2><button class="btn sm w" data-act="addg">+ grupa</button></div>
      <p class="small muted">CVE dostaje grupy, host — zabezpieczenia neutralizujące daną grupę.</p>
      <div class="tbl-wrap"><table id="gtbl"><thead><tr><th>ID</th><th>Nazwa</th><th>Opis</th><th></th></tr></thead><tbody>
      ${s.groups.map((g) => groupRow(g)).join('')}</tbody></table></div>
      <div class="row end mt8"><button class="btn primary sm w" data-act="saveg">Zapisz grupy</button></div>
    </div>
    <div class="panel"><h2>Kopia zapasowa</h2>
      <p class="small muted">Plik jest zaszyfrowany — otworzy go każdy aktywny użytkownik swoim hasłem. Automatyczne kopie: <code>data/backups/</code> (co godzinę i przed każdym importem).
        Szczegóły importów (do porównań) są w <code>data/imports/</code> — kopiuj cały katalog <code>data</code>.</p>
      <a class="btn sm" href="/api/backup">Pobierz zaszyfrowaną kopię bazy</a>
      <div class="callout info mt8">Zmiana własnego hasła: <a href="#/account">Moje konto</a> · konta: <a href="#/users">Użytkownicy</a> · historia: <a href="#/audit">Dziennik zmian</a></div>
    </div>
  </div>`;
  const drawTeams = () => {
    $('#teamtbl tbody', el).innerHTML = st.teams.map((t, i) => `<tr>
      <td><input type="text" class="mono" data-t="${i}" data-f="id" value="${esc(t.id)}" size="10" ${t._new ? '' : 'readonly'}></td>
      <td><input type="text" data-t="${i}" data-f="name" value="${esc(t.name)}"></td>
      <td><input type="text" data-t="${i}" data-f="email" value="${esc(t.email || '')}" placeholder="helpdesk@firma.pl"></td>
      <td><input type="text" data-t="${i}" data-f="description" value="${esc(t.description || '')}"></td>
      <td><button class="btn sm ghost" data-act="delteam" data-i="${i}">✕</button></td></tr>`).join('');
  };
  const drawRules = () => {
    const tOpts = st.teams.map((t) => [t.id, t.name || t.id]);
    $('#ruletbl tbody', el).innerHTML = st.rules.map((r, i) => `<tr>
      <td class="faint">${i + 1}</td>
      <td><select data-r="${i}" data-f="field">${options(FIELDS, r.field)}</select></td>
      <td><input type="text" class="mono" data-r="${i}" data-f="pattern" value="${esc(r.pattern)}" size="60"></td>
      <td><select data-r="${i}" data-f="team">${options(tOpts, r.team)}</select></td>
      <td class="nowrap"><button class="btn sm ghost" data-act="up" data-i="${i}">↑</button><button class="btn sm ghost" data-act="down" data-i="${i}">↓</button>
        <button class="btn sm ghost" data-act="delrule" data-i="${i}">✕</button></td></tr>`).join('');
  };
  drawTeams(); drawRules();
  el.addEventListener('input', (e) => {
    const d = e.target.dataset;
    if (d.t !== undefined) { st.teams[+d.t][d.f] = e.target.value; if (d.f === 'name') drawRules(); }
    if (d.r !== undefined) st.rules[+d.r][d.f] = e.target.value;
  });
  const reloadMeta = async () => { App.meta = await GET('/api/meta'); };
  onAct(el, {
    addteam: () => { st.teams.push({ id: '', name: '', email: '', description: '', _new: true }); drawTeams(); },
    delteam: (b) => { st.teams.splice(+b.dataset.i, 1); drawTeams(); drawRules(); },
    addrule: () => { st.rules.push({ field: 'os', pattern: '', team: (st.teams[0] || {}).id }); drawRules(); },
    delrule: (b) => { st.rules.splice(+b.dataset.i, 1); drawRules(); },
    up: (b) => { const i = +b.dataset.i; if (i > 0) { [st.rules[i - 1], st.rules[i]] = [st.rules[i], st.rules[i - 1]]; drawRules(); } },
    down: (b) => { const i = +b.dataset.i; if (i < st.rules.length - 1) { [st.rules[i + 1], st.rules[i]] = [st.rules[i], st.rules[i + 1]]; drawRules(); } },
    testrules: async () => {
      const r = await guard(() => POST('/api/teams/test', { teams: st.teams, team_rules: st.rules }));
      if (!r) return;
      $('#ruletest', el).innerHTML = `<table class="mt8"><thead><tr><th>Zespół</th><th class="num">Hosty</th><th>Przykłady</th></tr></thead><tbody>
        ${r.per_team.map((t) => `<tr><td>${t.team === '__none__' ? '<span class="b amber">Nieprzypisany</span>' : esc(t.label)}</td><td class="num">${t.hosts}</td>
          <td class="small mono">${esc(t.examples.join(', '))}</td></tr>`).join('') || '<tr><td colspan="3" class="empty">Brak hostów</td></tr>'}</tbody></table>`;
    },
    saveteams: async () => {
      const teams = st.teams.map(({ _new, ...t }) => t);
      if (await guard(() => PUT('/api/settings', { teams, team_rules: st.rules }), 'Zapisano zespoły i reguły')) { await reloadMeta(); render(); }
    },
    savesla: async () => {
      const f = formData($('#slaform .form', el));
      if (await guard(() => PUT('/api/settings', { sla_days: Object.fromEntries(Object.entries(f).filter(([, v]) => v)) }), 'Zapisano SLA')) await reloadMeta();
    },
    savestale: async () => {
      const f = formData($('#sform', el));
      if (await guard(() => PUT('/api/settings', { stale_warn_days: +f.stale_warn_days, stale_crit_days: +f.stale_crit_days }), 'Zapisano')) await reloadMeta();
    },
    saveimp: async () => {
      const f = formData($('#impform', el));
      if (await guard(() => PUT('/api/settings', { ...f, history_keep: +f.history_keep }), 'Zapisano ustawienia importu')) await reloadMeta();
    },
    tpldefault: () => {
      $('#tplform [name=ticket_subject]', el).value = td.subject;
      $('#tplform [name=ticket_template]', el).value = td.template;
      toast('Wstawiono domyślny szablon — zapisz, aby zastosować');
    },
    savetpl: async () => {
      const f = formData($('#tplform', el));
      if (f.ticket_subject === td.subject) f.ticket_subject = '';
      if (f.ticket_template === td.template) f.ticket_template = '';
      if (await guard(() => PUT('/api/settings', f), 'Zapisano szablon')) await reloadMeta();
    },
    addg: () => $('#gtbl tbody', el).insertAdjacentHTML('beforeend', groupRow({ id: '', name: '', description: '' })),
    delg: (b) => b.closest('tr').remove(),
    saveg: async () => {
      const groups = $$('#gtbl tbody tr', el).map((tr) => ({ id: $('[data-g=id]', tr).value, name: $('[data-g=name]', tr).value, description: $('[data-g=description]', tr).value })).filter((g) => g.id || g.name);
      if (await guard(() => PUT('/api/settings', { groups }), 'Zapisano grupy')) { await reloadMeta(); render(); }
    },
  });
}
function groupRow(g) {
  return `<tr><td><input type="text" class="mono" data-g="id" value="${esc(g.id)}" size="14"></td><td><input type="text" data-g="name" value="${esc(g.name)}"></td>
    <td><input type="text" data-g="description" value="${esc(g.description)}"></td><td><button class="btn sm ghost" data-act="delg">✕</button></td></tr>`;
}
