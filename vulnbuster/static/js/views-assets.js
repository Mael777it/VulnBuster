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
    <div class="actions"><a class="btn primary" href="#/report/product/${enc(pid)}">Raport do druku</a><button class="btn" data-act="csv">CSV</button></div></div>
  <div class="grid g2">
    <div class="panel" id="pform"><h2>Dane i status</h2><div class="form">
      <label>Nazwa<input type="text" name="name" value="${esc(p.name)}"></label>
      <label>Producent<input type="text" name="vendor" value="${esc(p.vendor || '')}"></label>
      <label>Status<select name="status">${options(PSTATUS_OPTS, p.status || 'unknown')}</select></label>
      <label>Kategoria<input type="text" name="category" value="${esc(p.category || '')}" placeholder="baza danych, VPN, system…"></label>
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
    csv: () => downloadCSV(`${p.name}-instalacje.csv`, ['Host', 'IP', 'Typ', 'Ekspozycja', 'Właściciel', 'Wersja', 'Status', 'Wersja docelowa', 'Otwarte CVE'],
      r.installations.map((i) => [i.hostname, i.ip, i.type, i.exposure, i.owner, i.version, STATUS[i.summary.status], i.summary.target || '',
        i.findings.filter((f) => ['vulnerable', 'review'].includes(f.status)).map((f) => f.cve).join(' ')])),
  });
}

function findingsList(fs) {
  if (!fs.length) return '<span class="faint small">brak CVE z regułami</span>';
  return `<ul class="findings">${fs.map((f) => `<li>${badge(f.status)} ${cveLink(f.cve)} ${kevBadge(f.kev, f.kev_ransomware)}
    <span class="muted">${esc(f.reason)}</span>${f.overlay ? `<span class="faint">— ${f.overlay.type === 'exception' ? 'wyjątek' : 'mitygacja'}: ${esc(f.overlay.text)}${f.overlay.overdue ? ' <span class="b violet">przegląd po terminie</span>' : ''}</span>` : ''}</li>`).join('')}</ul>`;
}

function installTable(insts, byHost) {
  if (!insts.length) return '<div class="empty">Brak instalacji</div>';
  return `<div class="tbl-wrap"><table><thead><tr><th>${byHost ? 'Host' : 'Aplikacja'}</th><th>Wersja</th><th>Status</th><th>Docelowa</th><th>Podatności</th>${byHost ? '<th>Właściciel</th>' : '<th></th>'}</tr></thead><tbody>
  ${insts.map((i) => `<tr><td>${byHost ? hostLink(i.host_id, i.hostname) + `<div>${expBadge(i.exposure)} <span class="small faint">${esc(i.type || '')}</span></div>` : prodLink(i.product_id, i.product)}</td>
    <td class="mono nowrap">${esc(i.version || '—')}${i.history && i.history.length > 1 ? `<div class="small faint">poprz. ${esc(i.history[i.history.length - 2].version)}</div>` : ''}</td>
    <td>${badge(i.summary.status)}</td><td class="mono">${esc(i.summary.target || (i.summary.nofix ? 'brak poprawki' : ''))}</td>
    <td>${findingsList(i.findings)}</td>${byHost ? `<td>${esc(i.owner)}</td>` : `<td><button class="btn sm ghost w" data-act="rminst" data-p="${esc(i.product_id)}" title="Oznacz jako odinstalowane">usuń</button></td>`}</tr>`).join('')}
  </tbody></table></div>`;
}

/* =================================================================== HOSTY */
async function viewHosts(el, _, q) {
  const r = await GET('/api/hosts');
  const types = [...new Set(r.hosts.map((h) => h.type).filter(Boolean))].sort();
  el.innerHTML = `
  <div class="page-head"><div><h1>Hosty i urządzenia</h1><div class="muted">${r.hosts.length} pozycji</div></div>
    <div class="actions"><button class="btn w" data-act="new">Dodaj ręcznie</button><button class="btn" data-act="csv">CSV</button></div></div>
  <div class="panel hidden" id="newh"><h2>Nowy host / urządzenie</h2>${hostForm({})}
    <div class="row end mt8"><button class="btn primary w" data-act="create">Dodaj</button></div></div>
  <div class="row mb12">
    <input type="search" id="hq" placeholder="Filtruj: nazwa, IP, właściciel…">
    <select id="ht">${options([['', 'Wszystkie typy'], ...types.map((t) => [t, t])], '')}</select>
    <select id="he">${options([['', 'Każda ekspozycja'], ...EXPOSURE_OPTS.slice(1)], '')}</select>
    <select id="hs">${options([['', 'Każdy status'], ['open', 'Wymaga działań'], ['kev', 'Z otwartym KEV'], ['ok', 'Bez działań']], q.f || '')}</select>
  </div>
  <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th>Host</th><th>IP</th><th>Typ / system</th><th>Ekspozycja</th><th>Status</th><th class="num">Otwarte</th><th class="num">Aplikacje</th><th>Właściciel</th></tr></thead>
    <tbody id="hbody"></tbody></table></div></div>`;
  let rows = [];
  const draw = () => {
    const f = $('#hq', el).value.toLowerCase(), t = $('#ht', el).value, e = $('#he', el).value, s = $('#hs', el).value;
    rows = r.hosts.filter((h) => (!f || [h.hostname, h.ip, h.owner, h.admin, h.os].join(' ').toLowerCase().includes(f))
      && (!t || h.type === t) && (!e || h.exposure === e) && (!s || (s === 'open' ? h.open : s === 'kev' ? h.open_kev : !h.open)));
    $('#hbody', el).innerHTML = rows.length ? rows.map((h) => `<tr class="clickable" data-href="#/host/${enc(h.id)}">
      <td>${hostLink(h.id, h.hostname)}${h.mitigations ? ` <span class="b blue" title="zdefiniowane mitygacje">🛡 ${h.mitigations}</span>` : ''}</td><td class="mono small">${esc(h.ip)}</td>
      <td>${esc(h.type)} <span class="small faint">${esc(h.os)}</span></td><td>${expBadge(h.exposure)}</td><td>${badge(h.status)}</td>
      <td class="num">${h.open}${h.open_kev ? ` <span class="b kev">${h.open_kev}</span>` : ''}</td><td class="num">${h.apps}</td><td>${esc(h.owner)}</td></tr>`).join('')
      : '<tr><td colspan="8" class="empty">Brak hostów — <a href="#/import">zaimportuj z Excela</a></td></tr>';
  };
  draw();
  ['#hq', '#ht', '#he', '#hs'].forEach((s) => $(s, el).addEventListener('input', draw));
  onAct(el, {
    new: () => $('#newh', el).classList.toggle('hidden'),
    create: async () => {
      const res = await guard(() => POST('/api/hosts', formData($('#newh', el))), 'Dodano');
      if (res) location.hash = '#/host/' + res.id;
    },
    csv: () => downloadCSV('hosty.csv', ['Host', 'IP', 'Typ', 'System', 'Ekspozycja', 'Status', 'Otwarte', 'Otwarte KEV', 'Aplikacje', 'Właściciel', 'Administrator'],
      rows.map((h) => [h.hostname, h.ip, h.type, h.os, h.exposure, STATUS[h.status], h.open, h.open_kev, h.apps, h.owner, h.admin])),
  });
}

function hostForm(h) {
  const f = (n, l, ph = '') => `<label>${l}<input type="text" name="${n}" value="${esc(h[n] || '')}" placeholder="${esc(ph)}"></label>`;
  return `<div class="form">
    ${f('hostname', 'Nazwa hosta / urządzenia')}${f('ip', 'Adres IP')}${f('type', 'Typ', 'serwer, switch, firewall…')}${f('os', 'System / firmware')}
    <label>Ekspozycja<select name="exposure">${options(EXPOSURE_OPTS, h.exposure || '')}</select></label>
    ${f('environment', 'Środowisko', 'prod / test')}${f('criticality', 'Krytyczność')}${f('location', 'Lokalizacja')}
    ${f('owner', 'Właściciel / odpowiedzialny')}${f('admin', 'Administrator')}${f('user', 'Użytkownik')}
    <label class="wide">Notatki<textarea name="notes" rows="2">${esc(h.notes || '')}</textarea></label></div>`;
}

async function viewHost(el, [hid]) {
  const r = await GET(`/api/hosts/${enc(hid)}/report`);
  await loadProducts();
  const h = r.host, s = r.summary;
  const groups = App.meta.settings.groups;
  const gname = (id) => (groups.find((g) => g.id === id) || { name: id }).name;
  el.innerHTML = `
  <div class="page-head"><div><h1>${esc(h.hostname)} ${expBadge(h.exposure)}</h1>
      <div class="muted">${esc(h.type || '')} ${esc(h.os || '')} · <span class="mono">${esc(h.ip || '')}</span> · właściciel: ${esc(h.owner || '—')} · admin: ${esc(h.admin || '—')}</div></div>
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
  <div class="panel" id="hform"><h2>Dane hosta</h2>${hostForm(h)}
    <div class="row end mt8"><button class="btn danger w" data-act="delhost">Usuń host</button><button class="btn primary w" data-act="savehost">Zapisz</button></div></div>
  <div id="hist"></div>
  ${productDatalist()}`;
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
      if (await guard(() => DEL(`/api/inventory/${enc(hid)}/${enc(b.dataset.p)}`), 'Oznaczono jako usunięte')) render();
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
  el.innerHTML = `
  <div class="page-head"><div><h1>Ustawienia</h1></div></div>
  <div class="grid g2">
    <div class="panel"><h2>Aktualność weryfikacji</h2>
      <div class="form" id="sform">
        <label>Ostrzeżenie po (dniach)<input type="number" name="stale_warn_days" value="${s.stale_warn_days}" min="1"></label>
        <label>Alarm po (dniach)<input type="number" name="stale_crit_days" value="${s.stale_crit_days}" min="1"></label>
      </div>
      <p class="small muted mt8">Decyzje „nie używamy / nie dotyczy” starsze niż próg będą oznaczone do ponownej weryfikacji.</p>
      <div class="row end"><button class="btn primary sm w" data-act="savestale">Zapisz</button></div>
      <h3>Kopia zapasowa</h3>
      <p class="small muted">Plik jest zaszyfrowany — otworzy go każdy aktywny użytkownik swoim hasłem. Automatyczne kopie zapisywane są w katalogu <code>backups/</code> obok pliku danych (co godzinę i przed każdym importem).</p>
      <a class="btn sm" href="/api/backup">Pobierz zaszyfrowaną kopię</a>
    </div>
    <div class="panel"><div class="panel-head"><h2>Grupy podatności</h2><button class="btn sm w" data-act="addg">+ grupa</button></div>
      <p class="small muted">Używane do mitygacji: CVE dostaje grupy, host — zabezpieczenia neutralizujące daną grupę.</p>
      <table id="gtbl"><thead><tr><th>ID</th><th>Nazwa</th><th>Opis</th><th></th></tr></thead><tbody>
      ${s.groups.map((g) => groupRow(g)).join('')}</tbody></table>
      <div class="row end mt8"><button class="btn primary sm w" data-act="saveg">Zapisz grupy</button></div>
    </div>
  </div>
  <div class="callout info">Zmiana własnego hasła: <a href="#/account">Moje konto</a> · konta użytkowników: <a href="#/users">Użytkownicy</a> · historia: <a href="#/audit">Dziennik zmian</a></div>`;
  onAct(el, {
    savestale: async () => {
      const f = formData($('#sform', el));
      if (await guard(() => PUT('/api/settings', { stale_warn_days: +f.stale_warn_days, stale_crit_days: +f.stale_crit_days }), 'Zapisano')) {
        App.meta = await GET('/api/meta');
      }
    },
    addg: () => $('#gtbl tbody', el).insertAdjacentHTML('beforeend', groupRow({ id: '', name: '', description: '' })),
    delg: (b) => b.closest('tr').remove(),
    saveg: async () => {
      const groups = $$('#gtbl tbody tr', el).map((tr) => ({ id: $('[data-g=id]', tr).value, name: $('[data-g=name]', tr).value, description: $('[data-g=description]', tr).value })).filter((g) => g.id || g.name);
      if (await guard(() => PUT('/api/settings', { groups }), 'Zapisano grupy')) { App.meta = await GET('/api/meta'); render(); }
    },
  });
}
function groupRow(g) {
  return `<tr><td><input type="text" class="mono" data-g="id" value="${esc(g.id)}" size="14"></td><td><input type="text" data-g="name" value="${esc(g.name)}"></td>
    <td><input type="text" data-g="description" value="${esc(g.description)}"></td><td><button class="btn sm ghost" data-act="delg">✕</button></td></tr>`;
}
