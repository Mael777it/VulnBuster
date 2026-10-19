/* SPDX-License-Identifier: MIT · Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com> */
/* Widoki: pulpit, wyszukiwarka, KEV, CVE */
'use strict';

/* =================================================================== PULPIT */
async function viewDashboard(el) {
  const d = await GET('/api/dashboard');
  const t = (v, l, cls, href) => `<a class="tile ${cls || ''}" href="${href}"><div class="v">${v}</div><div class="l">${l}</div></a>`;
  el.innerHTML = `
  <div class="page-head"><div><h1>Pulpit</h1><div class="muted">Stan podatności i zaległe weryfikacje</div></div>
    <div class="actions"><a class="btn primary" href="#/kev">Przegląd KEV</a><a class="btn" href="#/import">Import z Excela</a></div></div>
  ${!d.kev_updated_at ? '<div class="callout info">Katalog CISA KEV nie jest jeszcze załadowany — przejdź do <a href="#/kev">Przegląd KEV</a> i pobierz go albo wgraj plik JSON.</div>' : ''}
  <div class="tiles">
    ${t(d.open_findings, 'otwarte podatności (host×CVE)', d.open_findings ? 'red' : 'green', '#/hosts?f=open')}
    ${t(d.open_kev, 'w tym z KEV', d.open_kev ? 'red' : 'green', '#/hosts?f=kev')}
    ${t(d.kev_pending, 'KEV bez decyzji', d.kev_pending ? 'amber' : 'green', '#/kev')}
    ${t(d.stale.length, 'nieaktualne weryfikacje', d.stale.length ? 'amber' : 'green', '#/kev?view=stale')}
    ${t(d.exceptions_overdue.length, 'wyjątki po terminie przeglądu', d.exceptions_overdue.length ? 'violet' : '', '#/exceptions')}
    ${t(d.hosts, 'hosty / urządzenia', '', '#/hosts')}
    ${t(d.products_used, 'aplikacje używane', '', '#/products?tab=used')}
    ${t(d.products_not_used, 'aplikacje nieużywane', '', '#/products?tab=not_used')}
  </div>
  <div class="grid g2">
    <div class="panel tight"><div class="panel-head"><h2>Hosty wymagające działań</h2><a class="small" href="#/hosts?f=open">wszystkie →</a></div>
      ${d.top_hosts.length ? `<div class="tbl-wrap"><table><thead><tr><th>Host</th><th>Ekspozycja</th><th class="num">Otwarte</th><th class="num">KEV</th><th>Właściciel</th></tr></thead><tbody>
      ${d.top_hosts.map((h) => `<tr class="clickable" data-href="#/host/${enc(h.id)}"><td>${hostLink(h.id, h.hostname)}<div class="small faint">${esc(h.type || '')} ${esc(h.os || '')}</div></td>
        <td>${expBadge(h.exposure)}</td><td class="num">${h.open}</td><td class="num">${h.open_kev ? `<span class="b kev">${h.open_kev}</span>` : '0'}</td><td>${esc(h.owner)}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">Brak otwartych podatności 🎉</div>'}
    </div>
    <div class="panel tight"><div class="panel-head"><h2>Najnowsze wpisy KEV</h2><span class="small muted">katalog: ${esc(fmtDT(d.kev_updated_at))}</span></div>
      ${d.recent_kev.length ? `<div class="tbl-wrap"><table><tbody>
      ${d.recent_kev.map((k) => `<tr class="clickable" data-href="#/cve/${enc(k.cve)}"><td class="nowrap">${cveLink(k.cve)}<div class="small faint">${esc(k.dateAdded)}</div></td>
        <td>${esc(k.vendor)} <b>${esc(k.product)}</b></td><td>${triageBadge({ decision: k.decision })}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">Brak danych KEV</div>'}
    </div>
    <div class="panel tight"><div class="panel-head"><h2>Do ponownej weryfikacji</h2><span class="small muted">próg: ${App.meta.settings.stale_warn_days} / ${App.meta.settings.stale_crit_days} dni</span></div>
      ${d.stale.length ? `<div class="tbl-wrap"><table><tbody>
      ${d.stale.map((s) => `<tr>${s.cve ? `<td>${cveLink(s.cve)}</td><td>${triageBadge({ decision: s.decision })}</td>` : `<td>${prodLink(s.product_id, s.product)}</td><td>${prodBadge('not_used')}</td>`}
        <td>${staleBadge(s)}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">Wszystkie decyzje są aktualne</div>'}
    </div>
    <div class="panel tight"><div class="panel-head"><h2>Ostatnie importy</h2><a class="small" href="#/compare">porównaj →</a></div>
      ${d.imports.length ? `<div class="tbl-wrap"><table><tbody>
      ${d.imports.map((i) => `<tr><td>${esc(i.name)}</td><td class="small muted">${esc(fmtDT(i.created_at))}</td><td class="num">${i.rows} wierszy</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="empty">Brak importów — <a href="#/import">wklej dane z Excela</a></div>'}
      ${d.exceptions_overdue.length ? `<div class="panel-head"><h2>Wyjątki po terminie</h2></div><div class="tbl-wrap"><table><tbody>
        ${d.exceptions_overdue.map((x) => `<tr class="clickable" data-href="#/exceptions"><td>${esc(x.reason)}</td><td class="nowrap"><span class="b violet">przegląd ${esc(x.review_at)}</span></td></tr>`).join('')}
      </tbody></table></div>` : ''}
    </div>
  </div>`;
}

/* =================================================================== WYSZUKIWARKA */
async function viewSearch(el, _, q) {
  const term = q.q || '';
  const r = await GET('/api/search?q=' + enc(term));
  const none = !r.products.length && !r.cves.length && !r.hosts.length && !r.kev.length && !r.kev_products.length;
  el.innerHTML = `
  <div class="page-head"><div><h1>Wyniki: „${esc(term)}”</h1><div class="muted">Aplikacje, CVE, hosty, katalog KEV i Twoje notatki</div></div></div>
  ${none ? `<div class="panel empty">Nic nie znaleziono. <a href="#/products?new=${enc(term)}">Dodaj aplikację „${esc(term)}” i oznacz, czy jej używamy →</a></div>` : ''}
  ${r.products.length ? `<div class="panel tight"><div class="panel-head"><h2>Aplikacje</h2></div><div class="tbl-wrap"><table>
    <thead><tr><th>Aplikacja</th><th>Status</th><th>Weryfikacja</th><th class="num">Hosty</th><th>Notatka</th></tr></thead><tbody>
    ${r.products.map((p) => `<tr class="clickable" data-href="#/product/${enc(p.id)}"><td>${prodLink(p.id, p.name)}<div class="small faint">${esc(p.vendor || '')}</div></td>
      <td>${prodBadge(p.status)}</td><td>${staleBadge(p.stale)}</td><td class="num">${p.hosts}</td><td class="small">${esc((p.notes || '').slice(0, 160))}</td></tr>`).join('')}
    </tbody></table></div></div>` : ''}
  ${r.kev_products.length ? `<div class="panel tight"><div class="panel-head"><h2>Decyzje z przeglądu KEV</h2></div><div class="tbl-wrap"><table><tbody>
    ${r.kev_products.map((m) => `<tr><td><b>${esc(m.label)}</b><div class="small faint">ostatnio: ${cveLink(m.last_cve)}</div></td><td>${triageBadge({ decision: m.decision })}</td>
      <td>${staleBadge(m.stale)}</td><td class="small">${esc(m.note)}</td></tr>`).join('')}
    </tbody></table></div></div>` : ''}
  ${r.cves.length ? `<div class="panel tight"><div class="panel-head"><h2>CVE</h2></div><div class="tbl-wrap"><table>
    <thead><tr><th>CVE</th><th>Tytuł</th><th>Decyzja</th><th>Weryfikacja</th><th>Notatka</th></tr></thead><tbody>
    ${r.cves.map((c) => `<tr class="clickable" data-href="#/cve/${enc(c.id)}"><td class="nowrap">${cveLink(c.id)} ${kevBadge(c.kev)}</td><td>${esc(c.title)}</td>
      <td>${triageBadge(c.triage)}</td><td>${staleBadge(c.stale)}</td><td class="small">${esc((c.triage && c.triage.note) || '')}</td></tr>`).join('')}
    </tbody></table></div></div>` : ''}
  ${r.hosts.length ? `<div class="panel tight"><div class="panel-head"><h2>Hosty</h2></div><div class="tbl-wrap"><table><tbody>
    ${r.hosts.map((h) => `<tr class="clickable" data-href="#/host/${enc(h.id)}"><td>${hostLink(h.id, h.hostname)}</td><td class="mono small">${esc(h.ip)}</td>
      <td>${esc(h.type)} ${esc(h.os)}</td><td>${expBadge(h.exposure)}</td><td>${esc(h.owner)}</td></tr>`).join('')}
    </tbody></table></div></div>` : ''}
  ${r.kev.length ? `<div class="panel tight"><div class="panel-head"><h2>Katalog KEV — jeszcze nieprzeglądane</h2></div><div class="tbl-wrap"><table><tbody>
    ${r.kev.map((k) => `<tr class="clickable" data-href="#/cve/${enc(k.cve)}"><td class="nowrap">${cveLink(k.cve)}</td><td>${esc(k.vendor)} <b>${esc(k.product)}</b></td>
      <td>${esc(k.name)}</td><td class="small muted">${esc(k.dateAdded)}</td></tr>`).join('')}
    </tbody></table></div></div>` : ''}`;
}

/* =================================================================== KEV */
async function viewKev(el, _, q) {
  const view = q.view || 'pending';
  const term = q.q || '';
  await loadProducts();
  const r = await GET(`/api/kev?view=${enc(view)}&q=${enc(term)}&limit=${enc(q.limit || 60)}`);
  const tabs = [['pending', 'Do przeglądu'], ['affected', 'Dotyczy / używamy'], ['not_ours', 'Nie nasze'], ['stale', 'Nieaktualne'], ['all', 'Wszystkie']];
  el.innerHTML = `
  <div class="page-head"><div><h1>Przegląd KEV</h1>
    <div class="muted">Katalog CISA: ${r.catalog_size} wpisów · aktualizacja ${esc(fmtDT(r.updated_at))}${r.catalog_version ? ' · wersja ' + esc(r.catalog_version) : ''}</div></div>
    <div class="actions">
      <button class="btn primary w" data-act="fetch">Pobierz z CISA</button>
      <label class="btn w">Wgraj plik JSON<input type="file" accept=".json,application/json" class="hidden" id="kevfile"></label>
    </div></div>
  <div class="mb12 row">
    <div class="seg">${tabs.map(([k, l]) => `<button data-act="tab" data-v="${k}" class="${k === view ? 'on' : ''}">${l}</button>`).join('')}</div>
    <input type="search" id="kevq" placeholder="Filtruj: producent, produkt, CVE…" value="${esc(term)}">
    <span class="muted small">${r.total} pozycji${r.total > r.items.length ? `, pokazano ${r.items.length}` : ''}</span>
  </div>
  <div id="kevlist">${r.items.length ? r.items.map(kevCard).join('') : `<div class="panel empty">${r.catalog_size ? 'Brak pozycji w tym widoku' : 'Katalog pusty — pobierz go z CISA albo wgraj plik known_exploited_vulnerabilities.json'}</div>`}</div>
  ${r.total > r.items.length ? `<div class="row"><button class="btn" data-act="more">Pokaż więcej</button></div>` : ''}
  ${productDatalist()}`;

  const go = (patch) => { const nq = { view, q: term, ...patch }; location.hash = '#/kev?' + new URLSearchParams(nq).toString(); };
  $('#kevq', el).addEventListener('keydown', (e) => { if (e.key === 'Enter') go({ q: e.target.value }); });
  $('#kevfile', el).addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    const res = await guard(async () => POST('/api/kev/upload', { data: await fileToText(f) }));
    if (res) { toast(`Załadowano katalog: ${res.total} wpisów, nowych: ${res.added}`); render(); }
  });
  onAct(el, {
    tab: (b) => go({ view: b.dataset.v }),
    more: () => go({ limit: (+(q.limit || 60) + 100) }),
    fetch: async (b) => {
      b.disabled = true; b.textContent = 'Pobieranie…';
      const res = await guard(() => POST('/api/kev/fetch'));
      b.disabled = false; b.textContent = 'Pobierz z CISA';
      if (res) { toast(`Katalog zaktualizowany: ${res.total} wpisów, nowych: ${res.added}`); render(); }
    },
    dec: (b) => {
      const card = b.closest('.kev-card');
      $$('[data-act=dec]', card).forEach((x) => x.classList.toggle('on', x === b));
      card.dataset.decision = b.dataset.v;
    },
    addprod: (b) => {
      const card = b.closest('.kev-card');
      const inp = $('.addprod', card);
      const name = inp.value.trim(); if (!name) return;
      const p = productByName(name);
      if (!p) { toast('Nie ma takiej aplikacji w rejestrze — dodaj ją w zakładce Aplikacje albo wybierz z listy', true); return; }
      if ($(`input[value="${p.id}"]`, card)) { $(`input[value="${p.id}"]`, card).checked = true; inp.value = ''; return; }
      $('.cands', card).insertAdjacentHTML('beforeend', candChip({ product_id: p.id, name: p.name, hosts: p.hosts, status: p.status }, true));
      inp.value = '';
    },
    save: async (b) => {
      const card = b.closest('.kev-card');
      const dec = card.dataset.decision;
      if (!dec) { toast('Wybierz decyzję', true); return; }
      const pids = $$('.cands input:checked', card).map((i) => i.value);
      const note = $('textarea', card).value;
      const res = await guard(() => POST(`/api/kev/${enc(card.dataset.cve)}/triage`, { decision: dec, note, product_ids: pids }));
      if (!res) return;
      card.classList.add('done');
      $('.ft', card).innerHTML = `<div class="row">${triageBadge({ decision: dec })}<span class="muted small">zapisano ${esc(App.meta.today)}</span>
        ${['affected', 'used_safe', 'pending'].includes(dec) ? `<a class="btn sm primary" href="#/cve/${enc(card.dataset.cve)}">Uzupełnij wersje naprawione i sprawdź hosty →</a>` : ''}
        <button class="btn sm ghost w" data-act="reopen">zmień</button></div>`;
      loadProducts(true);
      refreshCounts();
    },
    reopen: () => render(),
  });
}

function candChip(c, checked) {
  const st = c.status === 'not_used' ? ' · <b>nie używamy</b>' : c.status === 'used' ? '' : ' · status nieznany';
  return `<label class="chip"><input type="checkbox" value="${esc(c.product_id)}"${checked ? ' checked' : ''}>
    ${esc(c.name)} <span class="faint">· ${c.hosts} ${c.hosts === 1 ? 'host' : 'hostów'}${st}</span></label>`;
}

function kevCard(k) {
  let suggested = k.triage && k.triage.decision;
  const inUse = k.candidates.filter((c) => c.hosts > 0);
  if (!suggested) {
    if (inUse.length) suggested = 'affected';
    else if (k.prior) suggested = k.prior.decision;
    else if (k.candidates.some((c) => c.status === 'not_used')) suggested = 'not_used';
  }
  const prior = k.prior ? `<div class="callout ${k.prior.stale.level === 'fresh' ? 'info' : ''}">
      Wcześniejsza decyzja dla <b>${esc(k.prior.label)}</b> (${cveLink(k.prior.last_cve)}): ${triageBadge({ decision: k.prior.decision })}
      ${staleBadge(k.prior.stale, 'weryfikacja ')}${byTxt(k.prior.verified_by)}${k.prior.note ? ` — <i>${esc(k.prior.note)}</i>` : ''}
      ${k.prior.stale.level !== 'fresh' ? '<br><b>Decyzja jest stara — stan mógł się zmienić, zweryfikuj ponownie.</b>' : ''}</div>` : '';
  const cands = k.candidates.length
    ? `<div class="my6 small muted">Pasujące aplikacje w rejestrze:</div>`
    : `<div class="my6 small muted">Nie znaleziono pasującej aplikacji w rejestrze — jeśli jej nie używamy, zapis „Nie używamy” doda ją do listy nieużywanych.</div>`;
  const decided = k.triage && k.triage.decision;
  return `<div class="kev-card${decided ? ' done' : ''}" data-cve="${esc(k.cve)}" data-decision="${esc(suggested || '')}">
    <div class="hd"><div>
        <div class="row">${cveLink(k.cve)} ${kevBadge(true, k.ransomware)} <span class="small muted">dodano ${esc(k.dateAdded)} · termin CISA ${esc(k.dueDate || '—')}</span></div>
        <div class="mt4"><span class="muted">${esc(k.vendor)}</span> <b>${esc(k.product)}</b> — ${esc(k.name)}</div>
      </div>
      <div>${decided ? triageBadge(k.triage) + ' ' + staleBadge(k.stale) + byTxt(k.triage.verified_by) : ''}</div></div>
    <div class="bd"><div class="desc">${esc(k.description)}</div>
      ${prior}
      ${cands}
      <div class="chips cands">${k.candidates.map((c) => candChip(c, c.hosts > 0 && c.score >= 0.8)).join('')}</div>
      <div class="mt8 row w"><input type="text" class="addprod" list="prodlist" placeholder="dodaj inną aplikację z rejestru…">
        <button class="btn sm w" data-act="addprod">Dodaj</button></div>
      ${k.triage && k.triage.note ? `<div class="mt6 small"><b>Notatka:</b> ${esc(k.triage.note)}</div>` : ''}
    </div>
    <div class="ft w">
      <div class="mb8 seg">${TRIAGE_OPTS.map(([v, l]) => `<button data-act="dec" data-v="${v}" class="${v === suggested ? 'on' : ''}">${l}</button>`).join('')}</div>
      <div class="row"><textarea rows="2" placeholder="Notatka: na jakiej podstawie (np. „sprawdzone w CMDB i SCCM — brak instalacji”)">${esc((k.triage && k.triage.note) || '')}</textarea></div>
      <div class="mt8 row end"><a class="btn sm ghost" href="#/cve/${enc(k.cve)}">Szczegóły CVE</a><button class="btn primary sm w" data-act="save">Zapisz decyzję (${esc(App.meta.today)})</button></div>
    </div></div>`;
}

/* =================================================================== LISTA CVE */
async function viewCves(el, _, q) {
  const r = await GET('/api/cves');
  el.innerHTML = `
  <div class="page-head"><div><h1>CVE</h1><div class="muted">Reguły wersji naprawionych i decyzje — ${r.cves.length} wpisów</div></div>
    <div class="actions"><input type="text" id="newcve" placeholder="CVE-2024-12345" class="mono"><button class="btn primary" data-act="open">Dodaj / otwórz</button></div></div>
  <div class="panel tight">
    <div class="pb12 panel-head">
      <div class="row"><input type="search" id="f-q" placeholder="Filtruj…" value="${esc(q.q || '')}">
        <select id="f-t">${options([['', 'Wszystkie decyzje'], ['none', 'Bez decyzji'], ...TRIAGE_OPTS], q.t || '')}</select>
        <label class="row small"><input type="checkbox" id="f-kev"${q.kev ? ' checked' : ''}> tylko KEV</label>
        <label class="row small"><input type="checkbox" id="f-open"${q.open ? ' checked' : ''}> z otwartymi hostami</label></div>
      <button class="btn sm" data-act="csv">CSV</button></div>
    <div class="tbl-wrap"><table><thead><tr><th>CVE</th><th>Tytuł</th><th>CVSS</th><th>Aplikacje (reguły)</th><th>Decyzja</th><th>Weryfikacja</th><th class="num">Otwarte</th></tr></thead>
    <tbody id="cvebody"></tbody></table></div></div>`;
  const body = $('#cvebody', el);
  let rows = [];
  const draw = () => {
    const fq = $('#f-q', el).value.toLowerCase(), ft = $('#f-t', el).value, fk = $('#f-kev', el).checked, fo = $('#f-open', el).checked;
    rows = r.cves.filter((c) => (!fq || (c.id + ' ' + c.title + ' ' + c.products.join(' ') + ' ' + ((c.triage && c.triage.note) || '')).toLowerCase().includes(fq))
      && (!ft || (ft === 'none' ? !(c.triage && c.triage.decision) : (c.triage && c.triage.decision) === ft)) && (!fk || c.kev) && (!fo || c.open));
    body.innerHTML = rows.length ? rows.map((c) => `<tr class="clickable" data-href="#/cve/${enc(c.id)}">
      <td class="nowrap">${cveLink(c.id)} ${kevBadge(c.kev)}</td><td>${esc(c.title)}</td><td class="num">${c.cvss ?? ''}</td>
      <td class="small">${esc(c.products.join(', ')) || '<span class="faint">brak reguł</span>'}</td><td>${triageBadge(c.triage)}</td><td>${staleBadge(c.stale)}</td>
      <td class="num">${c.open ? `<span class="b vulnerable">${c.open}</span>` : '0'}</td></tr>`).join('') : '<tr><td colspan="7" class="empty">Brak CVE</td></tr>';
  };
  draw();
  ['#f-q', '#f-t', '#f-kev', '#f-open'].forEach((s) => $(s, el).addEventListener('input', draw));
  const openNew = () => { const v = $('#newcve', el).value.trim().toUpperCase(); if (/^CVE-\d{4}-\d{4,}$/.test(v)) location.hash = '#/cve/' + v; else toast('Format: CVE-RRRR-NNNN', true); };
  $('#newcve', el).addEventListener('keydown', (e) => { if (e.key === 'Enter') openNew(); });
  onAct(el, {
    open: openNew,
    csv: () => downloadCSV('cve.csv', ['CVE', 'Tytuł', 'CVSS', 'KEV', 'Aplikacje', 'Decyzja', 'Notatka', 'Zweryfikowano', 'Otwarte'],
      rows.map((c) => [c.id, c.title, c.cvss, c.kev ? 'tak' : '', c.products.join(', '), (c.triage && c.triage.decision) || '', (c.triage && c.triage.note) || '', (c.triage && c.triage.verified_at) || '', c.open])),
  });
}

/* =================================================================== EDYTOR CVE */
async function viewCve(el, [cid]) {
  cid = cid.toUpperCase();
  await loadProducts(true);
  const r = await GET('/api/cves/' + enc(cid));
  const c = r.cve;
  const groups = App.meta.settings.groups;
  const st = {
    rules: (c.rules || []).map((x) => ({
      product_id: x.product_id, product: (r.product_names || {})[x.product_id] || '', unlisted: x.unlisted || 'review',
      branches: (x.branches || []).map((b) => ({ ...b })),
    })),
  };
  const k = r.kev;
  const t = c.triage || {};
  el.innerHTML = `
  <div class="page-head"><div><h1 class="mono">${esc(cid)} ${kevBadge(!!k, k && k.knownRansomwareCampaignUse === 'Known')}</h1>
      <div class="muted">${r.exists ? 'ostatnia zmiana ' + esc(fmtDT(c.updated_at)) : 'Nowy wpis — zapisz, aby utworzyć'}</div></div>
    <div class="actions"><button class="btn w" data-act="nvd">Podpowiedz z NVD</button>${r.exists ? '<button class="btn danger w" data-act="del">Usuń</button>' : ''}
      <button class="btn primary w" data-act="save">Zapisz CVE</button></div></div>
  ${k ? `<div class="callout bad"><b>CISA KEV</b> — ${esc(k.vendorProject)} ${esc(k.product)}: ${esc(k.vulnerabilityName)}. Dodano ${esc(k.dateAdded)}, termin ${esc(k.dueDate)}.
      <div class="mt4 small">${esc(k.requiredAction || '')}</div></div>` : ''}
  <div class="grid g2">
    <div class="panel"><h2>Decyzja: czy nas dotyczy?</h2>
      <div class="mb8 row">${triageBadge(t)} ${t.decision ? staleBadge(r.stale, 'weryfikacja ') + byTxt(t.verified_by) : ''}</div>
      ${t.note ? `<p class="small"><b>Uzasadnienie:</b> ${esc(t.note)}</p>` : ''}
      <div class="mb8 seg w" id="tri">${TRIAGE_OPTS.map(([v, l]) => `<button data-act="tri" data-v="${v}" class="${v === t.decision ? 'on' : ''}">${l}</button>`).join('')}</div>
      <textarea id="trinote" class="w" rows="3" placeholder="Uzasadnienie / źródło informacji">${esc(t.note || '')}</textarea>
      <div class="mt8 row end"><button class="btn primary sm w" data-act="trisave">Zapisz decyzję z datą ${esc(App.meta.today)}</button></div>
    </div>
    <div class="panel"><h2>Opis</h2>
      <div class="form" id="cveform">
        <label class="wide">Tytuł<input type="text" name="title" value="${esc(c.title || (k && k.vulnerabilityName) || '')}"></label>
        <label>CVSS<input type="text" name="cvss" value="${esc(c.cvss ?? '')}"></label>
        <label>Ważność<input type="text" name="severity" value="${esc(c.severity || '')}"></label>
        <label class="wide">Opis<textarea name="description" rows="3">${esc(c.description || (k && k.shortDescription) || '')}</textarea></label>
        <label class="wide">Notatki<textarea name="notes" rows="2">${esc(c.notes || '')}</textarea></label>
      </div>
      <h3>Grupy podatności (dla mitygacji na hostach)</h3>
      <div class="checks" id="groups">${groups.map((g) => `<label title="${esc(g.description)}"><input type="checkbox" value="${esc(g.id)}"${(c.groups || []).includes(g.id) ? ' checked' : ''}> ${esc(g.name)}</label>`).join('')}</div>
      <div class="mt8 checks"><label><input type="checkbox" id="noauto"${c.no_auto_exposure ? ' checked' : ''}> nie mityguj automatycznie hostów wewnętrznych (grupa „Wymaga ekspozycji do Internetu”)</label></div>
    </div>
  </div>
  <div id="nvdbox"></div>
  <div class="panel"><div class="panel-head"><h2>Reguły wersji — gdzie naprawione</h2><button class="btn sm w" data-act="addrule">+ Aplikacja</button></div>
    <p class="small muted">Dla każdej aplikacji podaj gałęzie wersji i wersję, od której błąd jest naprawiony. Wersje spoza opisanych gałęzi: starsze → wg ustawienia, nowsze → niepodatne.
      Szybkie wpisywanie: <code>12: 12.18, 14: 14.11, 16: 16.2, 11: brak, 10: niepodatne</code>. Dla pakietów dystrybucji wpisuj wersje dystrybucyjne (np. <code>2.4.37-62.el8_9</code>).</p>
    <div id="rules"></div>
  </div>
  <div class="panel tight"><div class="panel-head"><h2>Wpływ na hosty</h2><div class="row">${Object.entries(r.impact.counts).filter(([, n]) => n).map(([s, n]) => badge(s).replace('</span>', ` ${n}</span>`)).join(' ')}
      <button class="btn sm" data-act="impcsv">CSV</button></div></div>
    ${r.impact.rows.length ? `<div class="tbl-wrap"><table><thead><tr><th>Host</th><th>Aplikacja</th><th>Wersja</th><th>Status</th><th>Docelowa</th><th>Uzasadnienie</th><th>Właściciel</th></tr></thead><tbody>
    ${r.impact.rows.map((x) => `<tr class="clickable" data-href="#/host/${enc(x.host_id)}"><td>${hostLink(x.host_id, x.hostname)}</td><td>${esc(x.product)}</td><td class="mono">${esc(x.version)}</td>
      <td>${badge(x.status)}</td><td class="mono">${esc(x.target || '')}</td><td class="small">${esc(x.reason)}${x.overlay ? `<div class="faint">${x.overlay.type === 'exception' ? 'Wyjątek: ' : 'Mitygacja: '}${esc(x.overlay.text)}</div>` : ''}</td><td>${esc(x.owner)}</td></tr>`).join('')}
    </tbody></table></div>` : '<div class="empty">Brak dopasowanych instalacji. Dodaj regułę z aplikacją, która występuje w inwentarzu, i zapisz.</div>'}
  </div>
  <div id="hist"></div>
  ${productDatalist()}`;

  if (r.exists) historyPanel($('#hist', el), cid);
  const rulesEl = $('#rules', el);
  const drawRules = () => {
    rulesEl.innerHTML = st.rules.length ? st.rules.map((rule, ri) => `<div class="rule">
      <div class="mb8 row">
        <label class="field">Aplikacja<input type="text" list="prodlist" data-r="${ri}" data-f="product" value="${esc(rule.product)}" placeholder="np. PostgreSQL"></label>
        <label class="field">Gałęzie nieopisane (starsze)<select data-r="${ri}" data-f="unlisted">${options([['review', 'Do weryfikacji'], ['vulnerable', 'Traktuj jako podatne'], ['not_affected', 'Traktuj jako niepodatne']], rule.unlisted)}</select></label>
        <span class="small muted">${productByName(rule.product) ? `${productByName(rule.product).hosts} hostów w inwentarzu` : rule.product ? '<span class="b amber">nowa aplikacja — zostanie dodana do rejestru</span>' : ''}</span>
        <span class="grow"></span><button class="btn sm danger w" data-act="delrule" data-r="${ri}">Usuń aplikację</button></div>
      <table class="branch-tbl"><thead><tr><th>Gałąź</th><th>Stan</th><th>Naprawione w</th><th>Podatne od (opc.)</th><th>Notatka</th><th></th></tr></thead><tbody>
      ${rule.branches.map((b, bi) => `<tr>
        <td><input type="text" class="mono" data-r="${ri}" data-b="${bi}" data-f="branch" value="${esc(b.branch)}" placeholder="14 lub *"></td>
        <td><select data-r="${ri}" data-b="${bi}" data-f="state">${options([['fix', 'Jest poprawka'], ['nofix', 'Brak poprawki'], ['safe', 'Gałąź niepodatna']], b.state || 'fix')}</select></td>
        <td><input type="text" class="mono" data-r="${ri}" data-b="${bi}" data-f="fixed" value="${esc(b.fixed || '')}" ${b.state && b.state !== 'fix' ? 'disabled' : ''}></td>
        <td><input type="text" class="mono" data-r="${ri}" data-b="${bi}" data-f="introduced" value="${esc(b.introduced || '')}"></td>
        <td><input type="text" data-r="${ri}" data-b="${bi}" data-f="note" value="${esc(b.note || '')}"></td>
        <td><button class="btn sm ghost w" data-act="delbr" data-r="${ri}" data-b="${bi}">✕</button></td></tr>`).join('')}
      </tbody></table>
      <div class="mt8 row"><input type="text" class="mono" data-quick="${ri}" placeholder="szybko: 12: 12.18, 14: 14.11, 11: brak" size="44">
        <button class="btn sm w" data-act="quick" data-r="${ri}">Dodaj gałęzie</button><button class="btn sm ghost w" data-act="addbr" data-r="${ri}">+ wiersz</button></div>
    </div>`).join('') : '<div class="empty">Brak reguł. Dodaj aplikację, której dotyczy CVE.</div>';
  };
  drawRules();
  rulesEl.addEventListener('input', (e) => {
    const i = e.target; if (i.dataset.r === undefined || !i.dataset.f) return;
    const rule = st.rules[+i.dataset.r];
    if (i.dataset.b !== undefined) {
      rule.branches[+i.dataset.b][i.dataset.f] = i.value;
      if (i.dataset.f === 'state') drawRules();
    } else rule[i.dataset.f] = i.value;
  });
  rulesEl.addEventListener('change', (e) => { if (e.target.dataset.f === 'product') drawRules(); });

  const collect = () => {
    const f = formData($('#cveform', el));
    return {
      ...f, _version: c.updated_at, groups: $$('#groups input:checked', el).map((i) => i.value), no_auto_exposure: $('#noauto', el).checked,
      rules: st.rules.filter((x) => x.product.trim()).map((x) => {
        const p = productByName(x.product);
        return { ...(p ? { product_id: p.id } : { product: x.product.trim() }), unlisted: x.unlisted, branches: x.branches.filter((b) => b.branch || b.fixed) };
      }),
    };
  };
  onAct(el, {
    addrule: () => { st.rules.push({ product: '', product_id: null, unlisted: 'review', branches: [] }); drawRules(); },
    delrule: (b) => { st.rules.splice(+b.dataset.r, 1); drawRules(); },
    addbr: (b) => { st.rules[+b.dataset.r].branches.push({ branch: '', fixed: '', state: 'fix', introduced: '', note: '' }); drawRules(); },
    delbr: (b) => { st.rules[+b.dataset.r].branches.splice(+b.dataset.b, 1); drawRules(); },
    quick: (b) => {
      const inp = $(`[data-quick="${b.dataset.r}"]`, el);
      const add = parseQuickBranches(inp.value);
      const rule = st.rules[+b.dataset.r];
      for (const nb of add) {
        const ex = rule.branches.find((x) => x.branch === nb.branch);
        if (ex) Object.assign(ex, nb); else rule.branches.push(nb);
      }
      drawRules();
    },
    tri: (b) => { $$('#tri button', el).forEach((x) => x.classList.toggle('on', x === b)); },
    trisave: async () => {
      const on = $('#tri button.on', el);
      if (!on) { toast('Wybierz decyzję', true); return; }
      const ok = await guard(() => POST(`/api/cves/${enc(cid)}/triage`, { decision: on.dataset.v, note: $('#trinote', el).value }), 'Decyzja zapisana');
      if (ok) { refreshCounts(); render(); }
    },
    save: async () => {
      const ok = await guard(() => PUT('/api/cves/' + enc(cid), collect()), 'CVE zapisane — przeliczono wpływ na hosty');
      if (ok) render();
    },
    del: async () => {
      if (!confirm(`Usunąć ${cid} wraz z regułami i decyzją?`)) return;
      if (await guard(() => DEL('/api/cves/' + enc(cid)), 'Usunięto')) location.hash = '#/cves';
    },
    impcsv: () => downloadCSV(`${cid}-hosty.csv`, ['Host', 'Właściciel', 'Aplikacja', 'Wersja', 'Status', 'Wersja docelowa', 'Uzasadnienie'],
      r.impact.rows.map((x) => [x.hostname, x.owner, x.product, x.version, STATUS[x.status], x.target || '', x.reason])),
    nvd: async (b) => {
      b.disabled = true; b.textContent = 'Pobieranie z NVD…';
      const n = await guard(() => GET(`/api/cves/${enc(cid)}/nvd`));
      b.disabled = false; b.textContent = 'Podpowiedz z NVD';
      if (!n) return;
      const box = $('#nvdbox', el);
      box.innerHTML = `<div class="panel"><div class="panel-head"><h2>Podpowiedzi z NVD</h2><button class="btn sm ghost" data-act="nvdclose">Zamknij</button></div>
        <p class="small">CVSS ${esc(n.cvss ?? '—')} ${esc(n.severity || '')} <span class="mono faint">${esc(n.vector || '')}</span> · opublikowano ${esc(fmtDate(n.published))}</p>
        <p class="desc">${esc(n.description)}</p>
        <div class="my8 row"><button class="btn sm w" data-act="nvdmeta">Uzupełnij opis, CVSS i grupy</button></div>
        ${n.products.length ? n.products.map((p, pi) => `<div class="rule"><div class="row"><b>${esc(p.vendor)} / ${esc(p.product)}</b>
            <span class="small muted">${p.branches.map((x) => `${esc(x.branch)} → ${esc(x.fixed || 'brak poprawki')}`).join(', ') || 'brak zakresów wersji'}
            ${p.exact_versions.length ? ` · konkretne wersje: ${esc(p.exact_versions.slice(0, 8).join(', '))}` : ''}</span></div>
          <div class="mt6 row">jako aplikacja: <input type="text" list="prodlist" data-nvdp="${pi}" value="${esc(p.candidates[0] ? p.candidates[0].name : p.product)}">
            <button class="btn sm primary w" data-act="nvduse" data-p="${pi}"${p.branches.length ? '' : ' disabled'}>Dodaj jako regułę</button></div></div>`).join('')
          : '<div class="muted">NVD nie podaje konfiguracji (CPE) — wpisz wersje ręcznie.</div>'}</div>`;
      box._nvd = n;
    },
    nvdclose: () => { $('#nvdbox', el).innerHTML = ''; },
    nvdmeta: () => {
      const n = $('#nvdbox', el)._nvd; const f = $('#cveform', el);
      if (!$('[name=description]', f).value) $('[name=description]', f).value = n.description;
      if (!$('[name=title]', f).value) $('[name=title]', f).value = n.description.slice(0, 120);
      if (n.cvss != null) $('[name=cvss]', f).value = n.cvss;
      if (n.severity) $('[name=severity]', f).value = n.severity;
      n.groups.forEach((g) => { const i = $(`#groups input[value="${g}"]`, el); if (i) i.checked = true; });
      toast('Uzupełniono — pamiętaj o zapisaniu');
    },
    nvduse: (b) => {
      const n = $('#nvdbox', el)._nvd; const p = n.products[+b.dataset.p];
      const name = $(`[data-nvdp="${b.dataset.p}"]`, el).value.trim();
      let rule = st.rules.find((x) => x.product.toLowerCase() === name.toLowerCase());
      if (!rule) { rule = { product: name, unlisted: 'review', branches: [] }; st.rules.push(rule); }
      for (const nb of p.branches) {
        const ex = rule.branches.find((x) => x.branch === nb.branch);
        if (ex) Object.assign(ex, nb); else rule.branches.push({ ...nb });
      }
      drawRules();
      toast('Dodano gałęzie — sprawdź i zapisz CVE');
    },
  });
}
