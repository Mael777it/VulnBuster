/* SPDX-License-Identifier: MIT · Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com> */
/* Widoki: import z Excela, porównanie importów, raporty do druku */
'use strict';

/* =================================================================== IMPORT */
async function viewImport(el) {
  const fields = App.meta.fields;
  const S = { token: null, analysis: null, mapping: [], split: false, preview: null, file: null };
  el.innerHTML = `
  <div class="page-head"><div><h1>Import z Excela</h1><div class="muted">Wklej skopiowane komórki (z nagłówkami) albo wybierz plik .xlsx / .csv — kolumny rozpoznam automatycznie</div></div>
    <div class="actions"><a class="btn" href="#/imports">Historia importów</a></div></div>
  <div class="panel" id="step1">
    <h2>1. Dane</h2>
    <textarea class="paste" id="paste" placeholder="Zaznacz w Excelu zakres z nagłówkami → Ctrl+C → tutaj Ctrl+V
Przykład kolumn: Host | IP | System | Typ | Ekspozycja | Aplikacja | Wersja | Właściciel | Administrator
lub reguły CVE:  CVE | Aplikacja | Wersja naprawiona"></textarea>
    <div class="row mt8">
      <label class="btn">Wybierz plik<input type="file" id="file" accept=".xlsx,.xlsm,.csv,.txt,.tsv" class="hidden"></label>
      <span id="fname" class="small muted"></span><select id="sheet" class="hidden"></select>
      <span class="grow"></span>
      <label class="row small" title="Aktualizuj właściciela, IP, ekspozycję itd. istniejących hostów danymi z importu"><input type="checkbox" id="o-upd" checked> aktualizuj dane hostów</label>
      <label class="row small" title="Aplikacje hostów z importu, których nie ma w tym imporcie, zostaną oznaczone jako odinstalowane"><input type="checkbox" id="o-scope"> import zawiera pełną listę aplikacji tych hostów</label>
      <button class="btn primary w" data-act="analyze">Analizuj</button>
    </div>
  </div>
  <div id="step2"></div>`;

  const opts = () => ({ update_hosts: $('#o-upd', el).checked, replace_scope: $('#o-scope', el).checked });
  $('#file', el).addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    S.file = f; $('#fname', el).textContent = f.name;
    analyze();
  });
  $('#sheet', el).addEventListener('change', () => analyze());
  $('#step2', el).addEventListener('change', (e) => {
    if (e.target.dataset.col !== undefined) { S.mapping[+e.target.dataset.col] = e.target.value; repreview(); }
    if (e.target.id === 'split') { S.split = e.target.checked; repreview(); }
  });

  async function analyze() {
    const body = { options: opts() };
    if (S.file) {
      if (/\.xls[xm]$/i.test(S.file.name)) { body.xlsx_b64 = await fileToBase64(S.file); if (!$('#sheet', el).classList.contains('hidden')) body.sheet = $('#sheet', el).value; } else body.text = await fileToText(S.file);
    } else body.text = $('#paste', el).value;
    const btn = $('[data-act=analyze]', el); btn.disabled = true; btn.textContent = 'Analiza…';
    const a = await guard(() => POST('/api/import/analyze', body));
    btn.disabled = false; btn.textContent = 'Analizuj';
    if (!a) return;
    if (a.sheets && a.sheets.length > 1) {
      const sel = $('#sheet', el);
      if (sel.classList.contains('hidden')) { sel.innerHTML = options(a.sheets.map((s) => [s, s]), a.sheets[0]); sel.classList.remove('hidden'); }
    }
    S.token = a.token; S.analysis = a; S.mapping = a.columns.map((c) => c.field); S.split = a.split_product_version; S.preview = a.preview;
    drawStep2();
  }

  async function repreview() {
    const p = await guard(() => POST('/api/import/preview', { token: S.token, mapping: S.mapping, split: S.split, options: opts() }));
    if (p) { S.preview = p; drawPreview(); }
  }

  function drawStep2() {
    const a = S.analysis;
    $('#step2', el).innerHTML = `
    <div class="panel"><div class="panel-head"><h2>2. Mapowanie kolumn</h2>
        <span class="small muted">${a.rows} wierszy · ${a.has_header ? 'wykryto nagłówki' : 'bez nagłówków'}${a.profile_used ? ' · <span class="b green">użyto zapamiętanego mapowania</span>' : ''}</span></div>
      ${(a.warnings || []).map((w) => `<div class="callout">${esc(w)}</div>`).join('')}
      <div class="tbl-wrap"><table class="map-tbl"><thead><tr><th>Kolumna</th><th>Przykładowe wartości</th><th>Pole w aplikacji</th><th>Pewność</th></tr></thead><tbody>
      ${a.columns.map((c, i) => `<tr><td><b>${esc(c.header)}</b><div class="small faint">${c.filled} wypełnionych</div></td>
        <td><div class="sample">${esc(c.samples.join(' · '))}</div></td>
        <td><select data-col="${i}">${options(fields.map((f) => [f.id, f.label]), S.mapping[i])}</select></td>
        <td class="conf">${c.field === 'ignore' ? '' : `<span class="b ${c.confidence >= 0.75 ? 'green' : c.confidence >= 0.5 ? 'amber' : 'red'}">${Math.round(c.confidence * 100)}% · ${esc(c.source)}</span>`}</td></tr>`).join('')}
      </tbody></table></div>
      <div class="row mt8"><label class="row small"><input type="checkbox" id="split"${S.split ? ' checked' : ''}> rozdziel „Aplikacja 1.2.3” na nazwę i wersję</label></div>
    </div>
    <div id="prev"></div>`;
    drawPreview();
  }

  function drawPreview() {
    const p = S.preview, s = p.stats;
    const bs = s.by_status || {};
    const filters = [['all', 'Wszystkie'], ['action', 'Wymagają działań'], ['vulnerable', 'Podatne'], ['review', 'Do weryfikacji'], ['ok', 'OK']];
    $('#prev', el).innerHTML = `
    <div class="panel"><h2>3. Podgląd i ocena — nic jeszcze nie zapisano</h2>
      <div class="tiles">
        <div class="tile"><div class="v">${s.installations}</div><div class="l">instalacji (host × aplikacja)</div></div>
        <div class="tile red"><div class="v">${bs.vulnerable || 0}</div><div class="l">podatnych</div></div>
        <div class="tile amber"><div class="v">${bs.review || 0}</div><div class="l">do weryfikacji</div></div>
        <div class="tile green"><div class="v">${(bs.fixed || 0) + (bs.not_affected || 0)}</div><div class="l">załatane / niepodatne</div></div>
        <div class="tile"><div class="v">${(bs.mitigated || 0) + (bs.exception || 0)}</div><div class="l">mitygacja / wyjątek</div></div>
        <div class="tile"><div class="v">${s.new_hosts}</div><div class="l">nowych hostów</div></div>
        <div class="tile ${s.new_products ? 'amber' : ''}"><div class="v">${s.new_products}</div><div class="l">nowych aplikacji</div></div>
        <div class="tile"><div class="v">${s.rules_added}</div><div class="l">nowych reguł CVE</div></div>
      </div>
      ${p.new_products.length ? `<div class="callout">Nowe aplikacje (nie ma ich w rejestrze): <b>${esc(p.new_products.join(', '))}</b>.
        Jeśli to inna nazwa istniejącej aplikacji — dodaj alias w jej karcie albo scal po imporcie.</div>` : ''}
      ${p.rules_added.length ? `<details><summary class="small">Reguły CVE z importu (${p.rules_added.length})</summary><div class="small mono">${p.rules_added.map(esc).join('<br>')}</div></details>` : ''}
      ${p.conflicts.length ? `<div class="callout bad"><b>Konflikty reguł:</b><br>${p.conflicts.map(esc).join('<br>')}</div>` : ''}
      ${p.warnings.length ? `<div class="callout">${p.warnings.map(esc).join('<br>')}</div>` : ''}
      ${s.skipped ? `<div class="callout">Pominięto ${s.skipped} wierszy bez hosta i aplikacji (wiersze: ${esc(p.skipped_rows.join(', '))}).</div>` : ''}
      ${s.removed ? `<div class="callout info">${s.removed} aplikacji zostanie oznaczonych jako odinstalowane.</div>` : ''}
      <div class="row mb8 mt8"><div class="seg" id="pf">${filters.map(([k, l], i) => `<button data-v="${k}" class="${i === 0 ? 'on' : ''}">${l}</button>`).join('')}</div>
        <span class="small muted">${p.rows_total > p.rows.length ? `pokazano ${p.rows.length} z ${p.rows_total}` : ''}</span></div>
      <div class="tbl-wrap" id="prows"></div>
      <div class="row end mt8">
        <input type="text" id="impname" placeholder="Nazwa importu, np. „Inwentarz PostgreSQL — po oknie 10.2026”" size="48">
        <label class="row small"><input type="checkbox" id="saveprof" checked> zapamiętaj mapowanie</label>
        <button class="btn primary w" data-act="commit">Zapisz import</button></div>
    </div>`;
    const drawRows = (flt) => {
      const okS = ['fixed', 'not_affected', 'none', 'mitigated', 'exception', 'host', 'rule'];
      const rows = p.rows.filter((r) => flt === 'all' || (flt === 'action' ? ['vulnerable', 'review'].includes(r.status) : flt === 'ok' ? okS.includes(r.status) : r.status === flt));
      $('#prows', el).innerHTML = `<table><thead><tr><th>Wiersz</th><th>Host</th><th>Aplikacja</th><th>Wersja</th><th>CVE</th><th>Status</th><th>Docelowa</th><th>Uzasadnienie</th></tr></thead><tbody>
        ${rows.slice(0, 500).map((r) => `<tr><td class="faint">${r.row}</td><td>${esc(r.hostname)}</td><td>${esc(r.product)}</td><td class="mono">${esc(r.version)}</td>
          <td class="mono small">${esc(r.cve)}</td><td>${badge(r.status)}</td><td class="mono">${esc(r.target || '')}</td><td class="small">${esc(r.reason)}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">—</td></tr>'}
      </tbody></table>`;
    };
    drawRows('all');
    $('#pf', el).addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      $$('#pf button', el).forEach((x) => x.classList.toggle('on', x === b)); drawRows(b.dataset.v);
    });
  }

  onAct(el, {
    analyze: () => { if ($('#paste', el).value.trim()) S.file = null; analyze(); },
    commit: async (b) => {
      b.disabled = true;
      const res = await guard(() => POST('/api/import/commit', {
        token: S.token, mapping: S.mapping, split: S.split, options: opts(), name: $('#impname', el).value, save_profile: $('#saveprof', el).checked,
      }));
      b.disabled = false;
      if (!res) return;
      App.products = null;
      refreshCounts();
      const imps = (await GET('/api/imports')).imports;
      const prev = imps.length > 1 ? imps[1] : null;
      el.innerHTML = `<div class="panel"><h1>Import zapisany</h1>
        <p>${res.stats.records} wierszy · ${res.stats.installations} instalacji · ${res.stats.new_hosts} nowych hostów · ${res.stats.new_products} nowych aplikacji · ${res.stats.rules_added} reguł CVE.</p>
        <div class="row mt8"><a class="btn primary" href="#/hosts?f=open">Hosty wymagające działań</a>
        ${prev ? `<a class="btn" href="#/compare?a=${enc(prev.id)}&b=${enc(res.import_id)}">Porównaj z poprzednim importem („${esc(prev.name)}”)</a>` : ''}
        <a class="btn" href="#/import" data-act="again">Kolejny import</a></div></div>`;
      onAct(el, { again: () => render() });
    },
  });
}

/* =================================================================== HISTORIA I PORÓWNANIE */
async function viewImports(el) {
  const r = await GET('/api/imports');
  el.innerHTML = `
  <div class="page-head"><div><h1>Historia importów</h1></div><div class="actions"><a class="btn" href="#/compare">Porównaj</a><a class="btn primary" href="#/import">Nowy import</a></div></div>
  <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th>Nazwa</th><th>Data</th><th>Kto</th><th class="num">Wiersze</th><th class="num">Instalacje</th><th class="num">Nowe hosty</th><th class="num">Nowe aplikacje</th><th></th></tr></thead><tbody>
  ${r.imports.map((i, n) => `<tr><td><input type="text" value="${esc(i.name)}" data-id="${esc(i.id)}" size="40"></td><td class="small">${esc(fmtDT(i.created_at))}</td><td class="small">${esc(i.created_by || '')}</td>
    <td class="num">${i.rows}</td><td class="num">${i.installations}</td><td class="num">${i.new_hosts}</td><td class="num">${i.new_products}</td>
    <td class="nowrap"><button class="btn sm w" data-act="ren" data-id="${esc(i.id)}">Zmień nazwę</button>
      ${r.imports[n + 1] ? `<a class="btn sm" href="#/compare?a=${enc(r.imports[n + 1].id)}&b=${enc(i.id)}">vs poprzedni</a>` : ''}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">Brak importów</td></tr>'}
  </tbody></table></div></div>`;
  onAct(el, {
    ren: async (b) => { const v = $(`input[data-id="${b.dataset.id}"]`, el).value; await guard(() => PUT('/api/imports/' + enc(b.dataset.id), { name: v }), 'Zapisano'); },
  });
}

async function viewCompare(el, _, q) {
  const imps = (await GET('/api/imports')).imports;
  if (imps.length < 2) { el.innerHTML = '<div class="panel empty">Do porównania potrzebne są co najmniej dwa importy. Zaimportuj stan przed i po oknie serwisowym.</div>'; return; }
  const a = q.a || imps[1].id, b = q.b || imps[0].id;
  const opt = imps.map((i) => [i.id, `${i.name} (${fmtDT(i.created_at)})`]);
  el.innerHTML = `
  <div class="page-head"><div><h1>Porównanie importów</h1><div class="muted">Gdzie patchowanie zostało wykonane, a gdzie nie (oceniane według aktualnych reguł CVE)</div></div></div>
  <div class="panel"><div class="row"><label class="field">Przed<select id="ca">${options(opt, a)}</select></label><label class="field">Po<select id="cb">${options(opt, b)}</select></label>
    <button class="btn primary" data-act="cmp">Porównaj</button></div></div>
  <div id="cres"><div class="spinner">Liczenie…</div></div>`;
  onAct(el, { cmp: () => { location.hash = `#/compare?a=${enc($('#ca', el).value)}&b=${enc($('#cb', el).value)}`; } });
  if (a === b) { $('#cres', el).innerHTML = '<div class="callout">Wybierz dwa różne importy</div>'; return; }
  const r = await GET(`/api/imports/compare?a=${enc(a)}&b=${enc(b)}`);
  const C = {
    patched: ['Załatane', 'green'], still: ['Nadal podatne', 'red'], worse: ['Nowe podatności (pogorszenie)', 'red'], new_vuln: ['Nowe wpisy podatne', 'amber'],
    missing: ['Brak w nowym imporcie', 'gray'], new_ok: ['Nowe wpisy OK', 'gray'], ok: ['Bez zmian, OK', 'gray'],
  };
  const total = r.rows.length;
  const done = (r.counts.patched || 0);
  const needed = done + (r.counts.still || 0) + (r.counts.worse || 0);
  $('#cres', el).innerHTML = `
  <div class="tiles">${Object.entries(C).map(([k, [l, cls]]) => `<a class="tile ${cls}" href="#" data-act="flt" data-v="${k}"><div class="v">${r.counts[k] || 0}</div><div class="l">${l}</div></a>`).join('')}</div>
  <div class="panel"><h2>Skuteczność patchowania</h2>${progressBar(done, needed)}<p class="small muted mt8">Spośród instalacji podatnych w „przed” (${needed}) — załatane: ${done}. Łącznie porównano ${total} instalacji.</p></div>
  <div class="panel tight"><div class="panel-head"><h2 id="ctitle">Wszystkie</h2><div class="row"><button class="btn sm" data-act="flt" data-v="">pokaż wszystkie</button><button class="btn sm" data-act="ccsv">CSV</button></div></div>
    <div class="tbl-wrap" id="crows"></div></div>`;
  applyWidths(el);
  let cur = '';
  const draw = () => {
    const rows = r.rows.filter((x) => !cur || x.category === cur);
    $('#ctitle', el).textContent = cur ? C[cur][0] : 'Wszystkie';
    $('#crows', el).innerHTML = `<table><thead><tr><th>Host</th><th>Aplikacja</th><th>Przed</th><th>Po</th><th>Wynik</th><th>Załatane CVE</th><th>Nadal otwarte</th><th>Docelowa</th><th>Właściciel</th></tr></thead><tbody>
      ${rows.map((x) => `<tr><td>${hostLink(x.host_id, x.hostname)}</td><td>${esc(x.product)}</td><td class="mono">${esc(x.va ?? '—')}</td><td class="mono">${esc(x.vb ?? '—')}</td>
        <td><span class="b ${C[x.category][1]}">${C[x.category][0]}</span></td><td class="mono small">${esc(x.fixed_cves.join(' '))}</td>
        <td class="mono small">${esc(x.open_b.join(' '))}</td><td class="mono">${esc(x.target || '')}</td><td>${esc(x.owner)}</td></tr>`).join('') || '<tr><td colspan="9" class="empty">—</td></tr>'}</tbody></table>`;
  };
  draw();
  onAct($('#cres', el), {
    flt: (t) => { cur = t.dataset.v; draw(); },
    ccsv: () => downloadCSV(`porownanie-${r.a.name}-vs-${r.b.name}.csv`, ['Host', 'Właściciel', 'Aplikacja', 'Wersja przed', 'Wersja po', 'Wynik', 'Załatane CVE', 'Nadal otwarte', 'Docelowa'],
      r.rows.map((x) => [x.hostname, x.owner, x.product, x.va, x.vb, C[x.category][0], x.fixed_cves.join(' '), x.open_b.join(' '), x.target || ''])),
  });
}

/* =================================================================== RAPORTY */
function reportShell(inner) {
  return `<div class="report-toolbar"><button class="btn" data-act="back">← Wróć</button><button class="btn primary" data-act="print">Drukuj / zapisz PDF</button></div><div class="report">${inner}</div>`;
}
function reportActs(el) { onAct(el, { print: () => window.print(), back: () => history.back() }); }

async function viewHostReport(el, [hid]) {
  const r = await GET(`/api/hosts/${enc(hid)}/report`);
  const h = r.host;
  const ACT = ['vulnerable', 'review'];
  const todo = r.installations.filter((i) => i.findings.some((f) => ACT.includes(f.status)));
  const covered = r.installations.flatMap((i) => i.findings.filter((f) => ['exception', 'mitigated'].includes(f.status)).map((f) => ({ ...f, product: i.product, version: i.version })));
  const okApps = r.installations.filter((i) => !todo.includes(i));
  const gname = (id) => (App.meta.settings.groups.find((g) => g.id === id) || { name: id }).name;
  el.innerHTML = reportShell(`
    <div class="row"><div class="grow"><h1>Plan na okno serwisowe — ${esc(h.hostname)}</h1><div class="muted">Wygenerowano ${esc(App.meta.today)}</div></div>
      <div>${r.summary.open ? `<span class="b vulnerable">${r.summary.open} podatności do usunięcia</span>` : '<span class="b fixed">Brak działań</span>'}</div></div>
    <h2>Host</h2>
    <dl class="kv"><dt>Nazwa</dt><dd>${esc(h.hostname)}</dd><dt>Adres IP</dt><dd class="mono">${esc(h.ip || '—')}</dd>
      <dt>Typ / system</dt><dd>${esc(h.type || '—')} / ${esc(h.os || '—')}</dd><dt>Ekspozycja</dt><dd>${expBadge(h.exposure)}</dd>
      <dt>Środowisko</dt><dd>${esc(h.environment || '—')}</dd><dt>Krytyczność</dt><dd>${esc(h.criticality || '—')}</dd>
      <dt>Właściciel</dt><dd>${esc(h.owner || '—')}</dd><dt>Administrator</dt><dd>${esc(h.admin || '—')}</dd>
      ${h.notes ? `<dt>Uwagi</dt><dd>${esc(h.notes)}</dd>` : ''}</dl>
    <h2>Do wykonania (${todo.length})</h2>
    ${todo.length ? `<table><thead><tr><th>Aplikacja</th><th>Obecna wersja</th><th>Aktualizuj do (min.)</th><th>Podatności</th><th>Termin KEV</th><th>Wykonano</th></tr></thead><tbody>
      ${todo.map((i) => { const fs = i.findings.filter((f) => ACT.includes(f.status)); const due = fs.map((f) => f.kev_due).filter(Boolean).sort()[0];
        return `<tr><td><b>${esc(i.product)}</b></td><td class="mono">${esc(i.version)}</td>
        <td class="mono"><b>${esc(i.summary.target || '')}</b>${i.summary.nofix ? '<div class="small">brak poprawki w gałęzi — wymagana migracja</div>' : ''}</td>
        <td class="small">${fs.map((f) => `${f.kev ? '<span class="b kev">KEV</span> ' : ''}<span class="mono">${esc(f.cve)}</span>${f.status === 'review' ? ' <span class="b review">weryfikacja</span>' : ''}<br><span class="muted">${esc(f.reason)}</span>`).join('<br>')}</td>
        <td class="nowrap">${esc(due || '—')}</td><td>☐</td></tr>`; }).join('')}</tbody></table>` : '<p>Brak aplikacji wymagających aktualizacji.</p>'}
    ${covered.length ? `<h2>Objęte wyjątkiem lub mitygacją (bez działań w tym oknie)</h2><table><thead><tr><th>Aplikacja</th><th>Wersja</th><th>CVE</th><th>Status</th><th>Uzasadnienie</th></tr></thead><tbody>
      ${covered.map((f) => `<tr><td>${esc(f.product)}</td><td class="mono">${esc(f.version)}</td><td class="mono">${esc(f.cve)}</td><td>${badge(f.status)}</td>
        <td class="small">${esc(f.overlay.text)}${f.overlay.group ? ' (' + esc(gname(f.overlay.group)) + ')' : ''}${f.overlay.review_at ? ` — przegląd ${esc(f.overlay.review_at)}` : ''}</td></tr>`).join('')}</tbody></table>` : ''}
    <h2>Pozostałe aplikacje — bez działań (${okApps.length})</h2>
    <p class="small">${okApps.map((i) => `${esc(i.product)} <span class="mono">${esc(i.version)}</span>`).join(' · ') || '—'}</p>
    <div class="sign"><div>Wykonał (administrator), data</div><div>Zweryfikował (bezpieczeństwo), data</div></div>`);
  reportActs(el);
}

async function viewProductReport(el, [pid]) {
  const r = await GET(`/api/products/${enc(pid)}/report`);
  const p = r.product;
  const ACT = ['vulnerable', 'review'];
  const open = r.installations.filter((i) => ACT.includes(i.summary.status));
  const rest = r.installations.filter((i) => !ACT.includes(i.summary.status));
  el.innerHTML = reportShell(`
    <h1>Raport patchowania — ${esc(p.name)}</h1><div class="muted">${esc(p.vendor || '')} · wygenerowano ${esc(App.meta.today)}</div>
    <h2>Podsumowanie</h2>
    ${progressBar(r.progress.ok, r.progress.total)}
    <table class="mt8"><thead><tr><th>Gałąź</th><th class="num">Hosty</th><th class="num">Do akcji</th><th>Wersje w użyciu</th><th>Wersja docelowa</th></tr></thead><tbody>
      ${r.branches.map((b) => `<tr><td class="mono">${esc(b.branch)}</td><td class="num">${b.hosts}</td><td class="num">${b.open}</td><td class="mono small">${esc(b.versions.join(', '))}</td><td class="mono">${esc(b.target || '—')}</td></tr>`).join('')}</tbody></table>
    <h2>Wymaga działań (${open.length})</h2>
    ${open.length ? `<table><thead><tr><th>Host</th><th>Właściciel / admin</th><th>Ekspozycja</th><th>Wersja</th><th>Docelowa</th><th>CVE</th></tr></thead><tbody>
      ${open.map((i) => `<tr><td><b>${esc(i.hostname)}</b><div class="small muted">${esc(i.ip || '')} ${esc(i.environment || '')}</div></td><td class="small">${esc(i.owner)}<br>${esc(i.admin)}</td>
        <td>${expBadge(i.exposure)}</td><td class="mono">${esc(i.version)}</td><td class="mono"><b>${esc(i.summary.target || (i.summary.nofix ? 'migracja' : ''))}</b></td>
        <td class="small mono">${i.findings.filter((f) => ACT.includes(f.status)).map((f) => (f.kev ? 'KEV ' : '') + esc(f.cve)).join('<br>')}</td></tr>`).join('')}</tbody></table>` : '<p>Brak.</p>'}
    <h2>Pozostałe (${rest.length})</h2>
    ${rest.length ? `<table><thead><tr><th>Host</th><th>Wersja</th><th>Status</th><th>Uwagi</th></tr></thead><tbody>
      ${rest.map((i) => `<tr><td>${esc(i.hostname)}</td><td class="mono">${esc(i.version)}</td><td>${badge(i.summary.status)}</td>
        <td class="small">${esc(i.findings.filter((f) => f.overlay).map((f) => `${f.cve}: ${f.overlay.text}`).join('; '))}</td></tr>`).join('')}</tbody></table>` : '<p>—</p>'}
    ${r.trend.length > 1 ? `<h2>Historia</h2><table><tbody>${r.trend.map((t) => `<tr><td>${esc(t.name)}</td><td>${esc(fmtDate(t.date))}</td><td class="num">${t.hosts} hostów</td><td class="num">${t.open} do akcji</td></tr>`).join('')}</tbody></table>` : ''}
    ${p.notes ? `<h2>Notatki</h2><p>${esc(p.notes)}</p>` : ''}`);
  reportActs(el);
}
