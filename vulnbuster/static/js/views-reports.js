/* SPDX-License-Identifier: MIT · Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com> */
/* Widoki: raporty grupowane (spółka / zespół / typ…) i zgłoszenia do realizatorów */
'use strict';

/* =================================================================== RAPORTY GRUPOWANE */
async function viewReports(el, _, q) {
  await loadProducts();
  const prods = [...App.products].filter((p) => p.hosts).sort((a, b) => a.name.localeCompare(b.name, 'pl'));
  el.innerHTML = `
  <div class="page-head no-print"><div><h1>Raporty</h1><div class="muted">Podatności per spółka, zespół realizujący, typ sprzętu… — dla wszystkich aplikacji, jednej aplikacji albo jednego CVE</div></div></div>
  <div class="panel no-print" id="rf"><div class="form">
    <label>Grupuj wg<select name="group">${options(GROUP_OPTS, q.group || 'company')}</select></label>
    <label>Aplikacja<select name="product_id">${options(prods.map((p) => [p.id, `${p.name} (${p.hosts})`]), q.product || '', '— wszystkie aplikacje —')}</select></label>
    <label>CVE<input type="text" name="cve_id" class="mono" value="${esc(q.cve || '')}" placeholder="CVE-2024-…"></label>
    <label>Spółka<select name="f_company">${options((App.meta.companies || []).map((c) => [c, c]), q.company || '', '— wszystkie —')}</select></label>
    <label>Zespół<select name="f_team">${options(teamOpts('— wszystkie —'), q.team || '')}</select></label>
    <label>Typ urządzenia<input type="text" name="f_type" value="${esc(q.type || '')}" placeholder="dokładna wartość, np. Windows"></label>
  </div>
  <div class="checks mt8"><label><input type="checkbox" name="kev_only"${q.kev ? ' checked' : ''}> tylko podatności z CISA KEV</label>
    <label><input type="checkbox" name="all_rows"${q.all ? ' checked' : ''}> w szczegółach pokaż też instalacje bez działań</label></div>
  <div class="row end mt8">
    <button class="btn" data-act="tickets">Zgłoszenia do realizatorów</button>
    <button class="btn" data-act="csv">CSV</button><button class="btn" data-act="xlsx">Excel (arkusz na grupę)</button>
    <button class="btn" data-act="print">Drukuj / PDF</button><button class="btn primary" data-act="run">Pokaż raport</button></div></div>
  <div id="rres"></div>`;
  let last = null;
  const params = () => {
    const f = formData($('#rf', el));
    return {
      group: f.group, product_id: f.product_id || null, cve_id: f.cve_id.trim().toUpperCase() || null, kev_only: f.kev_only,
      only_open: !f.all_rows, filters: { company: f.f_company, team: f.f_team, type: f.f_type.trim() },
    };
  };
  const run = async () => {
    const prm = params();
    const box = $('#rres', el);
    box.innerHTML = '<div class="spinner">Liczenie…</div>';
    const r = await guard(() => POST('/api/reports/grouped', prm));
    if (!r) { box.innerHTML = ''; return; }
    last = r;
    const t = r.totals;
    box.innerHTML = `
    <div class="report-inline">
      <h2 class="rtitle">${esc(r.title)}</h2><div class="small muted mb8">Stan na ${esc(App.meta.today)} · VulnBuster</div>
      <div class="tiles">
        <div class="tile"><div class="v">${t.hosts}</div><div class="l">hosty</div></div>
        <div class="tile"><div class="v">${t.installations}</div><div class="l">instalacje</div></div>
        <div class="tile ${t.open ? 'red' : 'green'}"><div class="v">${t.open}</div><div class="l">do działań</div></div>
        <div class="tile ${t.open_kev ? 'red' : 'green'}"><div class="v">${t.open_kev}</div><div class="l">podatności z KEV</div></div>
        <div class="tile ${t.overdue ? 'red' : 'green'}"><div class="v">${t.overdue}</div><div class="l">po terminie</div></div>
        <div class="tile ${t.progress >= 90 ? 'green' : t.progress >= 60 ? 'amber' : 'red'}"><div class="v">${t.progress}%</div><div class="l">postęp (bez działań)</div></div>
      </div>
      <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th>${esc(r.group_label)}</th><th class="num">Hosty</th><th class="num">Instalacje</th>
        <th class="num">Do działań</th><th class="num">KEV</th><th class="num">Po terminie</th><th class="num">Wyjątki</th><th>Postęp</th></tr></thead><tbody>
        ${r.groups.map((g, i) => `<tr class="clickable" data-act="jump" data-i="${i}"><td><b>${esc(g.label)}</b></td><td class="num">${g.hosts}</td><td class="num">${g.installations}</td>
          <td class="num">${g.open ? `<span class="b vulnerable">${g.open}</span>` : '0'}</td><td class="num">${g.open_kev ? `<span class="b kev">${g.open_kev}</span>` : '0'}</td>
          <td class="num">${g.overdue ? `<span class="b red">${g.overdue}</span>` : '0'}</td><td class="num">${g.exception}</td>
          <td>${progressBar(g.ok, g.installations)}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">Brak danych dla wybranych filtrów</td></tr>'}
      </tbody></table></div></div>
      ${r.groups.map((g, i) => `<details class="panel grp" id="grp-${i}"${r.groups.length <= 3 ? ' open' : ''}><summary><b>${esc(g.label)}</b>
        <span class="muted small">· ${g.hosts} hostów · do działań ${g.open}${g.open_kev ? ' · KEV ' + g.open_kev : ''}${g.overdue ? ' · po terminie ' + g.overdue : ''}</span></summary>
        ${g.rows.length ? `<div class="tbl-wrap mt8"><table><thead><tr><th>Host</th><th>Spółka</th><th>Zespół</th><th>Aplikacja</th><th>Wersja</th><th>Docelowa</th>
          <th>Status</th><th>Ryzyko / termin</th><th>CVE</th><th>Właściciel</th></tr></thead><tbody>
          ${g.rows.slice(0, 400).map((x) => `<tr><td>${hostLink(x.host_id, x.hostname)}<div class="small faint">${esc(x.ip)} ${esc(x.type)}</div></td>
            <td class="small">${esc(x.company)}</td><td class="small">${esc(x.team)}</td><td>${prodLink(x.product_id, x.product)}</td>
            <td class="mono">${esc(x.version)}</td><td class="mono">${esc(x.target || (x.nofix ? 'migracja' : ''))}</td><td>${badge(x.status)}</td>
            <td>${riskBadge(x.risk)} ${deadlineBadge(x.deadline, x.overdue)}</td>
            <td class="small mono">${x.cves.map((c) => (x.kev.includes(c) ? '<b>' + esc(c) + '</b> KEV' : esc(c))).join('<br>')}</td>
            <td class="small">${esc(x.owner)}</td></tr>`).join('')}</tbody></table></div>
          ${g.rows_total > 400 ? `<div class="small muted mt8">Pokazano 400 z ${g.rows_total} — pełna lista w eksporcie Excel/CSV.</div>` : ''}`
          : '<div class="empty">Brak instalacji wymagających działań</div>'}</details>`).join('')}
    </div>`;
    applyWidths(box);
  };
  onAct(el, {
    run,
    jump: (t) => { const d = $(`#grp-${t.dataset.i}`, el); d.open = true; d.scrollIntoView({ behavior: 'smooth' }); },
    print: async () => { if (!last) await run(); $$('details.grp', el).forEach((d) => { d.open = true; }); window.print(); },
    xlsx: () => guard(() => downloadPost('/api/reports/grouped/xlsx', params(), 'raport.xlsx'), 'Pobrano plik Excel'),
    csv: async () => {
      if (!last) await run();
      if (!last) return;
      const rows = last.groups.flatMap((g) => g.rows.map((x) => [g.label, x.hostname, x.ip, x.company, x.team, x.type, x.os, x.environment, x.owner, x.admin,
        x.product, x.version, x.target || (x.nofix ? 'migracja' : ''), STATUS[x.status], RISK[x.risk] || '', x.deadline || '', x.overdue ? 'TAK' : '', x.cves.join(' '), x.kev.join(' ')]));
      downloadCSV(`raport-${last.group}-${App.meta.today}.csv`, [last.group_label, 'Host', 'IP', 'Spółka', 'Zespół', 'Typ', 'System', 'Środowisko', 'Właściciel', 'Administrator',
        'Aplikacja', 'Wersja', 'Docelowa', 'Status', 'Ryzyko', 'Termin', 'Po terminie', 'CVE', 'KEV'], rows);
    },
    tickets: () => {
      const p = params();
      if (!p.cve_id && !p.product_id) { toast('Wybierz aplikację albo CVE, dla których przygotować zgłoszenia', true); return; }
      location.hash = '#/tickets?' + new URLSearchParams(p.cve_id ? { cve: p.cve_id } : { product: p.product_id });
    },
  });
  if (q.group || q.product || q.cve) run();
}

/* =================================================================== ZGŁOSZENIA */
async function viewTickets(el, _, q) {
  if (!q.cve && !q.product) return viewTicketHistory(el);
  const split = q.split || 'team';
  const r = await POST('/api/tickets/preview', { cve_id: q.cve || null, product_id: q.product || null, split });
  let cveInfo = null;
  if (q.cve) cveInfo = await GET('/api/cves/' + enc(q.cve));
  const a = (cveInfo && cveInfo.cve.assessment) || {};
  const missing = q.cve ? [!a.impact && 'wpływ na organizację', !a.exploitation && 'sposób wykorzystania', !a.risk && 'wycena ryzyka',
    !a.deadline && !(cveInfo && cveInfo.kev) && 'termin'].filter(Boolean) : [];
  const scopeLabel = q.cve ? q.cve : (r.scope.product_name || 'aplikacja');
  el.innerHTML = `
  <div class="page-head"><div><h1>Zgłoszenia do realizatorów — ${esc(scopeLabel)}</h1>
      <div class="muted">Jedno zgłoszenie na zespół${split === 'team_company' ? ' i spółkę' : ''} · treść możesz poprawić przed skopiowaniem lub pobraniem</div></div>
    <div class="actions"><div class="seg">${[['team', 'Per zespół'], ['team_company', 'Per zespół i spółkę']].map(([k, l]) => `<button data-act="split" data-v="${k}" class="${k === split ? 'on' : ''}">${l}</button>`).join('')}</div>
      ${q.cve ? `<a class="btn" href="#/cve/${enc(q.cve)}">Karta CVE</a>` : `<a class="btn" href="#/product/${enc(q.product)}">Karta aplikacji</a>`}</div></div>
  ${missing.length ? `<div class="callout">W ocenie ${esc(q.cve)} brakuje: <b>${esc(missing.join(', '))}</b>. Uzupełnij je w <a href="#/cve/${enc(q.cve)}">karcie CVE</a>, a pojawią się w treści zgłoszeń.</div>` : ''}
  ${!r.tickets.length ? '<div class="panel empty">Brak hostów wymagających działań — nie ma czego zgłaszać 🎉</div>' : ''}
  ${r.tickets.map((t, i) => `<div class="panel ticket" data-i="${i}">
    <div class="panel-head"><div><h2>${esc(t.team_label)}${t.company ? ' · ' + esc(t.company) : ''}</h2>
        <div class="row small"><span>${t.hosts} hostów · ${t.installations} instalacji</span>${riskBadge(t.risk)} ${deadlineBadge(t.deadline, false)}
          ${t.sent ? `<span class="b green">zgłoszono ${esc(fmtDate(t.sent.created_at))}${t.sent.ticket_no ? ' · ' + esc(t.sent.ticket_no) : ''} (${esc(t.sent.created_by)})</span>` : '<span class="b outline">jeszcze nie zgłoszono</span>'}</div></div>
      <div class="row"><button class="btn sm" data-act="copysub">Kopiuj temat</button><button class="btn sm primary" data-act="copybody">Kopiuj treść</button>
        <button class="btn sm" data-act="eml" title="Plik .eml otworzy się w Outlooku jako szkic do wysłania, z listą hostów w CSV">Szkic e-mail (.eml)</button>
        <button class="btn sm" data-act="tcsv">CSV hostów</button></div></div>
    <div class="form">
      <label>Do<input type="text" name="to" value="${esc(t.email)}" placeholder="adres zespołu — ustaw w Ustawieniach"></label>
      <label class="wide">Temat<input type="text" name="subject" value="${esc(t.subject)}"></label>
      <label class="wide">Treść<textarea name="body" rows="16" class="mono ticket-body">${esc(t.body)}</textarea></label>
    </div>
    <div class="row mt8 w"><input type="text" name="ticket_no" placeholder="nr zgłoszenia w helpdesku (opcjonalnie)" size="32">
      <button class="btn sm" data-act="mark">Oznacz jako zgłoszone</button></div>
  </div>`).join('')}`;
  const T = (b) => r.tickets[+b.closest('.ticket').dataset.i];
  const F = (b) => formData(b.closest('.ticket'));
  onAct(el, {
    split: (b) => { location.hash = '#/tickets?' + new URLSearchParams({ ...(q.cve ? { cve: q.cve } : { product: q.product }), split: b.dataset.v }); },
    copysub: async (b) => toast((await copyText(F(b).subject)) ? 'Skopiowano temat' : 'Nie udało się skopiować', false),
    copybody: async (b) => toast((await copyText(F(b).body)) ? 'Skopiowano treść — wklej do formularza helpdesku' : 'Nie udało się skopiować'),
    tcsv: (b) => {
      const t = T(b);
      const a2 = document.createElement('a');
      a2.href = URL.createObjectURL(new Blob([t.csv], { type: 'text/csv;charset=utf-8' }));
      a2.download = `hosty-${(t.team_label + (t.company ? '-' + t.company : '')).replace(/[^\w-]+/g, '_')}.csv`;
      document.body.append(a2); a2.click(); a2.remove();
    },
    eml: (b) => {
      const t = T(b), f = F(b);
      return guard(() => downloadPost('/api/tickets/eml', { to: f.to, subject: f.subject, body: f.body, csv: t.csv,
        csv_name: `hosty-${(t.team_label).replace(/[^\w-]+/g, '_')}.csv` }, 'zgloszenie.eml'), 'Pobrano szkic — otwórz plik, aby wysłać z Outlooka');
    },
    mark: async (b) => {
      const t = T(b), f = F(b);
      const res = await guard(() => POST('/api/tickets', { cve_id: q.cve || null, product_id: q.product || null, team: t.team, company: t.company,
        ticket_no: f.ticket_no, subject: f.subject, deadline: t.deadline, hosts: [...new Set(t.rows.map((x) => x.host_id))] }), 'Zapisano zgłoszenie');
      if (res) render();
    },
  });
}

async function viewTicketHistory(el) {
  const r = await GET('/api/tickets');
  el.innerHTML = `
  <div class="page-head"><div><h1>Zgłoszenia do realizatorów</h1><div class="muted">Historia przekazanych zgłoszeń. Nowe przygotujesz z karty CVE, aplikacji albo z Raportów.</div></div></div>
  <div class="panel" id="tf"><div class="row"><input type="text" name="cve" class="mono" placeholder="CVE-2024-…"><button class="btn primary" data-act="go">Przygotuj zgłoszenia dla CVE</button></div></div>
  <div class="panel tight"><div class="tbl-wrap"><table><thead><tr><th>Data</th><th>Zakres</th><th>Zespół</th><th>Spółka</th><th>Nr</th><th>Temat</th><th class="num">Hosty</th><th>Kto</th><th></th></tr></thead><tbody>
  ${r.tickets.map((t) => `<tr><td class="small nowrap">${esc(fmtDT(t.created_at))}</td>
    <td>${t.cve ? cveLink(t.cve) : t.product ? prodLink(t.product, (App.products || []).find((p) => p.id === t.product)?.name || 'aplikacja') : ''}</td>
    <td>${esc(t.team_label)}</td><td class="small">${esc(t.company || '')}</td><td class="mono">${esc(t.ticket_no || '')}</td><td class="small">${esc(t.subject)}</td>
    <td class="num">${(t.hosts || []).length}</td><td class="small">${esc(t.created_by)}</td>
    <td><button class="btn sm ghost danger w" data-act="del" data-id="${esc(t.id)}">✕</button></td></tr>`).join('') || '<tr><td colspan="9" class="empty">Brak zgłoszeń</td></tr>'}
  </tbody></table></div></div>`;
  onAct(el, {
    go: () => { const c = $('#tf [name=cve]', el).value.trim().toUpperCase(); if (c) location.hash = '#/tickets?cve=' + enc(c); },
    del: async (b) => { if (confirm('Usunąć wpis o zgłoszeniu?') && await guard(() => DEL('/api/tickets/' + enc(b.dataset.id)), 'Usunięto')) render(); },
  });
}
