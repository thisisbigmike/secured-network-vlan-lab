/* SecureNet VLAN Lab - user interface */
(function () {
  'use strict';
  const T = window.SECURENET_TOPOLOGY;
  const C = window.SECURENET_CONFIGS;
  const E = window.NetEngine;
  const $ = (s, el) => (el || document).querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = {
    get(k, d) { try { const v = localStorage.getItem('securenet:' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('securenet:' + k, JSON.stringify(v)); } catch (e) { /* storage unavailable */ } }
  };
  const ALL_ON = { acls: true, vty: true, portSecurity: true, asaInbound: true };
  const ALL_OFF = { acls: false, vty: false, portSecurity: false, asaInbound: false };

  const state = {
    controls: Object.assign({}, ALL_ON),
    rogue: false,
    selected: 'PC13',
    consoles: {},
    lastEx: null,
    matrixDirty: true,
    matrixSel: null
  };
  let net = makeNet(state.controls, state.rogue);
  function makeNet(controls, rogue) { return new E.Network(T, C, { controls: Object.assign({}, controls), rogue }); }

  // ================================================================ theme
  (function initTheme() {
    const saved = store.get('theme', null);
    if (saved) document.documentElement.setAttribute('data-theme', saved);
    $('#themeToggle').addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      const next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      store.set('theme', next);
    });
  })();

  // ================================================================ tabs
  function showTab(id) {
    $$('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === id)));
    $$('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + id));
    if (id === 'matrix' && state.matrixDirty) renderMatrix();
    store.set('tab', id);
    try { history.replaceState(null, '', id === 'sim' ? location.pathname : '#' + id); } catch (e) { /* file:// may refuse */ }
  }
  $$('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));

  // ================================================================ icons
  const ZONE_VAR = { v1: '--v1', v2: '--v2', v3: '--v3', v4: '--v4', v5: '--v5', dmz: '--dmz', inet: '--inet' };
  function icon(type, role) {
    switch (type) {
      case 'router':
        return `<path d="M-22 -4v9a22 9 0 0 0 44 0v-9" fill="#1d5fa6"/><ellipse cx="0" cy="-4" rx="22" ry="9" fill="#3b86d1"/>
          <g stroke="#fff" stroke-width="2" stroke-linecap="round" fill="none"><path d="M-15 -4h9M-9 -7l3 3-3 3M15 -4h-9M9 -7l-3 3 3 3M0 -11v4M0 3v-4"/></g>`;
      case 'switch':
        return `<path d="M-26 -3l7-8h45l-7 8z" fill="#3b86d1"/><path d="M-26 -3h45v15h-45z" fill="#1d5fa6"/><path d="M19 -3l7-8v15l-7 8z" fill="#174c85"/>
          <g stroke="#fff" stroke-width="1.8" stroke-linecap="round" fill="none"><path d="M-15 -7h22M3 -9.5l4 2.5-4 2.5M-9 -4.5h22M-5 -7l-4 2.5 4 2.5" transform="translate(-1 0)"/></g>`;
      case 'hub':
        return `<rect x="-19" y="-8" width="38" height="16" rx="3" fill="#5b7795"/><g fill="#d8e4f2">${[-12, -6, 0, 6, 12].map((x) => `<rect x="${x - 2}" y="-2" width="4" height="4" rx="1"/>`).join('')}</g>`;
      case 'asa':
        return `<rect x="-22" y="-16" width="44" height="32" rx="4" fill="#b8323f"/><g stroke="#f6c9cd" stroke-width="1.6"><path d="M-22 -5h44M-22 6h44M-8 -16v11M8 -16v11M0 -5v11M-15 -5v11M15 -5v11M-8 6v10M8 6v10"/></g>`;
      case 'printer':
        return `<rect x="-11" y="-14" width="22" height="9" rx="1" fill="#e9eef5" stroke="#8193a8"/><rect x="-17" y="-6" width="34" height="14" rx="3" fill="#7d8ea3"/><rect x="-11" y="3" width="22" height="9" fill="#fff" stroke="#8193a8"/>`;
      case 'server':
        return `<rect x="-13" y="-18" width="26" height="36" rx="3" fill="#44566c"/><g fill="#9fb3c8"><rect x="-8" y="-12" width="16" height="3" rx="1"/><rect x="-8" y="-5" width="16" height="3" rx="1"/><rect x="-8" y="2" width="16" height="3" rx="1"/></g><circle cx="6" cy="12" r="2" fill="#5ee08c"/>`;
      case 'laptop':
        return `<rect x="-14" y="-15" width="28" height="19" rx="2" fill="#1b2433"/><rect x="-11" y="-12" width="22" height="13" fill="#e86a7a"/><path d="M-19 5h38l-4 6h-30z" fill="#7d8ea3"/>`;
      default: { // pc
        const screen = role === 'attacker' ? '#e5484d' : '#7fb5ea';
        return `<rect x="-15" y="-17" width="30" height="21" rx="2" fill="#1b2433"/><rect x="-12" y="-14" width="24" height="15" fill="${screen}"/><rect x="-3" y="4" width="6" height="6" fill="#55667a"/><rect x="-10" y="10" width="20" height="4" rx="2" fill="#55667a"/>`;
      }
    }
  }
  function iconSvg(name, size) {
    const d = T.devices[name];
    return `<svg viewBox="-30 -24 60 48" width="${size}" height="${size}" aria-hidden="true">${icon(d.type, d.role)}</svg>`;
  }

  // ================================================================ topology
  const svg = $('#topo');
  const tooltip = $('#tooltip');
  const LABEL = { R1: 'above', Switch0: 'below', 'ISP-Switch': 'right' };
  function visible(name) { const d = T.devices[name]; return !d.optional || state.rogue; }
  function zoneColor(z) { return z ? `var(${ZONE_VAR[z]})` : 'var(--text)'; }

  function renderTopology() {
    const [x0, y0, w, h] = T.viewBox;
    svg.setAttribute('viewBox', `${x0} ${y0} ${w} ${h}`);
    let s = '';
    for (const z of T.zones) {
      const c = zoneColor(z.id);
      s += `<g class="zone"><rect x="${z.x}" y="${z.y}" width="${z.w}" height="${z.h}" rx="14" style="fill:${c};fill-opacity:var(--zone-alpha);stroke:${c};stroke-opacity:.45"/>
        <text class="zl" x="${z.x + 12}" y="${z.y + 21}" style="fill:${c}">${esc(z.label)}</text><text class="zs" x="${z.x + 12}" y="${z.y + 37}">${esc(z.sub)}</text></g>`;
    }
    s += '<g id="links">';
    for (const l of T.links) {
      if (!visible(l[0]) || !visible(l[2])) continue;
      const a = T.devices[l[0]], b = T.devices[l[2]];
      const trunk = l[5] === '802.1Q trunk';
      s += `<line class="link ${l[4] === 'cross' ? 'cross' : ''} ${trunk ? 'trunk' : ''}" data-k="${linkKey(l[0], l[2])}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`;
    }
    for (const l of T.links) {
      if (!l[5] || l[5] === 'optional') continue;
      const a = T.devices[l[0]], b = T.devices[l[2]];
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const vertical = Math.abs(a.x - b.x) < 10;
      s += `<text class="link-label" x="${vertical ? mx + 10 : mx}" y="${vertical ? my + 4 : my - 8}" text-anchor="${vertical ? 'start' : 'middle'}">${esc(l[5])}</text>`;
    }
    s += '</g><g id="devices">';
    for (const [name, d] of Object.entries(T.devices)) {
      if (!visible(name)) continue;
      const core = ['router', 'switch', 'asa'].includes(d.type);
      const pos = LABEL[name] || 'below';
      const ip = d.ip || (name === 'R1' ? 'Fa0/0.1-5 · .1' : name === 'ASA1' ? 'in/out/dmz' : name === 'Switch0' ? 'mgmt 192.168.1.2' : '');
      let lx = 0, ly = 34, anchor = 'middle';
      if (pos === 'above') ly = -50;
      if (pos === 'right') { lx = 34; ly = -2; anchor = 'start'; }
      const lines = [`<text class="dn" x="${lx}" y="${ly}" text-anchor="${anchor}">${esc(name)}</text>`];
      if (core) lines.push(`<text class="dm" x="${lx}" y="${ly + 13.5}" text-anchor="${anchor}">${esc(d.model)}</text>`);
      if (ip && d.type !== 'hub') lines.push(`<text class="di" x="${lx}" y="${ly + (core ? 27 : 14)}" text-anchor="${anchor}">${esc(ip)}</text>`);
      s += `<g class="dev${state.selected === name ? ' sel' : ''}" data-dev="${esc(name)}" transform="translate(${d.x} ${d.y})" tabindex="0" role="button" aria-label="${esc(name)} ${esc(d.model)} ${esc(d.ip || '')}">
        <rect class="hit" x="-34" y="${pos === 'above' ? -64 : -26}" width="68" height="${pos === 'above' ? 92 : (core ? 88 : 76)}" rx="10"/>
        ${icon(d.type, d.role)}
        <g class="lbl" style="paint-order:stroke;stroke:var(--surface);stroke-width:4px;stroke-linejoin:round">${lines.join('')}</g>
        ${badgeFor(name)}
      </g>`;
    }
    s += '</g><g id="packets"></g>';
    svg.innerHTML = s;
    $$('.dev', svg).forEach((g) => {
      g.addEventListener('click', () => select(g.dataset.dev));
      g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(g.dataset.dev); } });
      g.addEventListener('mouseenter', () => showTip(g.dataset.dev));
      g.addEventListener('mouseleave', () => { tooltip.hidden = true; });
    });
  }
  function badgeFor(name) {
    const off = [];
    if (name === 'R1' && !state.controls.acls) off.push('ACLs OFF');
    if (name === 'R1' && !state.controls.vty) off.push('VTY OPEN');
    if (name === 'Switch0' && !state.controls.portSecurity) off.push('PORT-SEC OFF');
    if (name === 'ASA1' && !state.controls.asaInbound) off.push('INBOUND OPEN');
    return off.map((t, i) => `<g class="badge-off" transform="translate(24 ${-26 + i * 15})"><rect width="${t.length * 6 + 10}" height="13" rx="6.5"/><text x="5" y="9.5">${t}</text></g>`).join('');
  }
  function linkKey(a, b) { return [a, b].sort().join('|'); }
  function showTip(name) {
    const d = T.devices[name];
    const rect = svg.getBoundingClientRect();
    const vb = T.viewBox;
    const sx = rect.width / vb[2], sy = rect.height / vb[3];
    const wrap = $('.topo-wrap').getBoundingClientRect();
    tooltip.style.left = (rect.left - wrap.left + d.x * sx) + 'px';
    tooltip.style.top = (rect.top - wrap.top + (d.y - 26) * sy) + 'px';
    const zone = T.zones.find((z) => z.id === d.zone);
    tooltip.innerHTML = `<b>${esc(name)}</b> · ${esc(d.model)}${d.ip ? `<br>${esc(d.ip)} / ${E.ipToInt(d.mask) ? maskLen(d.mask) : ''}${d.gw ? ' · gw ' + esc(d.gw) : ''}` : ''}${zone ? `<br>${esc(zone.label)}` : ''}${d.role && !d.ip ? `<br>${esc(d.role)}` : ''}`;
    tooltip.hidden = false;
  }
  function maskLen(m) { return m.split('.').reduce((a, o) => a + (Number(o).toString(2).match(/1/g) || []).length, 0); }

  // ---------------------------------------------------------- animation
  let animToken = 0;
  function center(name) { const d = T.devices[name]; return { x: d.x, y: d.y }; }
  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
  async function animate(ex) {
    const my = ++animToken;
    const layer = $('#packets', svg);
    if (!layer || !ex) return;
    layer.innerHTML = '';
    $$('.link.lit', svg).forEach((l) => l.classList.remove('lit'));
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    for (const tr of ex.trails) {
      if (my !== animToken) return;
      const color = tr.error ? 'var(--warn)' : tr.dir === 'out' ? 'var(--accent)' : 'var(--ok)';
      const devs = tr.devices.filter(visible);
      const dot = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      dot.setAttribute('class', 'pkt');
      dot.innerHTML = `<rect x="-9" y="-6.5" width="18" height="13" rx="2.5" style="fill:${color}"/><path d="M-9 -6l9 6.5 9-6.5" fill="none" stroke="#fff" stroke-width="1.6"/>`;
      layer.appendChild(dot);
      for (let i = 0; i < devs.length - 1; i++) {
        if (my !== animToken) { dot.remove(); return; }
        const a = center(devs[i]), b = center(devs[i + 1]);
        const ln = svg.querySelector(`.link[data-k="${linkKey(devs[i], devs[i + 1])}"]`);
        if (ln) ln.classList.add('lit');
        const dist = Math.hypot(b.x - a.x, b.y - a.y);
        const dur = reduce ? 0 : Math.max(220, dist * 1.6);
        const t0 = performance.now();
        await new Promise((res) => {
          const step = (now) => {
            if (my !== animToken) return res();
            const t = dur ? Math.min(1, (now - t0) / dur) : 1;
            const e = t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
            dot.setAttribute('transform', `translate(${a.x + (b.x - a.x) * e} ${a.y + (b.y - a.y) * e})`);
            if (t < 1) requestAnimationFrame(step); else res();
          };
          requestAnimationFrame(step);
        });
      }
      if (my !== animToken) { dot.remove(); return; }
      if (devs.length === 1) dot.setAttribute('transform', `translate(${center(devs[0]).x} ${center(devs[0]).y})`);
      if (!tr.ok) {
        const p = center(devs[devs.length - 1]);
        const x = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        x.setAttribute('class', 'drop-x');
        x.setAttribute('transform', `translate(${p.x + 20} ${p.y - 20})`);
        x.innerHTML = '<circle r="11"/><line x1="-5" y1="-5" x2="5" y2="5"/><line x1="5" y1="-5" x2="-5" y2="5"/>';
        layer.appendChild(x);
        dot.remove();
      } else {
        await sleep(reduce ? 0 : 160);
        dot.remove();
      }
    }
    setTimeout(() => { if (my === animToken) $$('.link.lit', svg).forEach((l) => l.classList.remove('lit')); }, 1600);
  }

  // ================================================================ controls
  const CONTROL_HELP = {
    acls: 'Removes "ip access-group" from R1 sub-interfaces 0.2-0.5',
    vty: 'Removes "access-class 10 in" from R1 line vty 0 4',
    portSecurity: 'Removes "switchport port-security" from Switch0 Fa0/1-5',
    asaInbound: 'Replaces ACL OUTSIDE-DMZ with "permit ip any any"'
  };
  function renderControls() {
    const el = $('#controls');
    el.innerHTML = '<h3>Security controls (live config)</h3>' +
      Object.entries(E.CONTROLS).map(([k, c]) => `<label class="toggle ${state.controls[k] ? '' : 'off-state'}" title="${esc(CONTROL_HELP[k])}"><input type="checkbox" data-ctl="${k}" ${state.controls[k] ? 'checked' : ''}> ${esc(c.label)}</label>`).join('') +
      `<label class="toggle danger" title="Connects Rogue-Laptop (192.168.4.66) to Hub2 Port 5"><input type="checkbox" id="rogueToggle" ${state.rogue ? 'checked' : ''}> Plug rogue laptop into Account hub</label>
       <span class="spacer"></span><button class="btn small" type="button" id="resetSim">Clear ARP caches &amp; counters</button>`;
    $$('input[data-ctl]', el).forEach((i) => i.addEventListener('change', () => { state.controls[i.dataset.ctl] = i.checked; rebuild(); }));
    $('#rogueToggle').addEventListener('change', (e) => {
      state.rogue = e.target.checked;
      rebuild();
      if (state.rogue) select('Rogue-Laptop');
      else if (state.selected === 'Rogue-Laptop') select('PC18');
    });
    $('#resetSim').addEventListener('click', () => { net.reset(); clearEvents(); log(state.selected, 'dim', '[ARP caches, ACL counters and connection tables cleared]'); renderConsole(); });
  }
  function rebuild() {
    net = makeNet(state.controls, state.rogue);
    state.matrixDirty = true;
    renderTopology();
    renderControls();
    renderConsole();
    clearEvents();
    if ($('#tab-matrix').classList.contains('active')) renderMatrix();
    renderScenarios();
  }

  // ================================================================ console
  const QUICK = {
    PC10: ['ipconfig /all', 'ping 192.168.1.1', 'ping 192.168.4.18', 'ping 172.16.50.10', 'ssh -l admin 192.168.1.1', 'tracert 209.165.201.10'],
    PC11: ['ping 192.168.1.1', 'ping 192.168.2.13', 'ssh -l admin 192.168.1.2'],
    PC12: ['ping 192.168.1.1', 'ping 192.168.5.21', 'ping 172.16.0.2'],
    PC13: ['ipconfig', 'ping 192.168.2.1', 'ping 192.168.5.21', 'ping 192.168.4.18', 'ping 192.168.1.10', 'ssh -l admin 192.168.2.1', 'nslookup www.cyberlab.com'],
    PC14: ['ping 192.168.4.18', 'ping 192.168.4.100', 'ping 192.168.5.22'],
    PC15: ['ping 192.168.3.16', 'ping 172.16.50.10', 'tracert 209.165.201.10'],
    PC16: ['ping 192.168.3.1', 'ping 192.168.2.13', 'ping 192.168.1.10', 'ping 172.16.50.10', 'telnet 172.16.50.10 80'],
    PC24: ['ping 192.168.5.21', 'ping 192.168.4.19'],
    PC18: ['ipconfig', 'ping 192.168.4.1', 'ping 192.168.4.19', 'ping 192.168.2.13', 'ping 192.168.1.10', 'ping 209.165.201.10'],
    PC19: ['ping 192.168.4.1', 'ping 192.168.5.21'],
    PC20: ['ping 192.168.4.18', 'tracert 209.165.201.10'],
    PC21: ['ping 192.168.5.1', 'ping 192.168.1.10', 'ping 192.168.3.16', 'ssh -l admin 192.168.5.1', 'telnet 192.168.5.1'],
    PC22: ['ping 192.168.1.2', 'ssh -l admin 192.168.5.1'],
    PC23: ['ping 192.168.2.14', 'nslookup www.internet.com'],
    'Attacker-PC': ['ping 192.168.4.18', 'ping 209.165.200.227', 'telnet 209.165.200.227 80', 'telnet 209.165.200.227 21', 'ssh -l admin 209.165.200.226', 'tracert 209.165.200.227'],
    'DMZ-Server': ['ping 192.168.1.10', 'telnet 192.168.4.18 80', 'ping 209.165.201.10'],
    'Internet-Server': ['ping 209.165.200.227', 'ping 192.168.1.10'],
    'Rogue-Laptop': ['ping 192.168.4.1', 'ping 192.168.4.19', 'ping 209.165.201.10'],
    R1: ['enable', 'show ip interface brief', 'show access-lists', 'show ip route', 'show arp', 'show running-config', 'ping 192.168.4.18'],
    ISP: ['show ip interface brief', 'show ip route', 'ping 209.165.200.227', 'ping 192.168.1.10'],
    Switch0: ['enable', 'show vlan brief', 'show interfaces trunk', 'show port-security', 'show port-security interface fa0/4', 'show mac address-table', 'show running-config'],
    'ISP-Switch': ['show vlan brief'],
    ASA1: ['enable', 'show nameif', 'show ip address', 'show route', 'show access-list', 'show nat', 'show xlate', 'show conn', 'show running-config']
  };
  function isHost(name) { return ['pc', 'laptop', 'server'].includes(T.devices[name].type); }
  function isNetDev(name) { return ['router', 'switch', 'asa'].includes(T.devices[name].type); }
  function cons(name) {
    if (!state.consoles[name]) {
      const d = T.devices[name];
      const c = { lines: [], hist: [], hi: -1, priv: false, tab: isHost(name) ? 'cmd' : isNetDev(name) ? 'cli' : 'info', url: d.role === 'attacker' ? 'http://209.165.200.227' : 'http://www.cyberlab.com', page: null };
      if (isHost(name)) c.lines.push({ t: 'Packet Tracer PC Command Line 1.0', c: 'dim' });
      else if (isNetDev(name)) {
        const cfg = net.devices[name].cfg;
        if (cfg && cfg.banner) c.lines.push({ t: cfg.banner, c: 'dim' });
        c.lines.push({ t: `${name} (${d.model}) - press a command below or type "?"`, c: 'dim' });
      }
      state.consoles[name] = c;
    }
    return state.consoles[name];
  }
  function prompt(name) {
    if (isHost(name)) return 'C:\\>';
    const cfg = net.devices[name].cfg;
    return (cfg ? cfg.hostname : name) + (cons(name).priv ? '#' : '>');
  }
  function log(name, cls, text) { cons(name).lines.push({ t: text, c: cls }); }

  function select(name) {
    if (!T.devices[name] || !visible(name)) return;
    state.selected = name;
    $$('.dev', svg).forEach((g) => g.classList.toggle('sel', g.dataset.dev === name));
    renderConsole();
  }

  function renderConsole() {
    const name = state.selected;
    const d = T.devices[name];
    const c = cons(name);
    const zone = T.zones.find((z) => z.id === d.zone);
    const el = $('#console');
    const tabs = isHost(name) ? [['cmd', 'Command Prompt'], ['web', 'Web Browser'], ['info', 'IP Configuration']]
      : isNetDev(name) ? [['cli', 'CLI'], ['info', 'Details']] : [['info', 'Details']];
    if (!tabs.some((t) => t[0] === c.tab)) c.tab = tabs[0][0];
    el.innerHTML = `
      <div class="dev-head">
        <div class="ico">${iconSvg(name, 34)}</div>
        <div><h2>${esc(name)}${zone ? `<span class="zone-pill" style="background:${zoneColor(d.zone)}">${esc(zone.label.split('·')[0].trim())}</span>` : ''}</h2>
        <p>${esc(d.model)}${d.ip ? ' · ' + esc(d.ip) : ''}${d.role ? ' · ' + esc(d.role) : ''}</p></div>
      </div>
      <div class="subtabs" role="tablist">${tabs.map(([k, l]) => `<button role="tab" data-sub="${k}" aria-selected="${c.tab === k}">${l}</button>`).join('')}</div>
      <div class="console-body" id="consoleBody"></div>`;
    $$('.subtabs button', el).forEach((b) => b.addEventListener('click', () => { c.tab = b.dataset.sub; renderConsole(); }));
    const body = $('#consoleBody');
    if (c.tab === 'cmd' || c.tab === 'cli') renderTerminal(name, body);
    else if (c.tab === 'web') renderBrowser(name, body);
    else renderInfo(name, body);
  }

  function renderTerminal(name, body) {
    const c = cons(name);
    const chips = QUICK[name] || [];
    body.innerHTML = `
      ${chips.length ? `<div class="chips">${chips.map((q) => `<button class="chip" type="button" data-q="${esc(q)}">${esc(q)}</button>`).join('')}</div>` : ''}
      <div class="terminal" id="term" aria-live="polite"></div>
      <form class="term-input" id="termForm" autocomplete="off"><span>${esc(prompt(name))}</span><input id="termIn" aria-label="Command" spellcheck="false" placeholder="type a command, e.g. ${esc(chips[1] || chips[0] || 'help')}"></form>`;
    const term = $('#term');
    term.innerHTML = c.lines.map((l) => `<div class="${l.c || ''}">${esc(l.t) || '&nbsp;'}</div>`).join('');
    term.scrollTop = term.scrollHeight;
    const input = $('#termIn');
    $$('.chip', body).forEach((b) => b.addEventListener('click', () => run(name, b.dataset.q)));
    $('#termForm').addEventListener('submit', (e) => { e.preventDefault(); const v = input.value; input.value = ''; run(name, v); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        e.preventDefault();
        if (!c.hist.length) return;
        c.hi = e.key === 'ArrowUp' ? Math.max(0, (c.hi < 0 ? c.hist.length : c.hi) - 1) : Math.min(c.hist.length, c.hi + 1);
        input.value = c.hist[c.hi] || '';
      }
    });
    if (document.activeElement && document.activeElement.closest && !document.activeElement.closest('#tab-sim')) return;
  }

  function classify(line) {
    if (/bytes=\d+ time|^Reply from .*TTL|^!+$|Success rate is [1-9]|^\s+\d+\s+(\d+ ms|\*).*\d+\.\d+\.\d+\.\d+$|^Open$|Non-authoritative|^Address: 2|^Address: 1/.test(line)) return 'good';
    if (/unreachable|timed out|refused|Request Timeout|Invalid|can't find|could not find|rejects|^\.+$|^U[.U]*$|Success rate is 0/.test(line)) return 'bad';
    return '';
  }

  function run(name, line, opts) {
    const c = cons(name);
    line = String(line || '').trim();
    if (c.tab !== 'cmd' && c.tab !== 'cli') c.tab = isHost(name) ? 'cmd' : 'cli';
    log(name, 'cmd', prompt(name) + line);
    if (!line) { renderConsole(); return; }
    c.hist.push(line); c.hi = -1;
    if (line.toLowerCase() === 'cls' || line.toLowerCase() === 'clear') { c.lines = []; renderConsole(); return; }
    let res;
    if (isHost(name)) res = net.hostCommand(name, line);
    else {
      const st = { priv: c.priv };
      res = net.cli(name, line, st);
      if (res.state) c.priv = res.state.priv;
    }
    for (const l of res.out || []) log(name, classify(l), l);
    renderConsole();
    if (res.exchanges && res.exchanges.length) showExchange(res.exchanges[res.exchanges.length - 1], name + ' › ' + line);
    if (opts && opts.scroll) document.getElementById('console').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function renderBrowser(name, body) {
    const c = cons(name);
    body.innerHTML = `
      <div class="browser">
        <form class="browser-bar" id="browserForm"><input id="url" value="${esc(c.url)}" aria-label="URL" spellcheck="false"><button class="btn small primary" type="submit">Go</button></form>
        <div class="browser-view" id="bview">${pageHtml(c.page)}</div>
      </div>
      <div class="chips">${['http://www.cyberlab.com', 'http://172.16.50.10', 'http://www.internet.com', 'http://209.165.201.10', 'http://209.165.200.227'].map((u) => `<button class="chip" type="button" data-u="${u}">${u}</button>`).join('')}</div>`;
    $('#browserForm').addEventListener('submit', (e) => { e.preventDefault(); browse(name, $('#url').value); });
    $$('.chip', body).forEach((b) => b.addEventListener('click', () => browse(name, b.dataset.u)));
  }
  function browse(name, url) {
    const c = cons(name);
    c.url = url;
    c.tab = 'web';
    const r = net.browse(name, url);
    c.page = r;
    renderConsole();
    const ex = r.exchanges && r.exchanges[r.exchanges.length - 1];
    if (ex) showExchange(ex, `${name} › browse ${url}`);
  }
  function pageHtml(r) {
    if (!r) return '<p style="color:#6b7280">Enter an address and press Go. The request uses DNS (UDP 53) and HTTP (TCP 80), so it is checked by the same ACLs and firewall rules as everything else.</p>';
    if (r.view === 'page') return `<div class="page-title">${esc(r.page.title)} · served by ${esc(r.server)}</div><h3>${esc(r.page.heading)}</h3><p>${esc(r.page.body)}</p>`;
    return `<h3 class="err">${esc(r.title)}</h3><p>${esc(r.message)}</p>`;
  }

  function renderInfo(name, body) {
    const d = T.devices[name];
    const dev = net.devices[name];
    const rows = [];
    if (d.ip) {
      rows.push(['IPv4 address', d.ip], ['Subnet mask', d.mask], ['Default gateway', d.gw || '-'], ['DNS server', d.dns || '-'], ['MAC address', dev.mac]);
    }
    const attach = attachment(name);
    if (attach) rows.push(['Connected to', attach]);
    if (d.services) rows.push(['Services', Object.keys(d.services).map((s) => s.toUpperCase()).join(', ')]);
    let extra = '';
    if (d.type === 'printer') extra = '<p class="note">Printers in Packet Tracer have no command prompt. Ping them from a PC to test reachability.</p>';
    if (d.type === 'hub') extra = '<p class="note">A hub repeats every frame out of every port, so all devices on it share one collision domain and can see each other\'s traffic. The switch port it plugs into decides its VLAN.</p>';
    if (name === 'DMZ-Server') extra = '<p class="note">In Packet Tracer: Services → HTTP on (edit index.html), DNS on with A records <code>www.cyberlab.com → 172.16.50.10</code> and <code>www.internet.com → 209.165.201.10</code>. Published to the Internet as 209.165.200.227 by ASA static NAT.</p>';
    if (name === 'Rogue-Laptop') extra = '<p class="note">Not part of the design: this laptop is plugged into Hub2 Port 5 to test port security. Its MAC address is not one of the sticky addresses Switch0 learned on Fa0/4.</p>';
    if (isNetDev(name)) extra = `<p class="note">Open the CLI tab to run show commands against the live configuration. The full config is in the Packet Tracer build kit tab.</p>`;
    body.innerHTML = `${rows.length ? `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : ''}${extra}`;
  }
  function attachment(name) {
    const l = T.links.find((x) => x[0] === name || x[2] === name);
    if (!l) return '';
    const mine = l[0] === name ? [l[1], l[2], l[3]] : [l[3], l[0], l[1]];
    let s = `${mine[0]} → ${mine[1]} ${mine[2]}`;
    if (T.devices[mine[1]].type === 'hub') {
      const up = T.links.find((x) => (x[0] === mine[1] || x[2] === mine[1]) && (x[0] === 'Switch0' || x[2] === 'Switch0'));
      if (up) {
        const sp = up[0] === 'Switch0' ? up[1] : up[3];
        const vlan = T.vlans.find((v) => v.switchPort === sp);
        s += ` → Switch0 ${E.shortIf(sp)}${vlan ? ` (access VLAN ${vlan.id})` : ''}`;
      }
    }
    return s;
  }

  // ================================================================ events
  function clearEvents() {
    state.lastEx = null;
    $('#events').innerHTML = '';
    $('#resultBanner').innerHTML = '';
    $('#eventsEmpty').hidden = false;
    $('#replay').disabled = true;
    const layer = $('#packets', svg);
    if (layer) layer.innerHTML = '';
  }
  function verdict(ex) {
    const okStatus = ['echo-reply', 'syn-ack', 'dns'].includes(ex.status);
    const dst = ex.request && ex.request.pkt ? ex.request.pkt.dst : '';
    if (okStatus) return { cls: 'ok', title: `Delivered: ${ex.src} ↔ ${ex.from || dst}`, sub: ex.status === 'echo-reply' ? `Echo reply received (TTL ${ex.ttl}).` : ex.status === 'dns' ? 'DNS answer received.' : 'Connection accepted (TCP SYN-ACK).' };
    if (ex.arp) return { cls: 'warn', title: 'First packet lost while the router resolved ARP', sub: 'This is normal on the first ping. Run it again and every packet gets through.' };
    if (ex.status === 'rst') return { cls: 'bad', title: `Refused by ${ex.request.to.dev}`, sub: ex.note || 'The destination answered with TCP RST.' };
    if (ex.status === 'unreachable') return { cls: 'bad', title: `Blocked at ${ex.blockedAt}: Destination host unreachable`, sub: ex.reason };
    return { cls: 'bad', title: `Dropped${ex.blockedAt ? ' at ' + ex.blockedAt : ''}: no reply`, sub: ex.reason || 'The request timed out.' };
  }
  function showExchange(ex, label) {
    state.lastEx = ex;
    const v = verdict(ex);
    $('#resultBanner').innerHTML = `<div class="result-banner ${v.cls}"><span>${v.cls === 'ok' ? '✓' : v.cls === 'warn' ? '⏱' : '✕'}</span><div>${esc(v.title)}<small>${esc(label)} · ${esc(v.sub || '')}</small></div></div>`;
    $('#events').innerHTML = ex.events.map((e) => `<li class="${esc(e.kind)}"><span class="who">${esc(e.dev)}</span><span class="what">${esc(e.text)}</span></li>`).join('');
    $('#eventsEmpty').hidden = true;
    $('#replay').disabled = false;
    animate(ex);
  }
  $('#replay').addEventListener('click', () => state.lastEx && animate(state.lastEx));

  // ================================================================ matrix
  const M_SOURCES = [
    { dev: 'PC10', head: 'Management', sub: 'PC10 · VLAN 1', zone: 'v1', gw: '192.168.1.1' },
    { dev: 'PC13', head: 'Administrative', sub: 'PC13 · VLAN 2', zone: 'v2', gw: '192.168.2.1' },
    { dev: 'PC16', head: 'Maintenance', sub: 'PC16 · VLAN 3', zone: 'v3', gw: '192.168.3.1' },
    { dev: 'PC18', head: 'Account', sub: 'PC18 · VLAN 4', zone: 'v4', gw: '192.168.4.1' },
    { dev: 'PC21', head: 'Works', sub: 'PC21 · VLAN 5', zone: 'v5', gw: '192.168.5.1' },
    { dev: 'DMZ-Server', head: 'DMZ server', sub: '172.16.50.10', zone: 'dmz', gw: '172.16.50.1' },
    { dev: 'Attacker-PC', head: 'Internet attacker', sub: '209.165.201.20', zone: 'inet', gw: '209.165.200.226' }
  ];
  const M_TARGETS = [
    { head: 'Management', sub: 'ping PC11', zone: 'v1', f: () => ({ cmd: 'ping 192.168.1.11' }) },
    { head: 'Administrative', sub: 'ping PC14', zone: 'v2', f: () => ({ cmd: 'ping 192.168.2.14' }) },
    { head: 'Maintenance', sub: 'ping PC24', zone: 'v3', f: () => ({ cmd: 'ping 192.168.3.24' }) },
    { head: 'Account', sub: 'ping PC19', zone: 'v4', f: () => ({ cmd: 'ping 192.168.4.19' }) },
    { head: 'Works', sub: 'ping PC22', zone: 'v5', f: () => ({ cmd: 'ping 192.168.5.22' }) },
    { head: 'Company website', sub: 'HTTP to DMZ', zone: 'dmz', f: (s) => (s.dev === 'DMZ-Server' ? null : { cmd: `telnet ${s.dev === 'Attacker-PC' ? '209.165.200.227' : '172.16.50.10'} 80` }) },
    { head: 'DMZ server', sub: 'ping', zone: 'dmz', f: (s) => (s.dev === 'DMZ-Server' ? null : { cmd: `ping ${s.dev === 'Attacker-PC' ? '209.165.200.227' : '172.16.50.10'}` }) },
    { head: 'Internet', sub: 'HTTP 209.165.201.10', zone: 'inet', f: () => ({ cmd: 'telnet 209.165.201.10 80' }) },
    { head: 'Device login', sub: 'SSH to gateway / firewall', zone: null, f: (s) => ({ cmd: `ssh -l admin ${s.gw}` }) }
  ];

  function specOf(cmd) {
    const w = cmd.trim().split(/\s+/);
    if (w[0] === 'ping') return { proto: 'icmp', dst: w[1] };
    if (w[0] === 'telnet') return { proto: 'tcp', dst: w[1], port: Number(w[2]) || 23 };
    if (w[0] === 'ssh') return { proto: 'tcp', dst: w[w.length - 1], port: 22 };
    if (w[0] === 'browse') return { proto: 'tcp', dst: w[1].replace(/^https?:\/\//i, '').split(/[/:]/)[0], port: 80 };
    return null;
  }
  function dryRun(n, src, cmd) {
    const spec = specOf(cmd);
    if (!E.isIp(spec.dst)) {
      const r = n.resolveName(src, spec.dst, { dry: true });
      if (!r.ok) return { status: 'dns-fail', ok: false, reason: `DNS lookup for ${spec.dst} failed: ${r.reason}`, exDns: r.exchange };
      spec.dst = r.ip;
    }
    return n.test(src, spec);
  }
  function isOk(ex) { return ['echo-reply', 'syn-ack', 'dns'].includes(ex.status); }
  function blocker(ex) {
    if (isOk(ex)) return ex.status === 'echo-reply' ? 'reply' : 'open';
    if (ex.status === 'dns-fail') return 'DNS blocked';
    if (ex.status === 'rst') return /access-class/.test(ex.note || '') ? 'VTY access-class' : /accept only/.test(ex.note || '') ? 'SSH only' : 'Refused';
    const r = ex.rule || {};
    if (r.acl) return `${r.dev} ACL`;
    if (/no forward/.test(r.text || '')) return 'ASA no-forward';
    if (r.text === 'security-level') return 'ASA zones';
    if (r.text === 'no connection') return 'ASA stateful';
    if (/to-the-box/.test(r.text || '')) return 'ASA mgmt';
    if (r.text === 'no route') return 'Not routable';
    if (/port-security/.test(r.text || '')) return 'Port security';
    return ex.blockedAt ? `${ex.blockedAt}` : 'No reply';
  }

  function renderMatrix() {
    state.matrixDirty = false;
    const baseline = $('#baselineToggle').checked;
    const open = baseline ? makeNet(ALL_OFF, state.rogue) : null;
    let h = '<table class="matrix"><thead><tr><th>From ↓ &nbsp; To →</th>';
    for (const t of M_TARGETS) h += `<th style="--zc:${t.zone ? zoneColor(t.zone) : 'var(--border)'}">${esc(t.head)}<small>${esc(t.sub)}</small></th>`;
    h += '</tr></thead><tbody>';
    M_SOURCES.forEach((s, si) => {
      h += `<tr><th class="row" style="--zc:${zoneColor(s.zone)}">${esc(s.head)}<small>${esc(s.sub)}</small></th>`;
      M_TARGETS.forEach((t, ti) => {
        const job = t.f(s);
        if (!job) { h += '<td><div class="cell na">—</div></td>'; return; }
        const ex = dryRun(net, s.dev, job.cmd);
        const ok = isOk(ex);
        let was = '';
        if (open) { const ob = isOk(dryRun(open, s.dev, job.cmd)); if (ob !== ok) was = `<span class="was">off: ${ob ? '✓ open' : '✕'}</span>`; }
        const sel = state.matrixSel && state.matrixSel.si === si && state.matrixSel.ti === ti;
        h += `<td><button type="button" class="cell ${ok ? 'ok' : 'bad'}${sel ? ' sel' : ''}" data-si="${si}" data-ti="${ti}" aria-label="${esc(s.head)} to ${esc(t.head)}: ${ok ? 'allowed' : 'blocked'}"><span class="mark">${ok ? '✓' : '✕'}</span><span class="by">${esc(blocker(ex))}</span>${was}</button></td>`;
      });
      h += '</tr>';
    });
    h += '</tbody></table>';
    $('#matrixTable').innerHTML = h;
    $$('#matrixTable .cell[data-si]').forEach((b) => b.addEventListener('click', () => { state.matrixSel = { si: Number(b.dataset.si), ti: Number(b.dataset.ti) }; $$('#matrixTable .cell.sel').forEach((x) => x.classList.remove('sel')); b.classList.add('sel'); matrixDetail(); }));
    matrixDetail();
  }
  function matrixDetail() {
    const el = $('#matrixDetail');
    if (!state.matrixSel) { el.innerHTML = '<div class="detail"><p>Select a cell to see why it is allowed or blocked. Green = reachable, red = stopped by a security control. The small label shows which control decided.</p></div>'; return; }
    const s = M_SOURCES[state.matrixSel.si], t = M_TARGETS[state.matrixSel.ti];
    const job = t.f(s);
    const ex = dryRun(net, s.dev, job.cmd);
    const ok = isOk(ex);
    const why = ok ? 'Every device on the path permits it.' : (ex.reason || ex.note || 'No reply.');
    const rule = ex.rule && ex.rule.acl ? ` Rule: <code>${esc(ex.rule.acl)}${ex.rule.seq ? ' line ' + ex.rule.seq : ''}: ${esc(ex.rule.text)}</code>` : '';
    el.innerHTML = `<div class="detail"><p><b>${esc(s.dev)}</b> → <code>${esc(job.cmd)}</code> · <b style="color:var(--${ok ? 'ok' : 'bad'})">${ok ? 'Allowed' : 'Blocked'}</b>. ${esc(why)}${rule}</p><button class="btn primary" type="button" id="watchCell">Watch it in the simulator</button></div>`;
    $('#watchCell').addEventListener('click', () => watch(s.dev, job.cmd));
  }
  $('#baselineToggle').addEventListener('change', renderMatrix);

  function watch(dev, cmd) {
    showTab('sim');
    if (dev === 'Rogue-Laptop' && !state.rogue) { state.rogue = true; rebuild(); }
    select(dev);
    if (cmd.startsWith('browse ')) browse(dev, cmd.slice(7));
    else run(dev, cmd);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // ================================================================ scenarios
  const SCENARIOS = [
    {
      tag: 'Insider threat · unauthorised access', title: 'An Administrative clerk tries to get into the Account department',
      story: 'Most hacking and data theft described in Chapter 2 starts inside the building. A clerk in Administrative (VLAN 2) tries to reach the Account PCs and printer, where payroll data lives.',
      controls: 'VLAN segmentation + R1 extended ACL VLAN2-ADMIN-IN',
      steps: [
        { src: 'PC14', cmd: 'ping 192.168.4.18', label: 'Clerk pings an Account PC' },
        { src: 'PC14', cmd: 'ping 192.168.4.100', label: 'Clerk pings the Account printer' },
        { src: 'PC14', cmd: 'ping 192.168.5.22', label: 'Clerk pings a Works PC', legit: true },
        { src: 'PC10', cmd: 'ping 192.168.4.18', label: 'IT administrator (Management) checks the Account PC', legit: true }
      ]
    },
    {
      tag: 'Hacking network devices', title: 'Staff try to take over the router and switch',
      story: 'Whoever controls the router can rewrite every rule in it. Only the Management VLAN should ever log in to network devices, and only over encrypted SSH.',
      controls: 'R1 line vty access-class 10, transport input ssh, ACLs protecting 192.168.1.0/24',
      steps: [
        { src: 'PC22', cmd: 'ssh -l admin 192.168.5.1', label: 'Works PC opens SSH to its own gateway (R1)' },
        { src: 'PC22', cmd: 'ping 192.168.1.2', label: 'Works PC reaches the switch management address' },
        { src: 'PC22', cmd: 'telnet 192.168.5.1', label: 'Works PC tries clear-text Telnet instead' },
        { src: 'PC10', cmd: 'ssh -l admin 192.168.1.1', label: 'Administrator logs in from Management', legit: true }
      ]
    },
    {
      tag: 'External hacking · scanning', title: 'A hacker on the Internet probes the company',
      story: 'The attacker knows the company\'s public address range and scans it for a way in: internal PCs, the firewall itself, and other services on the public server.',
      controls: 'ASA security levels, NAT/PAT, access-group OUTSIDE-DMZ',
      steps: [
        { src: 'Attacker-PC', cmd: 'ping 192.168.4.18', label: 'Ping an internal Account PC directly' },
        { src: 'Attacker-PC', cmd: 'ssh -l admin 209.165.200.226', label: 'Log in to the firewall\'s public address' },
        { src: 'Attacker-PC', cmd: 'telnet 209.165.200.227 21', label: 'Connect to FTP on the public web server' },
        { src: 'Attacker-PC', cmd: 'browse http://209.165.200.227', label: 'Open the public company website', legit: true }
      ]
    },
    {
      tag: 'Physical intrusion · rogue device', title: 'An intruder plugs a laptop into the Account hub', rogue: true,
      story: 'Someone walks into the Account office and connects their own laptop (192.168.4.66) to the department hub, hoping to reach the rest of the network.',
      controls: 'Switch0 port security: sticky MACs, maximum 4, violation restrict',
      steps: [
        { src: 'Rogue-Laptop', cmd: 'ping 192.168.4.1', label: 'Laptop pings the Account gateway' },
        { src: 'Rogue-Laptop', cmd: 'browse http://209.165.201.10', label: 'Laptop tries to reach the Internet' },
        { src: 'Rogue-Laptop', cmd: 'ping 192.168.4.19', label: 'Laptop pings an Account PC on the same hub' }
      ],
      lesson: 'Port security stops the laptop at Switch0, but a hub repeats every frame to every port, so PCs on the same hub are still exposed. Replacing the hubs with access switches (one switch port per PC) closes this gap.'
    },
    {
      tag: 'Compromised server · pivoting', title: 'A hacked web server is used to attack staff',
      story: 'Public servers are the most exposed machines. If the DMZ web server is taken over, the attacker will try to use it as a stepping stone to internal PCs.',
      controls: 'ASA DMZ zone (security 70) with "no forward interface Vlan1"',
      steps: [
        { src: 'DMZ-Server', cmd: 'ping 192.168.1.10', label: 'DMZ server pings a Management PC' },
        { src: 'DMZ-Server', cmd: 'telnet 192.168.4.18 80', label: 'DMZ server connects to an Account PC' },
        { src: 'DMZ-Server', cmd: 'ping 209.165.201.10', label: 'DMZ server reaches the Internet', legit: true }
      ],
      lesson: 'The results are the same with the toggles off because DMZ isolation comes from the ASA zones themselves, which stay on in both runs.'
    },
    {
      tag: 'Least privilege', title: 'Staff get the services they need, nothing more',
      story: 'Extended ACLs filter by service, not just by address: Maintenance staff may use the company website and DNS, but nothing else on the DMZ server.',
      controls: 'R1 ACL VLAN3-MAINT-IN, lines 50 to 70',
      steps: [
        { src: 'PC16', cmd: 'browse http://www.cyberlab.com', label: 'Open the company website by name (DNS + HTTP)', legit: true },
        { src: 'PC16', cmd: 'ping 172.16.50.10', label: 'Ping the DMZ server' },
        { src: 'PC16', cmd: 'telnet 172.16.50.10 21', label: 'Connect to FTP on the DMZ server' },
        { src: 'PC16', cmd: 'browse http://www.internet.com', label: 'Browse the Internet', legit: true }
      ]
    }
  ];

  function renderScenarios() {
    const html = SCENARIOS.map((sc, i) => {
      const sec = makeNet(state.controls, !!sc.rogue);
      const open = makeNet(ALL_OFF, !!sc.rogue);
      let attacks = 0, blockedSec = 0, blockedOpen = 0, legit = 0, legitOk = 0;
      const rows = sc.steps.map((st, j) => {
        const a = dryRun(sec, st.src, st.cmd), b = dryRun(open, st.src, st.cmd);
        const ao = isOk(a), bo = isOk(b);
        if (st.legit) { legit++; if (ao) legitOk++; } else { attacks++; if (!ao) blockedSec++; if (!bo) blockedOpen++; }
        const why = ao ? '' : (a.reason || a.note || '');
        return `<tr><td>${esc(st.label)}<br><code>${esc(st.src)}: ${esc(st.cmd)}</code>${st.legit ? ' <span class="why">legitimate traffic</span>' : ''}</td>
          <td class="res ${ao ? 'ok' : 'bad'}">${ao ? '✓ succeeds' : '✕ ' + esc(blocker(a))}${why ? `<span class="why">${esc(why)}</span>` : ''}</td>
          <td class="res ${bo ? 'ok' : 'bad'}">${bo ? '✓ succeeds' : '✕ ' + esc(blocker(b))}</td>
          <td><button class="btn small" type="button" data-watch="${i}:${j}">Watch</button></td></tr>`;
      }).join('');
      const custom = JSON.stringify(state.controls) !== JSON.stringify(ALL_ON);
      const verdictText = `${custom ? 'With your current controls' : 'Secured'}: ${blockedSec} of ${attacks} attack step${attacks === 1 ? '' : 's'} blocked${legit ? `, ${legitOk} of ${legit} legitimate step${legit === 1 ? ' still works' : 's still work'}` : ''}. Without the controls: ${blockedOpen} of ${attacks} blocked.`;
      return `<article class="card scen">
        <span class="tag">${esc(sc.tag)}</span>
        <h3>${esc(sc.title)}</h3>
        <p>${esc(sc.story)}</p>
        <p class="controls-used">Control under test: <b>${esc(sc.controls)}</b></p>
        <div class="table-scroll"><table class="steps"><thead><tr><th>Step</th><th>${custom ? 'Current config' : 'Secured network'}</th><th>Controls off</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
        <div class="verdict">${esc(verdictText)}</div>
        ${sc.lesson ? `<p>${esc(sc.lesson)}</p>` : ''}
      </article>`;
    }).join('');
    $('#scenarioList').innerHTML = html;
    $$('#scenarioList [data-watch]').forEach((b) => b.addEventListener('click', () => {
      const [i, j] = b.dataset.watch.split(':').map(Number);
      const sc = SCENARIOS[i], st = sc.steps[j];
      if (!!sc.rogue !== state.rogue) { state.rogue = !!sc.rogue; rebuild(); }
      watch(st.src, st.cmd);
    }));
  }

  // ================================================================ build kit
  function renderKit() {
    const hosts = Object.entries(T.devices).filter(([, d]) => d.ip);
    const ptPlace = [
      ['Network Devices › Routers › 1841', 'R1, ISP', 2],
      ['Network Devices › Switches › 2960 (2960-24TT)', 'Switch0, ISP-Switch', 2],
      ['Network Devices › Security › 5505 (ASA 5505)', 'ASA1', 1],
      ['Network Devices › Hubs › Hub-PT', 'Hub0, Hub1, Hub2, Hub3, Hub4', 5],
      ['End Devices › PC-PT', 'PC10-PC16, PC18-PC24 (there is no PC17), Attacker-PC', 15],
      ['End Devices › Printer-PT', 'Printer0-Printer4', 5],
      ['End Devices › Server-PT', 'DMZ-Server, Internet-Server', 2],
      ['End Devices › Laptop-PT (optional)', 'Rogue-Laptop, only for the port-security test', 1]
    ];
    const cable = { straight: 'Copper Straight-Through', cross: 'Copper Cross-Over' };
    const cfgCards = [
      ['R1', 'Cisco 1841 · inter-VLAN routing, ACLs, SSH', 'Click R1 › CLI. Answer <code>no</code> to the setup dialog, press Enter, then paste.'],
      ['Switch0', 'Cisco 2960-24TT · VLANs, trunk, port security', 'Click Switch0 › CLI, press Enter, then paste.'],
      ['ASA1', 'Cisco ASA 5505 · zones, NAT, firewall policy', 'Click ASA1 › CLI. Type <code>enable</code> and press Enter at the blank password prompt, then paste.'],
      ['ISP', 'Cisco 1841 · simulated Internet provider', 'Click ISP › CLI. Answer <code>no</code> to the setup dialog, press Enter, then paste.']
    ];
    const checks = [
      ['PC13', 'ping 192.168.2.1', 'Replies (own gateway)'],
      ['PC13', 'ping 192.168.5.21', 'First packet may time out (ARP), then replies'],
      ['PC13', 'ping 192.168.4.18', 'Destination host unreachable (ACL VLAN2-ADMIN-IN line 40)'],
      ['PC21', 'ping 192.168.1.10', 'Destination host unreachable (Management is protected)'],
      ['PC10', 'ping 192.168.4.18', 'Replies (Management may reach every department)'],
      ['PC18', 'ping 192.168.2.13', 'Destination host unreachable (Account is isolated)'],
      ['PC16', 'Web Browser › http://www.cyberlab.com', 'Company page loads (DNS + HTTP allowed)'],
      ['PC16', 'ping 172.16.50.10', 'Destination host unreachable (only web and DNS allowed)'],
      ['PC22', 'ssh -l admin 192.168.5.1', '% Connection refused (VTY access-class 10)'],
      ['PC10', 'ssh -l admin 192.168.1.1', 'Password prompt; log in with admin / Admin@2026'],
      ['PC10', 'ping 209.165.201.10', 'Replies through ASA PAT (first one or two may time out)'],
      ['Attacker-PC', 'Web Browser › http://209.165.200.227', 'Company page loads (static NAT, ACL OUTSIDE-DMZ)'],
      ['Attacker-PC', 'ping 192.168.4.18', 'Destination host unreachable from the ISP (private address)'],
      ['DMZ-Server', 'ping 192.168.1.10', 'Request timed out (no forward interface Vlan1)'],
      ['Switch0', 'show port-security', 'Fa0/1-Fa0/5 secured, violation Restrict'],
      ['Rogue-Laptop', 'connect to Hub2 Port 5, then ping 192.168.4.1', 'Request timed out; Switch0 show port-security shows violations on Fa0/4']
    ];
    const done = store.get('checks', {});
    const changes = [
      ['IP address clash', 'The report gives the ASA inside interface 192.168.1.1 and outside 192.168.2.1, the same addresses as R1 Fa0/0.1 and Fa0/0.2. The ASA now sits on its own links: inside 172.16.0.2/30 to R1, outside 209.165.200.226/29 to the ISP, DMZ 172.16.50.1/24.'],
      ['Diagram labels', 'Figure 3.4 labels VLANs 2-5 as 192.16.x.0/24; the configs use 192.168.x.0/24. Use 192.168.x.0/24 everywhere.'],
      ['Trunk and access ports', 'Section 3.4 sets Fa0/24 to access VLAN 1, then access VLAN 2, then trunk. Here Fa0/1-Fa0/5 are access ports (one per department hub) and only Fa0/24 is the 802.1Q trunk to R1.'],
      ['VLAN names', 'The report names VLANs pc10-pc13. They are now named after departments; VLAN 1 must stay "default" because IOS cannot rename it.'],
      ['Native VLAN 1', 'R1 Fa0/0.1 uses "encapsulation dot1Q 1 native" so untagged Management traffic on the trunk is handled correctly.'],
      ['Extended ACLs', 'Chapter 5 says extended ACLs were used, but none are configured in Chapter 3 or 4. Four named ACLs now enforce the department policy.'],
      ['Management weakness', 'Section 5.2 notes that VLAN 1 (management) stayed reachable. The ACLs now block every department except Management from 192.168.1.0/24, and VTY logins are limited to Management over SSH.'],
      ['DMZ "no forward"', 'Section 4.4(c) mentions "no forward interface vlan 1" for the third ASA VLAN. It is configured on Vlan3 (dmz) before nameif, as the ASA 5505 base licence requires.'],
      ['First ping fails', 'Section 4.4(b) says the first message fails because of authorisation. The real cause is ARP: the router drops the first packet while it learns the destination MAC address. Later pings succeed.']
    ];
    $('#kit').innerHTML = `
      <nav class="card" aria-label="Build steps">
        <a href="#k1">1 · Place the devices</a><a href="#k2">2 · Cable them</a><a href="#k3">3 · Address the hosts</a><a href="#k4">4 · Paste the configs</a>
        <a href="#k5">5 · Set up the servers</a><a href="#k6">6 · Verify</a><a href="#k7">7 · Changes from the report</a><a href="#k8">8 · Defence demo</a>
      </nav>
      <div>
        <section class="card" id="k1"><h3><span class="num">1</span>Place the devices</h3>
          <p class="lead">Drag each device onto the workspace and rename it (click the device › Config › Display Name). Lay them out like the topology in the Simulator tab.</p>
          <div class="table-scroll"><table class="plain"><thead><tr><th>Packet Tracer location</th><th>Names</th><th>Qty</th></tr></thead><tbody>
          ${ptPlace.map((r) => `<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td><td>${r[2]}</td></tr>`).join('')}</tbody></table></div></section>

        <section class="card" id="k2"><h3><span class="num">2</span>Cable them</h3>
          <p class="lead">Choose the cable type yourself rather than the automatic lightning cable, so every device lands on the port the configs expect.</p>
          <div class="table-scroll"><table class="plain"><thead><tr><th>From</th><th>Port</th><th>To</th><th>Port</th><th>Cable</th></tr></thead><tbody>
          ${T.links.map((l) => `<tr><td>${esc(l[0])}</td><td class="mono">${esc(l[1])}</td><td>${esc(l[2])}</td><td class="mono">${esc(l[3])}</td><td>${esc(cable[l[4]])}${l[5] === 'optional' ? ' <em>(test only)</em>' : ''}</td></tr>`).join('')}</tbody></table></div></section>

        <section class="card" id="k3"><h3><span class="num">3</span>Address the hosts</h3>
          <p class="lead">For each PC, printer and server: click it › Desktop › IP Configuration › Static (printers: Config › FastEthernet0 and Config › Settings for the gateway).</p>
          <div class="table-scroll"><table class="plain"><thead><tr><th>Device</th><th>Zone</th><th>IPv4</th><th>Mask</th><th>Gateway</th><th>DNS</th></tr></thead><tbody>
          ${hosts.map(([n, d]) => { const z = T.zones.find((x) => x.id === d.zone); return `<tr><td>${esc(n)}</td><td>${esc(z ? z.label : '')}</td><td class="mono">${esc(d.ip)}</td><td class="mono">${esc(d.mask)}</td><td class="mono">${esc(d.gw || '')}</td><td class="mono">${esc(d.dns || '')}</td></tr>`; }).join('')}</tbody></table></div></section>

        <section class="card" id="k4"><h3><span class="num">4</span>Paste the configs</h3>
          <p class="lead">Copy each block and paste it into the device CLI (right-click › Paste, or Ctrl+V). The same files are in <code>packet-tracer/configs/</code>. Lab passwords: enable <code>Cyber@2026</code>, console <code>Console@2026</code>, SSH user <code>admin</code> / <code>Admin@2026</code>.</p>
          <div class="cfg-grid">${cfgCards.map(([n, sub, how]) => `
            <div class="cfg"><header><div><b>${n}</b><br><small>${esc(sub)}</small></div><span class="spacer"></span>
              <button class="btn small" type="button" data-copy="${n}">Copy</button><button class="btn small" type="button" data-dl="${n}">Download .txt</button></header>
              <p class="note" style="margin:10px 12px 0">${how}</p>
              <pre style="margin-top:10px">${highlight(C[n])}</pre></div>`).join('')}</div></section>

        <section class="card" id="k5"><h3><span class="num">5</span>Set up the servers</h3>
          <ol>
            <li><b>DMZ-Server</b> › Services › HTTP: On. Edit <code>index.html</code> to say "Welcome to CyberLab Ltd".</li>
            <li><b>DMZ-Server</b> › Services › DNS: On. Add A records <code>www.cyberlab.com → 172.16.50.10</code> and <code>www.internet.com → 209.165.201.10</code>.</li>
            <li><b>Internet-Server</b> › Services › HTTP: On. Edit <code>index.html</code> to say "Public Internet website". Turn DNS off.</li>
            <li>Leave FTP on (the default) on DMZ-Server: it shows that the firewall only lets the Internet reach the web service.</li>
            <li>Ping every PC and printer once (for example from PC10) so Switch0 learns their sticky MAC addresses before you connect the rogue laptop.</li>
          </ol></section>

        <section class="card" id="k6"><h3><span class="num">6</span>Verify</h3>
          <p class="lead">Run these in Packet Tracer and tick them off. The simulator gives the same results. Ticks are saved in this browser.</p>
          <ul class="check">${checks.map((c, i) => `<li><input type="checkbox" data-check="${i}" ${done[i] ? 'checked' : ''} aria-label="Done"><div><b>${esc(c[0])}</b> › <code>${esc(c[1])}</code><div class="exp">Expected: ${esc(c[2])}</div></div></li>`).join('')}</ul></section>

        <section class="card" id="k7"><h3><span class="num">7</span>Changes from the report</h3>
          <p class="lead">These fix problems in the configs printed in Chapters 3 and 4. They are worth knowing in case an examiner compares the two.</p>
          <div class="table-scroll"><table class="plain"><tbody>${changes.map((c) => `<tr><td style="white-space:nowrap;vertical-align:top"><b>${esc(c[0])}</b></td><td style="white-space:normal">${esc(c[1])}</td></tr>`).join('')}</tbody></table></div></section>

        <section class="card" id="k8"><h3><span class="num">8</span>Defence demo (about 5 minutes)</h3>
          <ol>
            <li>Show the topology: five department VLANs on Switch0, R1 router-on-a-stick, ASA firewall with DMZ and Internet.</li>
            <li>On Switch0 run <code>show vlan brief</code> and <code>show interfaces trunk</code>: segmentation and the 802.1Q trunk.</li>
            <li>From PC13 ping a Works PC (allowed), then an Account PC (blocked). On R1 run <code>show access-lists</code> and point at the match counter on line 40.</li>
            <li>From PC10 (Management) ping the same Account PC: administrators still have access.</li>
            <li>From PC22 try <code>ssh -l admin 192.168.5.1</code>: refused. From PC10: accepted.</li>
            <li>From Attacker-PC open <code>http://209.165.200.227</code> (works), then ping 192.168.4.18 (unreachable).</li>
            <li>Connect Rogue-Laptop to Hub2 and ping its gateway: dropped by port security.</li>
          </ol></section>
      </div>`;
    $$('[data-copy]').forEach((b) => b.addEventListener('click', () => copyText(C[b.dataset.copy], b)));
    $$('[data-dl]').forEach((b) => b.addEventListener('click', () => download(b.dataset.dl + '.txt', C[b.dataset.dl])));
    $$('[data-check]').forEach((i) => i.addEventListener('change', () => { const d = store.get('checks', {}); d[i.dataset.check] = i.checked; store.set('checks', d); }));
    $('#printKit').addEventListener('click', () => { showTab('build'); window.print(); });
  }
  function highlight(text) {
    return String(text).split('\n').map((l) => (l.trim().startsWith('!') ? `<span class="c">${esc(l)}</span>` : esc(l))).join('\n');
  }
  function copyText(text, btn) {
    const done = () => { const o = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = o; }, 1400); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
    else fallbackCopy(text, done);
  }
  function fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* ignore */ }
    ta.remove();
  }
  function download(name, text) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text.replace(/\n/g, '\r\n')], { type: 'text/plain' }));
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ================================================================ start
  renderTopology();
  renderControls();
  renderConsole();
  renderScenarios();
  renderKit();
  const hashTab = location.hash.replace('#', '');
  const startTab = ['sim', 'matrix', 'scenarios', 'build'].includes(hashTab) ? hashTab : store.get('tab', 'sim');
  if (['sim', 'matrix', 'scenarios', 'build'].includes(startTab)) showTab(startTab);
})();
