/*
 * SecureNet VLAN Lab - network simulation engine.
 *
 * The engine parses the same Cisco configuration files that are pasted into
 * Packet Tracer (R1, Switch0, ASA1, ISP) and walks every packet through them:
 * hubs, 802.1Q access/trunk ports, port security, router sub-interfaces,
 * extended/standard ACLs, VTY access-class, ASA security levels, "no forward",
 * NAT/PAT and stateful inspection. Nothing about who may talk to whom is
 * hard-coded here; change a config file and the results change with it.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.NetEngine = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ------------------------------------------------------------------ helpers
  const ipToInt = (s) => String(s).split('.').reduce((a, o) => ((a << 8) | (Number(o) & 255)) >>> 0, 0) >>> 0;
  const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
  const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s).trim());
  const maskToPrefix = (m) => { let n = ipToInt(m), c = 0; while (n & 0x80000000) { c++; n = (n << 1) >>> 0; } return c; };
  const sameNet = (a, b, mask) => ((ipToInt(a) & ipToInt(mask)) >>> 0) === ((ipToInt(b) & ipToInt(mask)) >>> 0);
  const netOf = (ip, mask) => intToIp((ipToInt(ip) & ipToInt(mask)) >>> 0);
  const inRange = (ip, net, mask) => ((ipToInt(ip) & ipToInt(mask)) >>> 0) === ((ipToInt(net) & ipToInt(mask)) >>> 0);

  const PORTS = { www: 80, http: 80, https: 443, domain: 53, dns: 53, ftp: 21, 'ftp-data': 20, telnet: 23, ssh: 22, smtp: 25, pop3: 110, tftp: 69, bootps: 67, bootpc: 68, snmp: 161, ntp: 123 };
  const SERVICE_NAMES = { 80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 21: 'FTP', 23: 'Telnet', 22: 'SSH', 25: 'SMTP', 110: 'POP3', 69: 'TFTP' };
  const portNum = (t) => (/^\d+$/.test(t) ? Number(t) : PORTS[String(t).toLowerCase()]);
  const ICMP_TYPES = ['echo', 'echo-reply', 'unreachable', 'time-exceeded'];

  function canonIf(name) {
    const s = String(name).trim();
    const m = s.match(/^([a-zA-Z-]+)\s*([\d/.]+)$/);
    if (!m) return s;
    const t = m[1].toLowerCase();
    let full = m[1];
    if (t.startsWith('f')) full = 'FastEthernet';
    else if (t.startsWith('g')) full = 'GigabitEthernet';
    else if (t.startsWith('e')) full = 'Ethernet';
    else if (t.startsWith('v')) full = 'Vlan';
    return full + m[2];
  }
  function shortIf(name, asa) {
    return String(name)
      .replace(/^FastEthernet/, 'Fa')
      .replace(/^GigabitEthernet/, 'Gi')
      .replace(/^Ethernet/, asa ? 'Et' : 'Eth');
  }
  function macOf(key) {
    let h1 = 0x811c9dc5, h2 = 0x12345678;
    for (let i = 0; i < key.length; i++) {
      h1 = Math.imul(h1 ^ key.charCodeAt(i), 16777619) >>> 0;
      h2 = Math.imul(h2 ^ key.charCodeAt(i), 2246822519) >>> 0;
    }
    const hex = ('0000' + (h2 & 0xffff).toString(16)).slice(-4) + ('00000000' + h1.toString(16)).slice(-8);
    const prefix = ['0001', '0002', '0004', '0005', '0006', '0009', '000A', '0030', '0050', '0060', '00D0', '00E0'][h2 % 12];
    return (prefix + '.' + hex.slice(4, 8) + '.' + hex.slice(8, 12)).toUpperCase();
  }
  function expandRange(spec) {
    // "FastEthernet0/6 - 23" or "Fa0/1 - 5, Gi0/1 - 2"
    const out = [];
    for (const part of spec.split(',')) {
      const p = part.trim();
      const m = p.match(/^([a-zA-Z]+)\s*(\d+\/)(\d+)\s*(?:-\s*(\d+))?$/);
      if (!m) { out.push(canonIf(p)); continue; }
      const a = Number(m[3]), b = m[4] ? Number(m[4]) : a;
      for (let i = a; i <= b; i++) out.push(canonIf(m[1] + m[2] + i));
    }
    return out;
  }

  // ---------------------------------------------------------------- ACL logic
  function parseAce(tokens, maskStyle) {
    let i = 0;
    const action = tokens[i++].toLowerCase();
    const proto = tokens[i++].toLowerCase();
    const addr = () => {
      const t = tokens[i++];
      if (t === undefined) return { addr: 0, wild: 0xffffffff, text: 'any' };
      if (t === 'any') return { addr: 0, wild: 0xffffffff, text: 'any' };
      if (t === 'host') { const a = tokens[i++]; return { addr: ipToInt(a), wild: 0, text: 'host ' + a }; }
      const m = tokens[i] && isIp(tokens[i]) ? tokens[i++] : (maskStyle === 'mask' ? '255.255.255.255' : '0.0.0.0');
      let wild = ipToInt(m);
      if (maskStyle === 'mask') wild = (~wild) >>> 0;
      return { addr: ipToInt(t), wild, text: t + ' ' + m };
    };
    const port = () => {
      const t = tokens[i];
      if (['eq', 'neq', 'gt', 'lt'].includes(t)) { i++; return { op: t, a: portNum(tokens[i++]) }; }
      if (t === 'range') { i++; const a = portNum(tokens[i++]); const b = portNum(tokens[i++]); return { op: 'range', a, b }; }
      return null;
    };
    const l4 = proto === 'tcp' || proto === 'udp';
    const src = addr();
    const sport = l4 ? port() : null;
    const dst = addr();
    const dport = l4 ? port() : null;
    let icmpType = null, established = false;
    while (i < tokens.length) {
      const t = String(tokens[i++]).toLowerCase();
      if (proto === 'icmp' && ICMP_TYPES.includes(t)) icmpType = t;
      else if (t === 'established') established = true;
    }
    return { action, proto, src, sport, dst, dport, icmpType, established, text: tokens.join(' ') };
  }
  function parseStdAce(tokens) {
    // permit 192.168.1.0 0.0.0.255 | permit host X | permit any | permit X
    const action = tokens[0].toLowerCase();
    let src;
    if (tokens[1] === 'any') src = { addr: 0, wild: 0xffffffff, text: 'any' };
    else if (tokens[1] === 'host') src = { addr: ipToInt(tokens[2]), wild: 0, text: 'host ' + tokens[2] };
    else src = { addr: ipToInt(tokens[1]), wild: tokens[2] ? ipToInt(tokens[2]) : 0, text: tokens[1] + (tokens[2] ? ' ' + tokens[2] : '') };
    return { action, proto: 'ip', src, dst: { addr: 0, wild: 0xffffffff, text: 'any' }, sport: null, dport: null, icmpType: null, established: false, text: tokens.join(' '), standard: true };
  }
  const addrMatch = (spec, ip) => ((((ipToInt(ip) ^ spec.addr) & ~spec.wild) >>> 0) === 0);
  function portMatch(spec, p) {
    if (!spec) return true;
    if (p === undefined || p === null) return false;
    switch (spec.op) {
      case 'eq': return p === spec.a;
      case 'neq': return p !== spec.a;
      case 'gt': return p > spec.a;
      case 'lt': return p < spec.a;
      case 'range': return p >= spec.a && p <= spec.b;
      default: return true;
    }
  }
  function aceMatches(ace, pkt) {
    if (ace.proto !== 'ip' && ace.proto !== pkt.proto) return false;
    if (!addrMatch(ace.src, pkt.src)) return false;
    if (!addrMatch(ace.dst, pkt.dst)) return false;
    if (ace.proto === 'tcp' || ace.proto === 'udp') {
      if (!portMatch(ace.sport, pkt.sport)) return false;
      if (!portMatch(ace.dport, pkt.dport)) return false;
      if (ace.established && !(pkt.flags && (pkt.flags.ack || pkt.flags.rst))) return false;
    }
    if (ace.proto === 'icmp' && ace.icmpType && ace.icmpType !== pkt.icmpType) return false;
    return true;
  }

  // ------------------------------------------------------------ config parser
  function newIf(name, kind) {
    const isSub = name.includes('.');
    return {
      name,
      description: '',
      ip: null, mask: null,
      shutdown: kind === 'router' && !isSub,
      parent: isSub ? name.split('.')[0] : null,
      encap: null, native: false,
      aclIn: null, aclOut: null,
      mode: 'access', accessVlan: 1, trunkAllowed: null, nativeVlan: 1, nonegotiate: false,
      portSecurity: null, portfast: false, bpduguard: false,
      nameif: null, secLevel: 0, noForward: []
    };
  }
  function vlanList(spec) {
    const out = new Set();
    for (const part of String(spec).split(',')) {
      const [a, b] = part.split('-').map(Number);
      for (let v = a; v <= (b || a); v++) out.add(v);
    }
    return out;
  }

  function parseConfig(text, kind) {
    const cfg = {
      kind, hostname: kind === 'asa' ? 'ciscoasa' : (kind === 'switch' ? 'Switch' : 'Router'),
      interfaces: {}, routes: [], acls: {}, vlans: {}, lines: { con: {}, vty: {} },
      defaultGateway: null, domain: null, cryptoKey: false, sshVersion: null, users: {},
      objects: {}, accessGroups: {}, inspect: new Set(), asaSsh: [], enableSecret: false,
      passwordEncryption: false, banner: null, loginBlock: null, minLength: null
    };
    const getIf = (n) => (cfg.interfaces[n] = cfg.interfaces[n] || newIf(n, kind));
    if (kind === 'switch') {
      cfg.vlans[1] = { name: 'default' };
      for (let i = 1; i <= 24; i++) getIf('FastEthernet0/' + i);
      getIf('GigabitEthernet0/1'); getIf('GigabitEthernet0/2');
    }
    if (kind === 'asa') {
      for (let i = 0; i <= 7; i++) { const p = getIf('Ethernet0/' + i); p.accessVlan = i === 0 ? 2 : 1; }
    }
    if (!text) return cfg;

    let ctx = null;
    const handleSub = (w, lw) => {
      const c = ctx;
      if (lw[0] === 'exit') { ctx = c.parent || null; return true; }
      if (c.t === 'if') {
        const all = (fn) => { c.ifs.forEach(fn); return true; };
        const k = lw.join(' ');
        if (lw[0] === 'description') return all((f) => { f.description = w.slice(1).join(' '); });
        if (k.startsWith('ip address') && isIp(w[2])) return all((f) => { f.ip = w[2]; f.mask = w[3]; });
        if (k.startsWith('ip address dhcp')) return all((f) => { f.ip = null; f.dhcp = true; });
        if (k === 'no ip address') return all((f) => { f.ip = null; f.mask = null; });
        if (k === 'shutdown') return all((f) => { f.shutdown = true; });
        if (k === 'no shutdown') return all((f) => { f.shutdown = false; });
        if (lw[0] === 'encapsulation' && lw[1] === 'dot1q') return all((f) => { f.encap = Number(w[2]); f.native = lw[3] === 'native'; });
        if (k.startsWith('ip access-group')) return all((f) => { if (lw[3] === 'out') f.aclOut = w[2]; else f.aclIn = w[2]; });
        if (k.startsWith('no ip access-group')) return all((f) => { if (lw[4] === 'out') f.aclOut = null; else f.aclIn = null; });
        if (k === 'switchport mode access') return all((f) => { f.mode = 'access'; });
        if (k === 'switchport mode trunk') return all((f) => { f.mode = 'trunk'; });
        if (k.startsWith('switchport access vlan')) return all((f) => { f.accessVlan = Number(w[3]); });
        if (k.startsWith('switchport trunk allowed vlan')) return all((f) => { f.trunkAllowed = vlanList(w[4]); });
        if (k.startsWith('switchport trunk native vlan')) return all((f) => { f.nativeVlan = Number(w[4]); });
        if (k === 'switchport nonegotiate') return all((f) => { f.nonegotiate = true; });
        if (k === 'switchport port-security') return all((f) => { f.portSecurity = f.portSecurity || { max: 1, sticky: false, violation: 'shutdown' }; });
        if (k.startsWith('switchport port-security maximum')) return all((f) => { f.portSecurity = f.portSecurity || { max: 1, sticky: false, violation: 'shutdown' }; f.portSecurity.max = Number(w[3]); });
        if (k.startsWith('switchport port-security mac-address sticky')) return all((f) => { f.portSecurity = f.portSecurity || { max: 1, sticky: false, violation: 'shutdown' }; f.portSecurity.sticky = true; });
        if (k.startsWith('switchport port-security violation')) return all((f) => { f.portSecurity = f.portSecurity || { max: 1, sticky: false, violation: 'shutdown' }; f.portSecurity.violation = lw[3]; });
        if (k === 'spanning-tree portfast') return all((f) => { f.portfast = true; });
        if (k === 'spanning-tree bpduguard enable') return all((f) => { f.bpduguard = true; });
        if (lw[0] === 'nameif') return all((f) => { f.nameif = w[1]; });
        if (lw[0] === 'security-level') return all((f) => { f.secLevel = Number(w[1]); });
        if (k.startsWith('no forward interface')) return all((f) => { f.noForward.push(canonIf(w[3])); });
        return false;
      }
      if (c.t === 'acl') {
        if (lw[0] === 'remark') { c.acl.remarks.push({ before: c.acl.entries.length, text: w.slice(1).join(' ') }); return true; }
        if (lw[0] === 'permit' || lw[0] === 'deny') {
          const ace = parseAce(w, 'wild');
          ace.seq = (c.acl.entries.length + 1) * 10;
          c.acl.entries.push(ace);
          return true;
        }
        return false;
      }
      if (c.t === 'vlan') { if (lw[0] === 'name') { cfg.vlans[c.id].name = w[1]; return true; } return false; }
      if (c.t === 'line') {
        const L = cfg.lines[c.which];
        if (lw[0] === 'password') { L.password = true; return true; }
        if (lw[0] === 'login') { L.login = lw[1] === 'local' ? 'local' : 'line'; return true; }
        if (lw[0] === 'exec-timeout' || lw[0] === 'logging') return true;
        if (lw[0] === 'access-class') { L.accessClass = w[1]; return true; }
        if (lw[0] === 'transport' && lw[1] === 'input') { L.transport = lw.slice(2); return true; }
        return false;
      }
      if (c.t === 'obj') {
        if (lw[0] === 'subnet') { c.obj.net = w[1]; c.obj.mask = w[2]; return true; }
        if (lw[0] === 'host') { c.obj.net = w[1]; c.obj.mask = '255.255.255.255'; return true; }
        if (lw[0] === 'nat') {
          const m = t => t.replace(/[()]/g, '');
          const [real, mapped] = m(w[1]).split(',');
          c.obj.nat = { real, mapped, type: lw[2], mappedAddr: w[3] };
          return true;
        }
        return false;
      }
      if (c.t === 'classmap') { if (lw[0] === 'match') return true; return false; }
      if (c.t === 'policymap') {
        if (lw[0] === 'class') { ctx = { t: 'pclass', parent: c }; return true; }
        return false;
      }
      if (c.t === 'pclass') {
        if (lw[0] === 'inspect') { cfg.inspect.add(lw.slice(1).join(' ')); return true; }
        return false;
      }
      return false;
    };

    for (const raw of String(text).split(/\r?\n/)) {
      const t = raw.trim();
      if (!t || t.startsWith('!')) continue;
      const w = t.split(/\s+/);
      const lw = w.map((x) => x.toLowerCase());
      if (ctx && handleSub(w, lw)) continue;
      ctx = null;
      const k = lw.join(' ');
      if (lw[0] === 'hostname') cfg.hostname = w[1];
      else if (lw[0] === 'interface' && lw[1] === 'range') ctx = { t: 'if', ifs: expandRange(w.slice(2).join(' ')).map(getIf) };
      else if (lw[0] === 'interface') ctx = { t: 'if', ifs: [getIf(canonIf(w.slice(1).join('')))] };
      else if (k.startsWith('ip access-list extended') || k.startsWith('ip access-list standard')) {
        const name = w[3];
        cfg.acls[name] = cfg.acls[name] || { name, type: lw[2], entries: [], remarks: [] };
        ctx = { t: 'acl', acl: cfg.acls[name] };
      } else if (lw[0] === 'access-list' && /^\d+$/.test(w[1])) {
        const name = w[1];
        cfg.acls[name] = cfg.acls[name] || { name, type: Number(name) < 100 ? 'standard' : 'extended', entries: [], remarks: [] };
        const acl = cfg.acls[name];
        if (lw[2] === 'remark') acl.remarks.push({ before: acl.entries.length, text: w.slice(3).join(' ') });
        else {
          const ace = acl.type === 'standard' ? parseStdAce(w.slice(2)) : parseAce(w.slice(2), 'wild');
          ace.seq = (acl.entries.length + 1) * 10;
          acl.entries.push(ace);
        }
      } else if (lw[0] === 'access-list' && lw[2] === 'extended') {
        const name = w[1];
        cfg.acls[name] = cfg.acls[name] || { name, type: 'extended', asa: true, entries: [], remarks: [] };
        const ace = parseAce(w.slice(3), 'mask');
        ace.seq = cfg.acls[name].entries.length + 1;
        cfg.acls[name].entries.push(ace);
      } else if (lw[0] === 'access-group') cfg.accessGroups[w[4]] = w[1];
      else if (lw[0] === 'vlan' && /^\d+$/.test(w[1])) { const id = Number(w[1]); cfg.vlans[id] = cfg.vlans[id] || { name: 'VLAN' + String(id).padStart(4, '0') }; ctx = { t: 'vlan', id }; }
      else if (lw[0] === 'line') { ctx = { t: 'line', which: lw[1] === 'vty' ? 'vty' : 'con' }; }
      else if (lw[0] === 'ip' && lw[1] === 'route') cfg.routes.push({ net: w[2], mask: w[3], gw: w[4] });
      else if (lw[0] === 'route' && w.length >= 5) cfg.routes.push({ nameif: w[1], net: w[2], mask: w[3], gw: w[4] });
      else if (k.startsWith('ip default-gateway')) cfg.defaultGateway = w[2];
      else if (k.startsWith('ip domain-name') || lw[0] === 'domain-name') cfg.domain = w[w.length - 1];
      else if (k.startsWith('crypto key generate rsa')) cfg.cryptoKey = true;
      else if (k.startsWith('ip ssh version')) cfg.sshVersion = Number(w[3]);
      else if (lw[0] === 'username') cfg.users[w[1]] = true;
      else if (lw[0] === 'object' && lw[1] === 'network') { cfg.objects[w[2]] = cfg.objects[w[2]] || { name: w[2] }; ctx = { t: 'obj', obj: cfg.objects[w[2]] }; }
      else if (lw[0] === 'class-map') ctx = { t: 'classmap' };
      else if (lw[0] === 'policy-map') ctx = { t: 'policymap' };
      else if (lw[0] === 'ssh' && isIp(w[1])) cfg.asaSsh.push({ net: w[1], mask: w[2], nameif: w[3] });
      else if (k.startsWith('enable secret') || k.startsWith('enable password')) cfg.enableSecret = true;
      else if (k === 'service password-encryption') cfg.passwordEncryption = true;
      else if (lw[0] === 'banner') cfg.banner = t.replace(/^banner\s+motd\s+/i, '').replace(/^#\s*|\s*#$/g, '');
      else if (k.startsWith('login block-for')) cfg.loginBlock = { secs: Number(w[2]), attempts: Number(w[4]), within: Number(w[6]) };
      else if (k.startsWith('security passwords min-length')) cfg.minLength = Number(w[3]);
    }
    return cfg;
  }

  // ----------------------------------------------------------- config toggles
  const CONTROLS = {
    acls: { label: 'Inter-VLAN ACLs on R1', device: 'R1' },
    vty: { label: 'VTY lockdown (Management VLAN only)', device: 'R1' },
    portSecurity: { label: 'Port security on Switch0', device: 'Switch0' },
    asaInbound: { label: 'ASA inbound filtering (web only)', device: 'ASA1' }
  };
  function applyControls(name, text, controls) {
    if (!text) return text;
    let lines = text.split(/\r?\n/);
    if (name === 'R1' && !controls.acls) lines = lines.filter((l) => !/^\s*ip access-group\s/i.test(l));
    if (name === 'R1' && !controls.vty) lines = lines.filter((l) => !/^\s*access-class\s/i.test(l));
    if (name === 'Switch0' && !controls.portSecurity) lines = lines.filter((l) => !/^\s*switchport port-security/i.test(l));
    if (name === 'ASA1' && !controls.asaInbound) {
      let done = false;
      lines = lines.flatMap((l) => {
        if (/^\s*access-list OUTSIDE-DMZ\s/i.test(l)) {
          if (done) return [];
          done = true;
          return ['access-list OUTSIDE-DMZ extended permit ip any any'];
        }
        return [l];
      });
    }
    return lines.join('\n');
  }

  // ================================================================ Network
  class Network {
    constructor(topology, configs, options) {
      this.topo = topology;
      this.rawConfigs = configs || {};
      this.controls = Object.assign({ acls: true, vty: true, portSecurity: true, asaInbound: true }, (options && options.controls) || {});
      this.rogue = !!(options && options.rogue);
      this.idSeq = 1;
      this.build();
    }

    // ---------------------------------------------------------- build model
    build() {
      this.configText = {};
      this.devices = {};
      for (const [name, d] of Object.entries(this.topo.devices)) {
        const dev = Object.assign({ name }, d);
        if (d.config) {
          this.configText[name] = applyControls(name, this.rawConfigs[d.config] || '', this.controls);
        }
        if (d.type === 'router') dev.cfg = parseConfig(this.configText[name], 'router');
        else if (d.type === 'switch') dev.cfg = parseConfig(d.config ? this.configText[name] : '', 'switch');
        else if (d.type === 'asa') dev.cfg = parseConfig(this.configText[name], 'asa');
        else if (d.type !== 'hub') dev.mac = macOf(name + '|nic');
        this.devices[name] = dev;
      }
      this.links = this.topo.links
        .filter((l) => !(l[5] === 'optional' && !this.rogue))
        .map((l) => ({ a: { dev: l[0], port: l[1] }, b: { dev: l[2], port: l[3] }, cable: l[4], label: l[5] }));
      this.linkMap = new Map();
      for (const l of this.links) {
        this.linkMap.set(l.a.dev + '|' + l.a.port, l.b);
        this.linkMap.set(l.b.dev + '|' + l.b.port, l.a);
      }
      this.portsOf = {};
      for (const l of this.links) {
        (this.portsOf[l.a.dev] = this.portsOf[l.a.dev] || []).push(l.a.port);
        (this.portsOf[l.b.dev] = this.portsOf[l.b.dev] || []).push(l.b.port);
      }
      // Sticky port security: the MACs already behind each secured port were learned
      // before any rogue device appeared (the build guide tells you to ping them first).
      this.secureMacs = {};
      for (const d of Object.values(this.devices)) {
        if (d.type !== 'switch') continue;
        for (const [pname, p] of Object.entries(d.cfg.interfaces)) {
          if (!p.portSecurity) continue;
          const macs = this.hostsBehind(d.name, pname).filter((h) => !h.optional).map((h) => h.mac);
          this.secureMacs[d.name + '|' + pname] = macs.slice(0, p.portSecurity.max);
        }
      }
      this.arp = {};
      this.conns = [];
      this.aclHits = {};
      this.psViolations = {};
      this.lastFlows = [];
    }

    reset() { this.arp = {}; this.conns = []; this.aclHits = {}; this.psViolations = {}; this.lastFlows = []; }

    setControls(controls) { Object.assign(this.controls, controls); this.build(); }
    setRogue(on) { this.rogue = !!on; this.build(); }

    hostsBehind(dev, port) {
      const peer = this.linkMap.get(dev + '|' + port);
      if (!peer) return [];
      const d = this.devices[peer.dev];
      if (isHostType(d.type)) return [d];
      if (d.type === 'hub') return (this.portsOf[d.name] || []).filter((p) => p !== peer.port).map((p) => this.linkMap.get(d.name + '|' + p)).map((x) => this.devices[x.dev]).filter((x) => isHostType(x.type));
      return [];
    }

    // ------------------------------------------------------------ endpoints
    endpoints(devName) {
      const d = this.devices[devName];
      if (!d) return [];
      if (isHostType(d.type)) {
        if (!this.portsOf[devName]) return [];
        return [{ dev: devName, ifName: 'FastEthernet0', ip: d.ip, mask: d.mask, port: 'FastEthernet0', tag: null, mac: d.mac, kind: 'host' }];
      }
      if (d.type === 'router') {
        return Object.values(d.cfg.interfaces).filter((f) => f.ip && this.ifUp(d, f)).map((f) => ({
          dev: devName, ifName: f.name, ip: f.ip, mask: f.mask, port: f.parent || f.name,
          tag: f.encap && !f.native ? f.encap : null, mac: macOf(devName + '|' + (f.parent || f.name)), kind: 'router'
        }));
      }
      if (d.type === 'switch') {
        return Object.values(d.cfg.interfaces).filter((f) => f.name.startsWith('Vlan') && f.ip && !f.shutdown).map((f) => ({
          dev: devName, ifName: f.name, ip: f.ip, mask: f.mask, svi: true, vlan: Number(f.name.slice(4)), mac: macOf(devName + '|' + f.name), kind: 'switch'
        }));
      }
      if (d.type === 'asa') {
        return Object.values(d.cfg.interfaces).filter((f) => f.name.startsWith('Vlan') && f.ip && f.nameif && !f.shutdown).map((f) => ({
          dev: devName, ifName: f.name, nameif: f.nameif, ip: f.ip, mask: f.mask, svi: true, vlan: Number(f.name.slice(4)),
          mac: macOf(devName + '|' + f.name), kind: 'asa', proxy: this.asaProxyIps(d, f.nameif)
        }));
      }
      return [];
    }
    epByIf(devName, ifName) { return this.endpoints(devName).find((e) => e.ifName === ifName); }

    ifUp(d, f) {
      if (d.type !== 'router') return !f.shutdown;
      if (f.parent) {
        const p = d.cfg.interfaces[f.parent];
        return !!p && !p.shutdown && !f.shutdown && this.linkMap.has(d.name + '|' + f.parent);
      }
      return !f.shutdown && this.linkMap.has(d.name + '|' + f.name);
    }
    asaProxyIps(d, nameif) {
      const out = [];
      for (const o of Object.values(d.cfg.objects)) if (o.nat && o.nat.type === 'static' && o.nat.mapped === nameif) out.push(o.nat.mappedAddr);
      return out;
    }

    portCfg(d, port) {
      return d.cfg.interfaces[port] || newIf(port, d.type === 'asa' ? 'asa' : 'switch');
    }
    vlanExists(d, v) {
      if (d.type === 'asa') return true;
      return !!d.cfg.vlans[v];
    }
    trunkAllows(pc, v) { return !pc.trunkAllowed || pc.trunkAllowed.has(v); }

    // ------------------------------------------------------- layer 2 flood
    // Returns every layer-3 endpoint that a broadcast (ARP) from `ep` reaches,
    // with the device path, plus anything that dropped the frame on the way.
    l2Reach(ep, ctx) {
      const found = [], drops = [], seen = new Set(), queue = [];
      const srcMac = ep.mac;
      const emit = (dev, port, tag, path, note) => {
        const peer = this.linkMap.get(dev + '|' + port);
        if (!peer) return;
        queue.push({ dev: peer.dev, port: peer.port, tag, path: path.concat([{ dev: peer.dev, inPort: peer.port, tag, from: dev, outPort: port, note }]) });
      };
      const switchFlood = (d, vlan, inPort, path) => {
        for (const e of this.endpoints(d.name)) if (e.svi && e.vlan === vlan) found.push({ ep: e, path });
        for (const p of this.portsOf[d.name] || []) {
          if (p === inPort) continue;
          const pc = this.portCfg(d, p);
          if (pc.shutdown) continue;
          if (pc.mode === 'trunk') { if (this.trunkAllows(pc, vlan)) emit(d.name, p, vlan === pc.nativeVlan ? null : vlan, path); }
          else if (pc.accessVlan === vlan) emit(d.name, p, null, path);
        }
      };
      const start = [{ dev: ep.dev, inPort: null, tag: ep.tag || null }];
      if (ep.svi) switchFlood(this.devices[ep.dev], ep.vlan, null, start);
      else emit(ep.dev, ep.port, ep.tag || null, start);

      while (queue.length) {
        const a = queue.shift();
        const key = a.dev + '|' + a.port + '|' + a.tag;
        if (seen.has(key)) continue;
        seen.add(key);
        const d = this.devices[a.dev];
        if (!d) continue;
        if (isHostType(d.type)) {
          if (a.tag == null) for (const e of this.endpoints(d.name)) found.push({ ep: e, path: a.path });
        } else if (d.type === 'hub') {
          for (const p of this.portsOf[d.name] || []) if (p !== a.port) emit(d.name, p, a.tag, a.path);
        } else if (d.type === 'switch' || d.type === 'asa') {
          const pc = this.portCfg(d, a.port);
          if (pc.shutdown) continue;
          let vlan;
          if (pc.mode === 'trunk') {
            vlan = a.tag == null ? pc.nativeVlan : a.tag;
            if (!this.trunkAllows(pc, vlan)) { drops.push({ dev: d.name, port: a.port, reason: `VLAN ${vlan} is not allowed on trunk ${shortIf(a.port)}` }); continue; }
          } else {
            if (a.tag != null) continue;
            vlan = pc.accessVlan;
          }
          if (!this.vlanExists(d, vlan)) { drops.push({ dev: d.name, port: a.port, reason: `VLAN ${vlan} does not exist on ${d.name}` }); continue; }
          if (pc.portSecurity) {
            const secure = this.secureMacs[d.name + '|' + a.port] || [];
            if (!secure.includes(srcMac) && secure.length >= pc.portSecurity.max) {
              drops.push({ dev: d.name, port: a.port, portSecurity: true, reason: `port security on ${d.name} ${shortIf(a.port)}: unknown MAC ${srcMac} (maximum ${pc.portSecurity.max} secure addresses, violation ${pc.portSecurity.violation})` });
              if (ctx && !ctx.dry) { const k = d.name + '|' + a.port; this.psViolations[k] = (this.psViolations[k] || 0) + 1; }
              continue;
            }
          }
          a.path[a.path.length - 1].vlan = vlan;
          switchFlood(d, vlan, a.port, a.path);
        } else if (d.type === 'router') {
          const f = Object.values(d.cfg.interfaces).find((x) => {
            if (!x.ip || !this.ifUp(d, x)) return false;
            if (a.tag == null) return (x.name === a.port && !x.encap) || (x.parent === a.port && x.native);
            return x.parent === a.port && x.encap === a.tag && !x.native;
          });
          if (f) found.push({ ep: this.epByIf(d.name, f.name), path: a.path });
        }
      }
      return { found, drops };
    }

    resolve(ep, ip, ctx) {
      const r = this.l2Reach(ep, ctx);
      const hit = r.found.find((f) => f.ep.dev !== ep.dev && (f.ep.ip === ip || (f.ep.proxy || []).includes(ip)));
      return { ok: !!hit, target: hit && hit.ep, path: hit ? hit.path : null, drops: r.drops };
    }

    // ------------------------------------------------------------- routing
    routerRoute(d, dst) {
      let best = null;
      for (const f of Object.values(d.cfg.interfaces)) {
        if (!f.ip || !this.ifUp(d, f)) continue;
        if (inRange(dst, f.ip, f.mask)) {
          const p = maskToPrefix(f.mask);
          if (!best || p > best.prefix) best = { prefix: p, ifc: f, gw: null, type: 'C' };
        }
      }
      for (const r of d.cfg.routes) {
        if (!inRange(dst, r.net, r.mask)) continue;
        const p = maskToPrefix(r.mask);
        if (best && best.prefix >= p) continue;
        const via = Object.values(d.cfg.interfaces).find((f) => f.ip && this.ifUp(d, f) && inRange(r.gw, f.ip, f.mask));
        if (via) best = { prefix: p, ifc: via, gw: r.gw, type: 'S' };
      }
      return best;
    }
    asaIfByNameif(d, n) { return Object.values(d.cfg.interfaces).find((f) => f.nameif === n); }
    asaRoute(d, dst) {
      let best = null;
      for (const f of Object.values(d.cfg.interfaces)) {
        if (!f.nameif || !f.ip) continue;
        if (inRange(dst, f.ip, f.mask)) {
          const p = maskToPrefix(f.mask);
          if (!best || p > best.prefix) best = { prefix: p, ifc: f, nameif: f.nameif, gw: null };
        }
      }
      for (const r of d.cfg.routes) {
        if (!r.nameif || !inRange(dst, r.net, r.mask)) continue;
        const p = maskToPrefix(r.mask);
        if (best && best.prefix >= p) continue;
        const f = this.asaIfByNameif(d, r.nameif);
        if (f) best = { prefix: p, ifc: f, nameif: r.nameif, gw: r.gw };
      }
      return best;
    }

    // ------------------------------------------------------------- ACLs
    evalAcl(dev, aclName, pkt, ctx) {
      const d = this.devices[dev];
      const acl = d.cfg.acls[aclName];
      if (!acl) return { action: 'permit', missing: true };
      for (let i = 0; i < acl.entries.length; i++) {
        const ace = acl.entries[i];
        if (aceMatches(ace, pkt)) {
          if (!ctx.dry) { const k = dev + '|' + aclName + '|' + i; this.aclHits[k] = (this.aclHits[k] || 0) + 1; }
          return { action: ace.action, ace, seq: ace.seq, acl: aclName };
        }
      }
      return { action: 'deny', ace: null, implicit: true, acl: aclName };
    }

    // ---------------------------------------------------------- packet walk
    ev(ctx, dev, text, kind) { ctx.events.push({ dev, text, kind: kind || 'info' }); }

    originate(devName, pkt, ctx) {
      const d = this.devices[devName];
      if (isHostType(d.type)) {
        const ep = this.endpoints(devName)[0];
        if (!ep) return { fail: { at: devName, reason: `${devName} is not connected to the network` } };
        let nh = pkt.dst;
        if (!sameNet(pkt.dst, d.ip, d.mask)) {
          if (!d.gw) return { fail: { at: devName, reason: `${devName} has no default gateway` } };
          nh = d.gw;
          this.ev(ctx, devName, `${devName} → ${pkt.dst} is outside ${netOf(d.ip, d.mask)}/${maskToPrefix(d.mask)}, so the frame goes to the default gateway ${d.gw}.`);
        } else this.ev(ctx, devName, `${devName} → ${pkt.dst} is in the same subnet; delivered directly at layer 2.`);
        return { dev: devName, ep, nextHop: nh, pkt };
      }
      if (d.type === 'router') {
        const rt = this.routerRoute(d, pkt.dst);
        if (!rt) return { fail: { at: devName, reason: `${devName} has no route to ${pkt.dst}` } };
        if (!pkt.src) pkt.src = rt.ifc.ip;
        return { dev: devName, ep: this.epByIf(devName, rt.ifc.name), nextHop: rt.gw || pkt.dst, pkt };
      }
      if (d.type === 'asa') {
        const rt = this.asaRoute(d, pkt.dst);
        if (!rt) return { fail: { at: devName, reason: `${devName} has no route to ${pkt.dst}` } };
        if (!pkt.src) pkt.src = rt.ifc.ip;
        return { dev: devName, ep: this.epByIf(devName, rt.ifc.name), nextHop: rt.gw || pkt.dst, pkt };
      }
      if (d.type === 'switch') {
        const ep = this.endpoints(devName)[0];
        if (!ep) return { fail: { at: devName, reason: `${devName} has no management address` } };
        const nh = sameNet(pkt.dst, ep.ip, ep.mask) ? pkt.dst : d.cfg.defaultGateway;
        if (!nh) return { fail: { at: devName, reason: `${devName} has no default gateway` } };
        if (!pkt.src) pkt.src = ep.ip;
        return { dev: devName, ep, nextHop: nh, pkt };
      }
      return { fail: { at: devName, reason: 'device cannot send packets' } };
    }

    arpCache(dev) { return (this.arp[dev] = this.arp[dev] || new Map()); }

    hop(step, ctx, trail) {
      const { ep, nextHop } = step;
      const r = this.resolve(ep, nextHop, ctx);
      const ps = r.drops.find((x) => x.portSecurity);
      if (!r.ok) {
        if (ps) {
          this.ev(ctx, ps.dev, `Frame from ${ep.dev} dropped by ${ps.reason}.`, 'drop');
          return { fail: { at: ps.dev, reason: `Dropped by ${ps.reason}`, rule: { dev: ps.dev, text: 'switchport port-security' } } };
        }
        this.ev(ctx, ep.dev, `ARP for ${nextHop} gets no answer in this broadcast domain.`, 'drop');
        return { fail: { at: ep.dev, reason: `No device answers ARP for ${nextHop} on ${ep.dev}'s segment` } };
      }
      // ARP caches
      const devType = this.devices[ep.dev].type;
      const cache = this.arpCache(ep.dev);
      const known = cache.has(nextHop);
      if (!ctx.dry) {
        cache.set(nextHop, { mac: r.target.mac, ifName: ep.ifName });
        this.arpCache(r.target.dev).set(ep.ip, { mac: ep.mac, ifName: r.target.ifName });
      }
      if (ctx.arpModel && !known && devType === 'router') {
        this.ev(ctx, ep.dev, `${ep.dev} has no ARP entry for ${nextHop}; it sends an ARP request and drops this packet (normal for the first ping).`, 'arp');
        return { fail: { at: ep.dev, reason: `ARP resolution for ${nextHop} (first packet is dropped while the router learns the MAC address)`, arp: true } };
      }
      // describe the layer-2 path
      for (const h of r.path.slice(1)) {
        const hd = this.devices[h.dev];
        if (hd.type === 'hub') this.ev(ctx, h.dev, `${h.dev} repeats the frame out of every port (hubs share one collision domain).`);
        if ((hd.type === 'switch' || hd.type === 'asa') && h !== r.path[r.path.length - 1]) {
          const nxt = r.path[r.path.indexOf(h) + 1];
          const pc = this.portCfg(hd, h.inPort), po = this.portCfg(hd, nxt.outPort);
          const inDesc = pc.mode === 'trunk' ? `trunk ${shortIf(h.inPort, hd.type === 'asa')}${h.tag ? ` (802.1Q tag ${h.tag})` : ' (native, untagged)'}` : `${shortIf(h.inPort, hd.type === 'asa')} (access VLAN ${pc.accessVlan})`;
          const outDesc = po.mode === 'trunk' ? `trunk ${shortIf(nxt.outPort, hd.type === 'asa')}${nxt.tag ? ` adding 802.1Q tag ${nxt.tag}` : ' untagged (native VLAN)'}` : `${shortIf(nxt.outPort, hd.type === 'asa')} (access VLAN ${po.accessVlan})`;
          this.ev(ctx, h.dev, `${h.dev} switches the frame in VLAN ${h.vlan}: in on ${inDesc}, out on ${outDesc}.`);
        }
      }
      for (const h of r.path) if (trail[trail.length - 1] !== h.dev) trail.push(h.dev);
      return { arrived: r.target };
    }

    // Walks one packet from its origin until it is delivered or dropped.
    journey(pkt, origin, ctx) {
      const trail = [origin];
      let step = this.originate(origin, pkt, ctx);
      for (let guard = 0; guard < 40; guard++) {
        if (step.fail) return Object.assign({ status: 'dropped', trail, pkt }, step.fail);
        const h = this.hop(step, ctx, trail);
        if (h.fail) return Object.assign({ status: 'dropped', trail, pkt: step.pkt }, h.fail);
        const tgt = h.arrived;
        const d = this.devices[tgt.dev];
        const p = step.pkt;
        let out;
        if (isHostType(d.type)) out = p.dst === d.ip ? { delivered: true } : { drop: `${d.name} is not ${p.dst}` };
        else if (d.type === 'switch') out = p.dst === tgt.ip ? { delivered: true } : { drop: `${d.name} does not route` };
        else if (d.type === 'router') out = this.routerProcess(d, tgt, p, ctx);
        else if (d.type === 'asa') out = this.asaProcess(d, tgt, p, ctx);
        if (out.delivered) return { status: 'delivered', to: tgt, pkt: p, trail };
        if (out.drop) {
          this.ev(ctx, d.name, out.drop, 'drop');
          return { status: 'dropped', at: d.name, reason: out.drop, error: out.error, errorFrom: out.errorFrom, rule: out.rule, pkt: p, trail };
        }
        step = { dev: d.name, ep: out.forward.ep, nextHop: out.forward.nextHop, pkt: out.forward.pkt };
      }
      return { status: 'dropped', at: origin, reason: 'routing loop', trail, pkt };
    }

    routerProcess(d, ingress, pkt, ctx) {
      const f = d.cfg.interfaces[ingress.ifName];
      const label = `${d.name} ${shortIf(f.name)}`;
      if (f.aclIn && !pkt.local) {
        const r = this.evalAcl(d.name, f.aclIn, pkt, ctx);
        if (!r.missing) {
          const line = r.ace ? `line ${r.seq} "${r.ace.text}"` : 'the implicit "deny any" at the end';
          if (r.action === 'deny') {
            return { drop: `${label}: inbound ACL ${f.aclIn} matched ${line} → packet denied.`, error: isError(pkt) ? null : 'unreachable', errorFrom: f.ip, rule: { dev: d.name, acl: f.aclIn, seq: r.seq || null, text: r.ace ? r.ace.text : 'deny ip any any (implicit)' } };
          }
          this.ev(ctx, d.name, `${label}: inbound ACL ${f.aclIn} matched ${line} → permitted.`, 'acl');
        }
      }
      const own = Object.values(d.cfg.interfaces).find((x) => x.ip === pkt.dst && this.ifUp(d, x));
      if (own) { this.ev(ctx, d.name, `${pkt.dst} is ${d.name}'s own address (${shortIf(own.name)}).`, 'ok'); return { delivered: true }; }
      if (pkt.ttl <= 1) return { drop: `${label}: TTL expired in transit.`, error: isError(pkt) ? null : 'time-exceeded', errorFrom: f.ip };
      const rt = this.routerRoute(d, pkt.dst);
      if (!rt) return { drop: `${label}: no route to ${pkt.dst}` + (isPrivate(pkt.dst) ? ' (private addresses are not routed on the Internet)' : '') + '.', error: isError(pkt) ? null : 'unreachable', errorFrom: f.ip, rule: { dev: d.name, text: 'no route' } };
      const np = Object.assign({}, pkt, { ttl: pkt.ttl - 1 });
      if (rt.ifc.aclOut) {
        const r = this.evalAcl(d.name, rt.ifc.aclOut, np, ctx);
        if (!r.missing && r.action === 'deny') return { drop: `${d.name} ${shortIf(rt.ifc.name)}: outbound ACL ${rt.ifc.aclOut} denied the packet.`, error: isError(pkt) ? null : 'unreachable', errorFrom: f.ip, rule: { dev: d.name, acl: rt.ifc.aclOut, seq: r.seq || null, text: r.ace ? r.ace.text : 'implicit deny' } };
      }
      this.ev(ctx, d.name, `${d.name} routes ${pkt.dst} via ${rt.type === 'C' ? 'connected network on' : 'static route ' + rt.gw + ' out'} ${shortIf(rt.ifc.name)}.`);
      return { forward: { ep: this.epByIf(d.name, rt.ifc.name), nextHop: rt.gw || pkt.dst, pkt: np } };
    }

    asaProcess(d, ingress, pkt, ctx) {
      const inIf = ingress.nameif;
      const conns = ctx.conns;
      // 1. return traffic for an existing connection
      if (!isError(pkt)) {
        const c = [...conns].reverse().find((x) => x.dev === d.name && x.outIf === inIf && x.proto === pkt.proto && x.id === pkt.id && x.outDst === pkt.src && x.outSrc === pkt.dst);
        if (c) {
          const np = Object.assign({}, pkt, { src: c.inDst, dst: c.inSrc });
          const rt = this.asaRoute(d, np.dst);
          if (!rt) return { drop: `${d.name}: no route back to ${np.dst}.` };
          const nat = (pkt.dst !== np.dst || pkt.src !== np.src) ? ` and un-translates ${pkt.src}→${pkt.dst} to ${np.src}→${np.dst}` : '';
          this.ev(ctx, d.name, `${d.name} matches the existing ${pkt.proto.toUpperCase()} connection (stateful inspection)${nat}; allowed back to ${c.inIf}.`, 'ok');
          return { forward: { ep: this.epByIf(d.name, rt.ifc.name), nextHop: rt.gw || np.dst, pkt: np } };
        }
      }
      // 2. traffic to the ASA itself
      const own = Object.values(d.cfg.interfaces).find((x) => x.ip === pkt.dst && x.nameif);
      if (own) {
        if (own.nameif !== inIf) return { drop: `${d.name}: the firewall only answers on the interface a packet arrives on (${inIf}), not on ${own.nameif}.` };
        if (pkt.proto === 'icmp' && pkt.icmpType === 'echo') { this.ev(ctx, d.name, `${d.name} answers ping on its ${inIf} interface.`, 'ok'); return { delivered: true }; }
        if (pkt.proto === 'tcp' && pkt.dport === 22 && d.cfg.asaSsh.some((s) => s.nameif === inIf && inRange(pkt.src, s.net, s.mask))) return { delivered: true };
        return { drop: `${d.name}: no management service for ${pkt.proto.toUpperCase()}${pkt.dport ? '/' + pkt.dport : ''} from ${pkt.src} on the ${inIf} interface.`, rule: { dev: d.name, text: 'to-the-box traffic denied' } };
      }
      // 3. replies with no matching connection
      if (isReplyType(pkt)) return { drop: `${d.name}: ${describe(pkt)} from ${pkt.src} has no matching connection, so the stateful firewall drops it.`, rule: { dev: d.name, text: 'no connection' } };
      // 4. destination NAT (published servers)
      let realDst = pkt.dst;
      for (const o of Object.values(d.cfg.objects)) {
        if (o.nat && o.nat.type === 'static' && o.nat.mapped === inIf && o.nat.mappedAddr === pkt.dst) {
          realDst = o.net;
          this.ev(ctx, d.name, `${d.name} static NAT (object ${o.name}): ${pkt.dst} → real address ${realDst}.`, 'nat');
        }
      }
      const rt = this.asaRoute(d, realDst);
      if (!rt) return { drop: `${d.name}: no route to ${realDst}.` };
      const outIf = rt.nameif;
      if (outIf === inIf) return { drop: `${d.name}: ${realDst} is back out the ${inIf} interface; hairpinning is not allowed.` };
      const inF = this.asaIfByNameif(d, inIf), outF = rt.ifc;
      if (inF.noForward.includes(outF.name)) {
        return { drop: `${d.name}: "no forward interface ${outF.name}" on ${inF.name} (${inIf}) blocks every connection from ${inIf} to ${outIf}.`, rule: { dev: d.name, text: `no forward interface ${outF.name}` } };
      }
      const aclName = d.cfg.accessGroups[inIf];
      const test = Object.assign({}, pkt, { dst: realDst });
      if (aclName) {
        const r = this.evalAcl(d.name, aclName, test, ctx);
        if (r.action === 'deny') {
          return { drop: `${d.name}: access-group ${aclName} on ${inIf} ${r.ace ? 'line ' + r.seq + ' "' + r.ace.text + '"' : 'has no permit for ' + describe(pkt) + ' → implicit deny'}.`, rule: { dev: d.name, acl: aclName, seq: r.seq || null, text: r.ace ? r.ace.text : 'implicit deny' } };
        }
        this.ev(ctx, d.name, `${d.name}: access-group ${aclName} on ${inIf} permits it (line ${r.seq} "${r.ace.text}").`, 'acl');
      } else if (inF.secLevel <= outF.secLevel) {
        return { drop: `${d.name}: ${inIf} (security ${inF.secLevel}) → ${outIf} (security ${outF.secLevel}). Traffic may not go from a lower to a higher security level without an ACL.`, rule: { dev: d.name, text: 'security-level' } };
      } else {
        this.ev(ctx, d.name, `${d.name}: ${inIf} (security ${inF.secLevel}) → ${outIf} (security ${outF.secLevel}) is allowed by default.`, 'acl');
      }
      // 5. source NAT
      let newSrc = pkt.src;
      for (const o of Object.values(d.cfg.objects)) {
        if (!o.nat || o.nat.real !== inIf || o.nat.mapped !== outIf || !inRange(pkt.src, o.net, o.mask)) continue;
        newSrc = o.nat.type === 'dynamic' && o.nat.mappedAddr === 'interface' ? outF.ip : o.nat.mappedAddr;
        this.ev(ctx, d.name, `${d.name} ${o.nat.type === 'dynamic' ? 'PAT' : 'static NAT'} (object ${o.name}): source ${pkt.src} → ${newSrc}.`, 'nat');
        break;
      }
      // 6. connection state
      const stateful = pkt.proto !== 'icmp' || d.cfg.inspect.has('icmp');
      if (stateful) conns.push({ dev: d.name, proto: pkt.proto, id: pkt.id, inIf, outIf, inSrc: pkt.src, inDst: pkt.dst, outSrc: newSrc, outDst: realDst, sport: pkt.sport, dport: pkt.dport, t: Date.now() });
      const np = Object.assign({}, pkt, { src: newSrc, dst: realDst });
      return { forward: { ep: this.epByIf(d.name, outF.name), nextHop: rt.gw || realDst, pkt: np } };
    }

    // ------------------------------------------------------- responders
    respond(to, pkt) {
      const d = this.devices[to.dev];
      const base = { src: pkt.dst, dst: pkt.src, id: pkt.id, ttl: isHostType(d.type) ? 128 : 255 };
      if (pkt.proto === 'icmp' && pkt.icmpType === 'echo') return { kind: 'echo-reply', pkt: Object.assign(base, { proto: 'icmp', icmpType: 'echo-reply' }) };
      if (pkt.proto === 'tcp') {
        const open = this.tcpOpen(d, pkt);
        const flags = open.ok ? { syn: true, ack: true } : { rst: true, ack: true };
        return { kind: open.ok ? 'syn-ack' : 'rst', note: open.note, pkt: Object.assign(base, { proto: 'tcp', sport: pkt.dport, dport: pkt.sport, flags }) };
      }
      if (pkt.proto === 'udp' && pkt.dport === 53 && d.services && d.services.dns) {
        const answer = d.services.dns[String(pkt.query || '').toLowerCase()] || null;
        return { kind: 'dns', answer, pkt: Object.assign(base, { proto: 'udp', sport: 53, dport: pkt.sport }) };
      }
      return null;
    }
    tcpOpen(d, pkt) {
      if (isHostType(d.type)) {
        const s = d.services || {};
        if (pkt.dport === 80 && s.http) return { ok: true };
        if (pkt.dport === 21 && s.ftp) return { ok: true };
        if (pkt.dport === 53 && s.dns) return { ok: true };
        return { ok: false, note: `${d.name} has no service listening on port ${pkt.dport}` };
      }
      if (d.type === 'router' || d.type === 'switch') {
        const vty = d.cfg.lines.vty || {};
        const proto = pkt.dport === 22 ? 'ssh' : pkt.dport === 23 ? 'telnet' : null;
        if (!proto) return { ok: false, note: `no service on port ${pkt.dport}` };
        const transport = vty.transport || ['telnet', 'ssh'];
        if (!transport.includes(proto) && !transport.includes('all')) return { ok: false, note: `VTY lines accept only ${transport.join(', ')}` };
        if (proto === 'ssh' && !d.cfg.cryptoKey) return { ok: false, note: 'no RSA keys, SSH disabled' };
        if (vty.accessClass) {
          const acl = d.cfg.acls[vty.accessClass];
          if (acl) {
            const hit = acl.entries.find((a) => addrMatch(a.src, pkt.src));
            if (!hit || hit.action === 'deny') return { ok: false, accessClass: true, note: `VTY access-class ${vty.accessClass} rejects ${pkt.src}` };
          }
        }
        return { ok: true };
      }
      if (d.type === 'asa') return { ok: true };
      return { ok: false };
    }

    // --------------------------------------------------- one full exchange
    // Sends a request, lets the destination answer, and walks the answer back.
    exchange(src, req, opts) {
      opts = opts || {};
      const ctx = { events: [], dry: !!opts.dry, arpModel: !!opts.arpModel && !opts.dry, conns: opts.dry ? [] : this.conns };
      req = Object.assign({ id: this.idSeq++, ttl: this.devices[src] && isHostType(this.devices[src].type) ? 128 : 255 }, req);
      if (!req.src) {
        const d = this.devices[src];
        req.src = isHostType(d.type) ? d.ip : null;
      }
      this.ev(ctx, src, `${src} sends ${describe(req)} to ${req.dst}${req.ttl < 30 ? ` (TTL ${req.ttl})` : ''}.`, 'start');
      const out = { request: null, reply: null, status: 'timeout', events: ctx.events, trails: [] };
      const r1 = this.journey(req, src, ctx);
      out.request = r1;
      out.trails.push({ dir: 'out', devices: r1.trail, ok: r1.status === 'delivered', dropAt: r1.status === 'dropped' ? r1.at : null });
      if (r1.status === 'delivered') {
        const resp = this.respond(r1.to, r1.pkt);
        if (!resp) { out.status = 'timeout'; out.reason = `${r1.to.dev} does not answer ${describe(req)}.`; return this.finish(out, src); }
        if (resp.kind === 'rst') this.ev(ctx, r1.to.dev, `${r1.to.dev} refuses the connection (${resp.note || 'port closed'}) and sends TCP RST.`, 'drop');
        else this.ev(ctx, r1.to.dev, `${r1.to.dev} receives it and replies with ${describe(resp.pkt)}.`, 'ok');
        const r2 = this.journey(resp.pkt, r1.to.dev, ctx);
        out.reply = r2;
        out.trails.push({ dir: 'back', devices: r2.trail, ok: r2.status === 'delivered', dropAt: r2.status === 'dropped' ? r2.at : null });
        if (r2.status === 'delivered' && r2.to.dev === src) {
          out.status = resp.kind;
          out.from = r2.pkt.src;
          out.ttl = r2.pkt.ttl;
          out.answer = resp.answer;
          out.note = resp.note;
          this.ev(ctx, src, `${src} receives the ${describe(r2.pkt)} from ${r2.pkt.src}.`, 'ok');
        } else {
          out.status = 'timeout';
          out.reason = 'The reply was dropped: ' + (r2.reason || 'unknown');
          out.blockedAt = r2.at;
          out.rule = r2.rule;
        }
      } else if (r1.status === 'dropped' && r1.error) {
        const err = { proto: 'icmp', icmpType: r1.error, src: r1.errorFrom, dst: r1.pkt.src, ttl: 255, id: req.id, isError: true };
        this.ev(ctx, r1.at, `${r1.at} sends ICMP ${r1.error === 'unreachable' ? 'Destination Unreachable' : 'Time Exceeded'} from ${r1.errorFrom} back to ${err.dst}.`, 'info');
        const r3 = this.journey(err, r1.at, ctx);
        out.trails.push({ dir: 'back', devices: r3.trail, ok: r3.status === 'delivered', error: true });
        out.reason = r1.reason; out.blockedAt = r1.at; out.rule = r1.rule;
        if (r3.status === 'delivered' && r3.to.dev === src) { out.status = r1.error; out.from = r3.pkt.src; }
        else out.status = 'timeout';
      } else {
        out.status = 'timeout';
        out.reason = r1.reason; out.blockedAt = r1.at; out.rule = r1.rule; out.arp = !!r1.arp;
      }
      return this.finish(out, src);
    }
    finish(out, src) {
      out.src = src;
      if (!out.blockedAt && out.status !== 'timeout') out.ok = true;
      out.ok = ['echo-reply', 'syn-ack', 'dns'].includes(out.status);
      this.lastFlows.unshift(out);
      this.lastFlows.length = Math.min(this.lastFlows.length, 20);
      return out;
    }

    // ------------------------------------------------ user-level commands
    resolveName(src, name, opts) {
      const d = this.devices[src];
      const server = d && d.dns;
      if (!server) return { ok: false, reason: 'no DNS server configured' };
      const ex = this.exchange(src, { proto: 'udp', dst: server, sport: 1025 + (this.idSeq % 5000), dport: 53, query: name }, opts);
      if (ex.status !== 'dns') return { ok: false, reason: ex.reason || 'DNS server did not answer', exchange: ex, server };
      if (!ex.answer) return { ok: false, reason: 'name not found', nx: true, exchange: ex, server };
      return { ok: true, ip: ex.answer, exchange: ex, server };
    }

    ping(src, target, opts) {
      opts = opts || {};
      const d = this.devices[src];
      const isHost = isHostType(d.type);
      const count = opts.count || (isHost ? 4 : 5);
      const lines = [];
      let ip = target;
      if (!isIp(target)) {
        const r = this.resolveName(src, target);
        if (!r.ok) return { lines: [`Ping request could not find host ${target}. Please check the name and try again.`], exchanges: r.exchange ? [r.exchange] : [], ok: false };
        ip = r.ip;
      }
      const exchanges = [];
      for (let i = 0; i < count; i++) exchanges.push(this.exchange(src, { proto: 'icmp', icmpType: 'echo', dst: ip }, { arpModel: true }));
      const okN = exchanges.filter((e) => e.status === 'echo-reply').length;
      if (isHost) {
        lines.push('', `Pinging ${ip} with 32 bytes of data:`, '');
        const times = [];
        for (const e of exchanges) {
          if (e.status === 'echo-reply') {
            const t = Math.max(0, (e.trails[0].devices.filter((x) => this.devices[x].type === 'router').length) - 1 + Math.round(Math.random()));
            times.push(t);
            lines.push(`Reply from ${e.from}: bytes=32 time${t === 0 ? '<1' : '='}${t === 0 ? '' : t}ms TTL=${e.ttl}`);
          } else if (e.status === 'unreachable') lines.push(`Reply from ${e.from}: Destination host unreachable.`);
          else if (e.status === 'time-exceeded') lines.push(`Reply from ${e.from}: TTL expired in transit.`);
          else lines.push('Request timed out.');
        }
        const recv = exchanges.filter((e) => e.status !== 'timeout').length;
        lines.push('', `Ping statistics for ${ip}:`, `    Packets: Sent = ${count}, Received = ${recv}, Lost = ${count - recv} (${Math.round(((count - recv) / count) * 100)}% loss),`);
        if (times.length) {
          const mn = Math.min(...times), mx = Math.max(...times), av = Math.round(times.reduce((a, b) => a + b, 0) / times.length);
          lines.push('Approximate round trip times in milli-seconds:', `    Minimum = ${mn}ms, Maximum = ${mx}ms, Average = ${av}ms`);
        }
      } else {
        lines.push('Type escape sequence to abort.', `Sending ${count}, 100-byte ICMP Echos to ${ip}, timeout is 2 seconds:`);
        lines.push(exchanges.map((e) => (e.status === 'echo-reply' ? '!' : e.status === 'unreachable' ? 'U' : '.')).join(''));
        lines.push(`Success rate is ${Math.round((okN / count) * 100)} percent (${okN}/${count})` + (okN ? ', round-trip min/avg/max = 0/0/1 ms' : ''));
      }
      return { lines, exchanges, ok: okN > 0, ip };
    }

    tracert(src, target) {
      let ip = target;
      const lines = [];
      if (!isIp(target)) {
        const r = this.resolveName(src, target);
        if (!r.ok) return { lines: [`Unable to resolve target system name ${target}.`], exchanges: [] };
        ip = r.ip;
      }
      lines.push('', `Tracing route to ${ip} over a maximum of 30 hops: `, '');
      const exchanges = [];
      let silent = 0;
      for (let ttl = 1; ttl <= 30; ttl++) {
        const probes = [0, 1, 2].map(() => this.exchange(src, { proto: 'icmp', icmpType: 'echo', dst: ip, ttl }, { arpModel: true }));
        exchanges.push(...probes);
        const good = probes.find((p) => p.status !== 'timeout');
        const col = (p) => (p.status === 'timeout' ? '*'.padEnd(9) : '0 ms'.padEnd(9));
        const n = String(ttl).padStart(3);
        if (good && good.status === 'unreachable') {
          lines.push(`${n}   ${probes.map(col).join('')}${good.from}`);
          lines.push(`${String(ttl + 1).padStart(3)}   ${good.from}   reports: Destination host unreachable.`);
          break;
        }
        if (!good) { lines.push(`${n}   *        *        *        Request timed out.`); silent++; if (silent >= 3) { lines.push('', '(trace stopped: probes are being filtered)'); break; } continue; }
        silent = 0;
        lines.push(`${n}   ${probes.map(col).join('')}${good.from}`);
        if (good.status === 'echo-reply') break;
      }
      lines.push('', 'Trace complete.');
      return { lines, exchanges };
    }

    nslookup(src, name) {
      const d = this.devices[src];
      if (!d.dns) return { lines: ['', 'Server: [none]', '', '*** No DNS server is configured on this host.'], exchanges: [] };
      const r = this.resolveName(src, name);
      const lines = ['', `Server: [${d.dns}]`, `Address: ${d.dns}`, ''];
      if (r.ok) lines.push('Non-authoritative answer:', `Name:\t${name}`, `Address: ${r.ip}`);
      else if (r.nx) lines.push(`*** ${d.dns} can't find ${name}: Non-existent domain`);
      else lines.push('DNS request timed out.', '    timeout was 15000 milli seconds.');
      return { lines, exchanges: r.exchange ? [r.exchange] : [], ok: r.ok };
    }

    connect(src, target, port, opts) {
      let ip = target;
      let dnsEx = null;
      if (!isIp(target)) {
        const r = this.resolveName(src, target, opts);
        dnsEx = r.exchange || null;
        if (!r.ok) return { status: 'dns-fail', reason: r.reason, exchanges: dnsEx ? [dnsEx] : [] };
        ip = r.ip;
      }
      const ex = this.exchange(src, { proto: 'tcp', dst: ip, sport: 1025 + (this.idSeq % 5000), dport: port, flags: { syn: true } }, opts);
      return { status: ex.status, ip, exchange: ex, exchanges: dnsEx ? [dnsEx, ex] : [ex] };
    }

    browse(src, url) {
      const host = String(url).trim().replace(/^https?:\/\//i, '').split(/[/:]/)[0];
      const c = this.connect(src, host, 80);
      if (c.status === 'dns-fail') return Object.assign(c, { view: 'error', title: 'Host Name Unresolved', message: `The name ${host} could not be resolved (${c.reason}).` });
      if (c.status === 'syn-ack') {
        const d = this.devices[c.exchange.request.to.dev];
        return Object.assign(c, { view: 'page', page: d.services.http, server: d.name });
      }
      if (c.status === 'rst') return Object.assign(c, { view: 'error', title: 'Server Reset Connection', message: `${c.ip} refused the connection on port 80.` });
      return Object.assign(c, { view: 'error', title: 'Request Timeout', message: c.exchange.reason || 'No response from the server.' });
    }

    // Quick yes/no reachability test used by the policy matrix (no side effects).
    test(src, spec) {
      if (spec.proto === 'icmp') return this.exchange(src, { proto: 'icmp', icmpType: 'echo', dst: spec.dst }, { dry: true });
      if (spec.proto === 'tcp') return this.exchange(src, { proto: 'tcp', dst: spec.dst, sport: 40000, dport: spec.port, flags: { syn: true } }, { dry: true });
      if (spec.proto === 'udp') return this.exchange(src, { proto: 'udp', dst: spec.dst, sport: 40000, dport: spec.port, query: spec.query }, { dry: true });
      throw new Error('bad spec');
    }

    // ------------------------------------------------------------- CLI
    cli(devName, line, state) {
      const d = this.devices[devName];
      state = state || {};
      const cmd = String(line).trim();
      if (!cmd) return { out: [] };
      const words = cmd.split(/\s+/);
      const lw = words.map((w) => w.toLowerCase());
      const m = (abbr, full) => abbr.length >= 2 && full.startsWith(abbr) || abbr === full;
      if (m(lw[0], 'enable') || lw[0] === 'en') { state.priv = true; return { out: [], state }; }
      if (m(lw[0], 'disable')) { state.priv = false; return { out: [], state }; }
      if (lw[0] === 'exit' || lw[0] === 'logout' || lw[0] === 'end') { state.priv = false; return { out: [], state }; }
      if (m(lw[0], 'configure') || lw[0] === 'conf') return { out: ['% This simulator runs the saved configuration and is read-only.', '% Use the Security controls panel to switch protections off and on,', '% or paste the configs from the Build Kit into Packet Tracer.'] };
      if (lw[0] === '?' || lw[0] === 'help') return { out: this.cliHelp(d) };
      if (m(lw[0], 'ping')) {
        if (!words[1]) return { out: ['% Incomplete command.'] };
        const r = this.ping(devName, words[1]);
        return { out: r.lines, exchanges: r.exchanges };
      }
      if (m(lw[0], 'traceroute')) {
        if (!words[1]) return { out: ['% Incomplete command.'] };
        const r = this.tracert(devName, words[1]);
        return { out: r.lines, exchanges: r.exchanges };
      }
      if (m(lw[0], 'show') || lw[0] === 'sh') {
        if (!state.priv && d.type !== 'asa') {
          // user EXEC can run most show commands in IOS, but not running-config
        }
        return { out: this.show(d, lw.slice(1), words.slice(1)) };
      }
      return { out: [`% Invalid input detected at '^' marker.`] };
    }
    cliHelp(d) {
      const common = ['enable', 'ping <ip>', 'traceroute <ip>', 'show running-config'];
      if (d.type === 'router') return common.concat(['show ip interface brief', 'show ip route', 'show access-lists', 'show arp', 'show ip ssh', 'show interfaces trunk (switch only)']);
      if (d.type === 'switch') return common.concat(['show vlan brief', 'show interfaces trunk', 'show port-security', 'show port-security interface fa0/4', 'show mac address-table', 'show ip interface brief']);
      if (d.type === 'asa') return common.concat(['show nameif', 'show ip address', 'show route', 'show switch vlan', 'show access-list', 'show xlate', 'show conn', 'show nat']);
      return common;
    }

    show(d, lw, words) {
      const s = lw.join(' ');
      const is = (...alts) => alts.some((a) => matchAbbrev(s, a));
      if (is('running-config', 'run')) return this.showRun(d);
      if (d.type === 'router') {
        if (is('ip interface brief', 'ip int brief', 'ip int br')) return this.showIpIntBrief(d);
        if (is('ip route')) return this.showIpRoute(d);
        if (is('access-lists', 'access-list', 'ip access-lists')) return this.showAcl(d);
        if (is('arp', 'ip arp')) return this.showArp(d);
        if (is('ip ssh')) return d.cfg.cryptoKey ? [`SSH Enabled - version ${d.cfg.sshVersion || 1.99}.0`, 'Authentication timeout: 120 secs; Authentication retries: 3'] : ['SSH Disabled - version 1.99', '%Please create RSA keys (of at least 768 bits size) to enable SSH v2.'];
      }
      if (d.type === 'switch') {
        if (is('vlan brief', 'vlan')) return this.showVlan(d);
        if (is('interfaces trunk', 'interface trunk')) return this.showTrunk(d);
        if (s.startsWith('port') && words.length >= 3) return this.showPortSecIf(d, canonIf(words.slice(2).join('').replace(/^interface/i, '')));
        if (is('port-security')) return this.showPortSec(d);
        if (is('mac address-table', 'mac-address-table')) return this.showMac(d);
        if (is('ip interface brief', 'ip int brief', 'ip int br')) return this.showSwitchIpBrief(d);
      }
      if (d.type === 'asa') {
        if (is('nameif')) return this.showNameif(d);
        if (is('ip address', 'interface ip brief')) return this.showAsaIp(d);
        if (is('route')) return this.showAsaRoute(d);
        if (is('switch vlan')) return this.showAsaSwitchVlan(d);
        if (is('access-list')) return this.showAsaAcl(d);
        if (is('xlate')) return this.showXlate(d);
        if (is('conn')) return this.showConn(d);
        if (is('nat')) return this.showNat(d);
      }
      return [`% Invalid input detected at '^' marker.`];
    }

    showRun(d) {
      const text = this.configText[d.name];
      if (!text) return ['Building configuration...', '', 'Current configuration : factory default (no changes)', '!', 'end'];
      const skip = /^(enable|configure terminal|end|write memory|exit|1024|crypto key generate rsa.*)$/i;
      const out = ['Building configuration...', '', `Current configuration : ${text.length} bytes`, '!'];
      let last = '';
      for (const raw of text.split(/\r?\n/)) {
        const t = raw.trim();
        if (!t || skip.test(t)) continue;
        if (t.startsWith('!')) { if (last !== '!') out.push('!'); last = '!'; continue; }
        let l = raw.replace(/\s+$/, '');
        l = l.replace(/\b(secret)\s+(?!5\s)(\S+)/i, (_, k, v) => `${k} 5 ${fakeHash(v)}`);
        if (d.cfg.passwordEncryption) l = l.replace(/^(\s*password)\s+(?!7\s)(\S+)/i, (_, k, v) => `${k} 7 ${fakeType7(v)}`);
        l = l.replace(/^(enable password)\s+(\S+)$/i, (_, k, v) => `${k} ${fakeHash(v).slice(3, 19)} encrypted`);
        l = l.replace(/^(username \S+ password)\s+(\S+)$/i, (_, k, v) => `${k} ${fakeHash(v).slice(3, 19)} encrypted`);
        out.push(l);
        last = l;
      }
      out.push('!', 'end');
      return out;
    }
    showIpIntBrief(d) {
      const out = ['Interface              IP-Address      OK? Method Status                Protocol'];
      const names = Object.keys(d.cfg.interfaces).sort(ifSort);
      for (const n of names) {
        const f = d.cfg.interfaces[n];
        const up = this.ifUp(d, f);
        const admin = f.shutdown || (f.parent && d.cfg.interfaces[f.parent] && d.cfg.interfaces[f.parent].shutdown);
        const status = admin ? 'administratively down' : up ? 'up' : 'down';
        out.push(`${n.padEnd(23)}${(f.ip || 'unassigned').padEnd(16)}YES ${(f.ip ? 'manual' : 'unset').padEnd(7)}${status.padEnd(22)}${up ? 'up' : 'down'}`);
      }
      return out;
    }
    showIpRoute(d) {
      const out = ['Codes: C - connected, S - static, R - RIP, M - mobile, B - BGP', '       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area', '       * - candidate default, U - per-user static route, o - ODR', ''];
      const def = d.cfg.routes.find((r) => r.net === '0.0.0.0');
      out.push(def ? `Gateway of last resort is ${def.gw} to network 0.0.0.0` : 'Gateway of last resort is not set', '');
      const conn = Object.values(d.cfg.interfaces).filter((f) => f.ip && this.ifUp(d, f)).map((f) => ({ net: netOf(f.ip, f.mask), p: maskToPrefix(f.mask), f }));
      conn.sort((a, b) => ipToInt(a.net) - ipToInt(b.net));
      for (const c of conn) out.push(`C    ${c.net}/${c.p} is directly connected, ${c.f.name}`);
      for (const r of d.cfg.routes) out.push(`S${r.net === '0.0.0.0' ? '*' : ' '}   ${r.net}/${maskToPrefix(r.mask)} [1/0] via ${r.gw}`);
      return out;
    }
    showAcl(d) {
      const out = [];
      for (const acl of Object.values(d.cfg.acls)) {
        out.push(`${acl.type === 'standard' ? 'Standard' : 'Extended'} IP access list ${acl.name}`);
        acl.entries.forEach((e, i) => {
          const hits = this.aclHits[d.name + '|' + acl.name + '|' + i];
          out.push(`    ${e.seq} ${e.text}${hits ? ` (${hits} match(es))` : ''}`);
        });
      }
      const where = Object.values(d.cfg.interfaces).filter((f) => f.aclIn || f.aclOut);
      if (where.length) { out.push(''); for (const f of where) out.push(`! applied: ${f.name} ip access-group ${f.aclIn || f.aclOut} ${f.aclIn ? 'in' : 'out'}`); }
      else out.push('', '! (no ACLs are applied to any interface)');
      return out;
    }
    showArp(d) {
      const out = ['Protocol  Address          Age (min)  Hardware Addr   Type   Interface'];
      for (const e of this.endpoints(d.name)) out.push(`Internet  ${e.ip.padEnd(17)}-          ${e.mac}  ARPA   ${e.ifName}`);
      for (const [ip, v] of this.arpCache(d.name)) out.push(`Internet  ${ip.padEnd(17)}0          ${v.mac}  ARPA   ${v.ifName}`);
      return out;
    }
    showVlan(d) {
      const out = ['', 'VLAN Name                             Status    Ports', '---- -------------------------------- --------- -------------------------------'];
      const ids = Object.keys(d.cfg.vlans).map(Number).sort((a, b) => a - b);
      for (const id of ids) {
        const ports = Object.values(d.cfg.interfaces).filter((f) => !f.name.startsWith('Vlan') && f.mode !== 'trunk' && f.accessVlan === id).sort((a, b) => ifSort(a.name, b.name)).map((f) => shortIf(f.name));
        const chunks = [];
        for (let i = 0; i < ports.length; i += 4) chunks.push(ports.slice(i, i + 4).join(', '));
        out.push(`${String(id).padEnd(5)}${d.cfg.vlans[id].name.padEnd(33)}active    ${chunks[0] || ''}`);
        for (const c of chunks.slice(1)) out.push(' '.repeat(48) + c);
      }
      for (const [id, n] of [[1002, 'fddi-default'], [1003, 'token-ring-default'], [1004, 'fddinet-default'], [1005, 'trnet-default']]) out.push(`${String(id).padEnd(5)}${n.padEnd(33)}act/unsup`);
      return out;
    }
    showTrunk(d) {
      const trunks = Object.values(d.cfg.interfaces).filter((f) => f.mode === 'trunk' && !f.shutdown);
      if (!trunks.length) return [''];
      const out = ['Port        Mode         Encapsulation  Status        Native vlan'];
      for (const t of trunks) out.push(`${shortIf(t.name).padEnd(12)}${(t.nonegotiate ? 'on' : 'auto').padEnd(13)}802.1q         trunking      ${t.nativeVlan}`);
      const allowed = (t) => (t.trunkAllowed ? compressVlans([...t.trunkAllowed]) : '1-1005');
      const active = (t) => compressVlans(Object.keys(d.cfg.vlans).map(Number).filter((v) => this.trunkAllows(t, v)));
      out.push('', 'Port        Vlans allowed on trunk');
      for (const t of trunks) out.push(`${shortIf(t.name).padEnd(12)}${allowed(t)}`);
      out.push('', 'Port        Vlans allowed and active in management domain');
      for (const t of trunks) out.push(`${shortIf(t.name).padEnd(12)}${active(t)}`);
      out.push('', 'Port        Vlans in spanning tree forwarding state and not pruned');
      for (const t of trunks) out.push(`${shortIf(t.name).padEnd(12)}${active(t)}`);
      return out;
    }
    showPortSec(d) {
      const out = ['Secure Port MaxSecureAddr CurrentAddr SecurityViolation Security Action', '               (Count)       (Count)        (Count)', '--------------------------------------------------------------------'];
      let any = false;
      for (const f of Object.values(d.cfg.interfaces).sort((a, b) => ifSort(a.name, b.name))) {
        if (!f.portSecurity) continue;
        any = true;
        const cur = (this.secureMacs[d.name + '|' + f.name] || []).length;
        const vio = this.psViolations[d.name + '|' + f.name] || 0;
        out.push(`${shortIf(f.name).padStart(13)}${String(f.portSecurity.max).padStart(10)}${String(cur).padStart(12)}${String(vio).padStart(18)}         ${cap(f.portSecurity.violation)}`);
      }
      out.push('----------------------------------------------------------------------');
      if (!any) out.push('(port security is not enabled on any interface)');
      return out;
    }
    showPortSecIf(d, name) {
      const f = d.cfg.interfaces[name];
      if (!f) return ['% Invalid interface'];
      if (!f.portSecurity) return [`Port Security              : Disabled`, `Port Status                : Secure-down`];
      const macs = this.secureMacs[d.name + '|' + name] || [];
      const vio = this.psViolations[d.name + '|' + name] || 0;
      return [
        'Port Security              : Enabled',
        `Port Status                : Secure-up`,
        `Violation Mode             : ${cap(f.portSecurity.violation)}`,
        'Aging Time                 : 0 mins',
        'Aging Type                 : Absolute',
        'SecureStatic Address Aging : Disabled',
        `Maximum MAC Addresses      : ${f.portSecurity.max}`,
        `Total MAC Addresses        : ${macs.length}`,
        'Configured MAC Addresses   : 0',
        `Sticky MAC Addresses       : ${f.portSecurity.sticky ? macs.length : 0}`,
        `Last Source Address:Vlan   : ${macs[macs.length - 1] || '0000.0000.0000'}:${f.accessVlan}`,
        `Security Violation Count   : ${vio}`
      ];
    }
    showMac(d) {
      const out = ['          Mac Address Table', '-------------------------------------------', '', 'Vlan    Mac Address       Type        Ports', '----    -----------       --------    -----'];
      const rows = [];
      for (const p of this.portsOf[d.name] || []) {
        const pc = this.portCfg(d, p);
        if (pc.mode === 'trunk') {
          const peer = this.linkMap.get(d.name + '|' + p);
          const mac = macOf(peer.dev + '|' + peer.port);
          for (const v of Object.keys(d.cfg.vlans).map(Number)) if (this.trunkAllows(pc, v) && v < 1000) rows.push([v, mac, 'DYNAMIC', p]);
        } else {
          const secure = this.secureMacs[d.name + '|' + p];
          for (const h of this.hostsBehind(d.name, p)) {
            const sticky = secure && secure.includes(h.mac);
            if (secure && !sticky) continue;
            rows.push([pc.accessVlan, h.mac, sticky ? 'STATIC' : 'DYNAMIC', p]);
          }
        }
      }
      rows.sort((a, b) => a[0] - b[0]);
      for (const r of rows) out.push(`${String(r[0]).padStart(4)}    ${r[1]}    ${r[2].padEnd(12)}${shortIf(r[3])}`);
      return out;
    }
    showSwitchIpBrief(d) {
      const out = ['Interface              IP-Address      OK? Method Status                Protocol'];
      for (const n of Object.keys(d.cfg.interfaces).sort(ifSort)) {
        const f = d.cfg.interfaces[n];
        const linked = this.linkMap.has(d.name + '|' + n) || n.startsWith('Vlan');
        const status = f.shutdown ? 'administratively down' : linked ? 'up' : 'down';
        out.push(`${n.padEnd(23)}${(f.ip || 'unassigned').padEnd(16)}YES ${(f.ip ? 'manual' : 'unset').padEnd(7)}${status.padEnd(22)}${status === 'up' ? 'up' : 'down'}`);
      }
      return out;
    }
    showNameif(d) {
      const out = ['Interface                Name                     Security'];
      for (const f of Object.values(d.cfg.interfaces)) if (f.nameif) out.push(`${f.name.padEnd(25)}${f.nameif.padEnd(25)}${String(f.secLevel).padStart(3)}`);
      return out;
    }
    showAsaIp(d) {
      const out = ['System IP Addresses:', 'Interface                Name                   IP address      Subnet mask     Method'];
      for (const f of Object.values(d.cfg.interfaces)) if (f.name.startsWith('Vlan')) out.push(`${f.name.padEnd(25)}${(f.nameif || '').padEnd(23)}${(f.ip || 'unassigned').padEnd(16)}${(f.mask || 'unassigned').padEnd(16)}${f.ip ? 'CONFIG' : 'unset'}`);
      return out;
    }
    showAsaRoute(d) {
      const out = ['Codes: C - connected, S - static, * - candidate default', ''];
      for (const f of Object.values(d.cfg.interfaces)) if (f.nameif && f.ip) out.push(`C    ${netOf(f.ip, f.mask)} ${f.mask} is directly connected, ${f.nameif}`);
      for (const r of d.cfg.routes) out.push(`S${r.net === '0.0.0.0' ? '*' : ' '}   ${r.net} ${r.mask} [1/0] via ${r.gw}, ${r.nameif}`);
      return out;
    }
    showAsaSwitchVlan(d) {
      const out = ['VLAN Name                             Status    Ports', '---- -------------------------------- --------- ---------------------------'];
      const vlans = Object.values(d.cfg.interfaces).filter((f) => f.name.startsWith('Vlan'));
      for (const v of vlans) {
        const id = Number(v.name.slice(4));
        const ports = Object.values(d.cfg.interfaces).filter((f) => f.name.startsWith('Ethernet') && f.accessVlan === id).map((f) => shortIf(f.name, true));
        out.push(`${String(id).padEnd(5)}${(v.nameif || '-').padEnd(33)}${(v.shutdown ? 'down' : 'up').padEnd(10)}${ports.join(', ')}`);
      }
      return out;
    }
    showAsaAcl(d) {
      const out = [];
      for (const acl of Object.values(d.cfg.acls)) {
        out.push(`access-list ${acl.name}; ${acl.entries.length} elements`);
        acl.entries.forEach((e, i) => out.push(`access-list ${acl.name} line ${e.seq} extended ${e.text} (hitcnt=${this.aclHits[d.name + '|' + acl.name + '|' + i] || 0})`));
      }
      for (const [nameif, acl] of Object.entries(d.cfg.accessGroups)) out.push(`! access-group ${acl} in interface ${nameif}`);
      return out.length ? out : ['(no access lists)'];
    }
    showXlate(d) {
      const out = [];
      const statics = Object.values(d.cfg.objects).filter((o) => o.nat && o.nat.type === 'static');
      const dyn = this.conns.filter((c) => c.dev === d.name && c.inSrc !== c.outSrc).slice(-10);
      out.push(`${statics.length + dyn.length} in use`, 'Flags: D - DNS, e - extended, I - identity, i - dynamic, r - portmap,', '       s - static, T - twice, N - net-to-net');
      for (const o of statics) out.push(`NAT from ${o.nat.real}:${o.net} to ${o.nat.mapped}:${o.nat.mappedAddr}`, '    flags s idle 0:00:00 timeout 0:00:00');
      for (const c of dyn) out.push(`${c.proto.toUpperCase()} PAT from ${c.inIf}:${c.inSrc}/${c.sport || c.id} to ${c.outIf}:${c.outSrc}/${c.sport || c.id} flags ri idle 0:00:01 timeout 0:00:30`);
      return out;
    }
    showConn(d) {
      const list = this.conns.filter((c) => c.dev === d.name).slice(-12);
      const out = [`${list.length} in use, ${this.conns.length} most used`];
      for (const c of list) out.push(`${c.proto.toUpperCase()} ${c.outIf} ${c.outDst}${c.dport ? ':' + c.dport : ''} ${c.inIf} ${c.inSrc}${c.sport ? ':' + c.sport : ''}, idle 0:00:01, bytes 64, flags ${c.proto === 'tcp' ? 'UIO' : ''}`);
      return out;
    }
    showNat(d) {
      const out = ['Auto NAT Policies (Section 2)'];
      let i = 1;
      for (const o of Object.values(d.cfg.objects)) if (o.nat) out.push(`${i++} (${o.nat.real}) to (${o.nat.mapped}) source ${o.nat.type} ${o.name} ${o.nat.mappedAddr}`);
      return out;
    }

    // Host-side commands for the PC "Command Prompt".
    hostCommand(devName, line) {
      const d = this.devices[devName];
      const words = String(line).trim().split(/\s+/);
      const c = (words[0] || '').toLowerCase();
      if (!c) return { out: [] };
      if (c === 'ipconfig') {
        const all = (words[1] || '').toLowerCase() === '/all';
        const out = ['', 'FastEthernet0 Connection:(default port)', ''];
        if (all) out.push(`   Physical Address................: ${d.mac}`);
        out.push(`   IPv4 Address....................: ${d.ip}`, `   Subnet Mask.....................: ${d.mask}`, `   Default Gateway.................: ${d.gw || '0.0.0.0'}`);
        if (all) out.push(`   DNS Servers.....................: ${d.dns || '0.0.0.0'}`);
        return { out };
      }
      if (c === 'ping') { if (!words[1]) return { out: ['Usage: ping <ip address | name>'] }; const r = this.ping(devName, words[words.length - 1], { count: (words.includes('-n') ? Number(words[words.indexOf('-n') + 1]) : 4) || 4 }); return { out: r.lines, exchanges: r.exchanges }; }
      if (c === 'tracert') { if (!words[1]) return { out: ['Usage: tracert <ip address | name>'] }; const r = this.tracert(devName, words[1]); return { out: r.lines, exchanges: r.exchanges }; }
      if (c === 'nslookup') { if (!words[1]) return { out: [`Server: [${d.dns || 'none'}]`] }; const r = this.nslookup(devName, words[1]); return { out: r.lines, exchanges: r.exchanges }; }
      if (c === 'arp') {
        const cache = this.arpCache(devName);
        if (!cache.size) return { out: ['No ARP Entries Found'] };
        const out = ['  Internet Address      Physical Address      Type'];
        for (const [ip, v] of cache) out.push(`  ${ip.padEnd(22)}${v.mac.padEnd(22)}dynamic`);
        return { out };
      }
      if (c === 'ssh' || c === 'telnet') {
        let target, user = 'admin';
        if (c === 'ssh') { const i = words.indexOf('-l'); if (i >= 0) { user = words[i + 1]; target = words[i + 2]; } else target = words[1]; }
        else target = words[1];
        if (!target) return { out: [c === 'ssh' ? 'Usage: ssh -l <username> <ip address>' : 'Usage: telnet <ip address>'] };
        const port = c === 'ssh' ? 22 : Number(words[2]) || 23;
        const r = this.connect(devName, target, port);
        const ex = r.exchange;
        const out = c === 'telnet' ? [`Trying ${r.ip || target} ...`] : [];
        if (r.status === 'dns-fail') out.push(`% Unknown command or computer name, or unable to find computer address`);
        else if (r.status === 'syn-ack') {
          const dev = this.devices[ex.request.to.dev];
          if (c === 'telnet' && port !== 23) out.push(`Open`, `Connected to ${r.ip} port ${port} (${SERVICE_NAMES[port] || 'service'}) on ${dev.name}.`, '[Connection closed by foreign host]');
          else out.push(c === 'ssh' ? '' : 'Open', `Password: ********`, '', dev.cfg && dev.cfg.banner ? dev.cfg.banner : '', `${dev.cfg ? dev.cfg.hostname : dev.name}# `, `[Simulated: ${c.toUpperCase()} session to ${dev.name} as ${user} is open. This proves the Management VLAN can administer the device.]`);
        } else if (r.status === 'rst') out.push('% Connection refused by remote host', ex.note ? `  (${ex.note})` : '');
        else if (r.status === 'unreachable') out.push('% Destination unreachable; gateway or host down', ex.reason ? `  (${ex.reason})` : '');
        else out.push('% Connection timed out; remote host not responding', ex.reason ? `  (${ex.reason})` : '');
        return { out: out.filter((x) => x !== undefined), exchanges: r.exchanges };
      }
      if (c === 'help' || c === '?') return { out: ['Available commands:', '  ipconfig [/all]', '  ping <ip|name> [-n count]', '  tracert <ip|name>', '  nslookup <name>', '  arp -a', '  ssh -l <user> <ip>', '  telnet <ip> [port]', '  cls'] };
      return { out: ['Invalid Command.'] };
    }
  }

  // ------------------------------------------------------------- utilities
  function isHostType(t) { return t === 'pc' || t === 'printer' || t === 'server' || t === 'laptop'; }
  function isError(p) { return p.proto === 'icmp' && (p.icmpType === 'unreachable' || p.icmpType === 'time-exceeded'); }
  function isReplyType(p) {
    if (p.proto === 'icmp') return p.icmpType !== 'echo';
    if (p.proto === 'tcp') return !!(p.flags && (p.flags.ack || p.flags.rst));
    return false;
  }
  function isPrivate(ip) { return inRange(ip, '10.0.0.0', '255.0.0.0') || inRange(ip, '172.16.0.0', '255.240.0.0') || inRange(ip, '192.168.0.0', '255.255.0.0'); }
  function describe(p) {
    if (p.proto === 'icmp') return { echo: 'ICMP Echo Request', 'echo-reply': 'ICMP Echo Reply', unreachable: 'ICMP Destination Unreachable', 'time-exceeded': 'ICMP Time Exceeded' }[p.icmpType] || 'ICMP';
    if (p.proto === 'tcp') {
      const f = p.flags || {};
      const port = f.ack ? p.sport : p.dport;
      const svc = SERVICE_NAMES[port] || 'TCP';
      return `${svc} (TCP ${f.syn && f.ack ? 'SYN-ACK' : f.syn ? 'SYN' : f.rst ? 'RST' : 'segment'}, port ${port})`;
    }
    if (p.proto === 'udp') return p.dport === 53 ? `DNS query${p.query ? ' for ' + p.query : ''} (UDP 53)` : p.sport === 53 ? 'DNS response (UDP 53)' : `UDP port ${p.dport}`;
    return p.proto;
  }
  function matchAbbrev(input, full) {
    const a = input.split(/\s+/).filter(Boolean), b = full.split(/\s+/);
    if (a.length !== b.length) return false;
    return a.every((w, i) => b[i].startsWith(w));
  }
  function ifSort(a, b) {
    const k = (n) => { const m = n.match(/^([A-Za-z]+)(\d+)?\/?(\d+)?\.?(\d+)?/); return [m[1], Number(m[2] || 0), Number(m[3] || 0), Number(m[4] || 0)]; };
    const x = k(a), y = k(b);
    if (x[0] !== y[0]) return x[0] < y[0] ? -1 : 1;
    for (let i = 1; i < 4; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return 0;
  }
  function compressVlans(list) {
    const v = [...new Set(list)].sort((a, b) => a - b);
    const out = [];
    for (let i = 0; i < v.length; i++) {
      let j = i;
      while (j + 1 < v.length && v[j + 1] === v[j] + 1) j++;
      out.push(j > i ? `${v[i]}-${v[j]}` : String(v[i]));
      i = j;
    }
    return out.join(',');
  }
  function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }
  function fakeHash(v) {
    const chars = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let h = 2166136261, out = '$1$';
    for (let i = 0; i < 26; i++) { h = Math.imul(h ^ v.charCodeAt(i % v.length) ^ i, 16777619) >>> 0; out += chars[h % 64]; if (i === 3) out += '$'; }
    return out;
  }
  function fakeType7(v) {
    let out = '08';
    for (let i = 0; i < v.length; i++) out += ((v.charCodeAt(i) ^ 'dsfd;kfoA,.iyewrkldJKD'.charCodeAt(i % 22)) & 255).toString(16).padStart(2, '0').toUpperCase();
    return out;
  }

  return { Network, parseConfig, CONTROLS, ipToInt, intToIp, isIp, sameNet, describe, shortIf, canonIf };
});
