#!/usr/bin/env node
/*
 * Verifies the security policy produced by the Packet Tracer configs.
 *   node tests/engine.test.js
 */
'use strict';
const assert = require('assert');
const path = require('path');
const root = path.resolve(__dirname, '..');
const topo = require(path.join(root, 'assets', 'topology.js'));
const configs = require(path.join(root, 'assets', 'configs.js'));
const { Network } = require(path.join(root, 'assets', 'engine.js'));

let passed = 0, failed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}
const ok = (ex) => ['echo-reply', 'syn-ack', 'dns'].includes(ex.status);
const expectOk = (ex, msg) => assert.ok(ok(ex), `${msg}: expected success, got ${ex.status} (${ex.reason || ''})`);
const expectBlocked = (ex, msg) => assert.ok(!ok(ex), `${msg}: expected blocked, got ${ex.status}`);

const secured = new Network(topo, configs);
const reps = { 1: 'PC10', 2: 'PC13', 3: 'PC16', 4: 'PC18', 5: 'PC21' };
const targets = { 1: '192.168.1.11', 2: '192.168.2.14', 3: '192.168.3.24', 4: '192.168.4.19', 5: '192.168.5.22' };
// row = source VLAN, column = destination VLAN
const allowed = {
  1: { 1: 1, 2: 1, 3: 1, 4: 1, 5: 1 },
  2: { 1: 0, 2: 1, 3: 1, 4: 0, 5: 1 },
  3: { 1: 0, 2: 1, 3: 1, 4: 0, 5: 1 },
  4: { 1: 0, 2: 0, 3: 0, 4: 1, 5: 0 },
  5: { 1: 0, 2: 1, 3: 1, 4: 0, 5: 1 }
};

console.log('\nInter-VLAN ping policy (secured)');
for (let s = 1; s <= 5; s++) for (let d = 1; d <= 5; d++) {
  check(`VLAN ${s} (${reps[s]}) -> VLAN ${d} (${targets[d]}) ${allowed[s][d] ? 'allowed' : 'blocked'}`, () => {
    const ex = secured.test(reps[s], { proto: 'icmp', dst: targets[d] });
    if (allowed[s][d]) expectOk(ex, 'ping'); else expectBlocked(ex, 'ping');
  });
}

console.log('\nServices');
for (let v = 1; v <= 5; v++) {
  check(`VLAN ${v} can browse the DMZ web server`, () => expectOk(secured.test(reps[v], { proto: 'tcp', dst: '172.16.50.10', port: 80 }), 'http'));
  check(`VLAN ${v} can resolve names on the DMZ DNS server`, () => expectOk(secured.test(reps[v], { proto: 'udp', dst: '172.16.50.10', port: 53, query: 'www.cyberlab.com' }), 'dns'));
  check(`VLAN ${v} can reach the Internet web server (PAT)`, () => expectOk(secured.test(reps[v], { proto: 'tcp', dst: '209.165.201.10', port: 80 }), 'http'));
  check(`VLAN ${v} can ping the Internet (ICMP inspection)`, () => expectOk(secured.test(reps[v], { proto: 'icmp', dst: '209.165.201.10' }), 'ping'));
  check(`VLAN ${v} ${v === 1 ? 'can' : 'cannot'} ping the DMZ server`, () => {
    const ex = secured.test(reps[v], { proto: 'icmp', dst: '172.16.50.10' });
    if (v === 1) expectOk(ex, 'ping'); else expectBlocked(ex, 'ping');
  });
  check(`VLAN ${v} ${v === 1 ? 'can' : 'cannot'} SSH to its gateway on R1`, () => {
    const ex = secured.test(reps[v], { proto: 'tcp', dst: `192.168.${v}.1`, port: 22 });
    if (v === 1) expectOk(ex, 'ssh'); else assert.strictEqual(ex.status, v === 4 ? 'unreachable' : 'rst', 'expected refusal');
  });
}
check('Telnet to R1 is refused even from Management (SSH only)', () => assert.strictEqual(secured.test('PC10', { proto: 'tcp', dst: '192.168.1.1', port: 23 }).status, 'rst'));
check('Management can SSH to Switch0', () => expectOk(secured.test('PC10', { proto: 'tcp', dst: '192.168.1.2', port: 22 }), 'ssh'));
check('Administrative cannot reach Switch0 management', () => expectBlocked(secured.test('PC13', { proto: 'icmp', dst: '192.168.1.2' }), 'ping'));
check('Management can ping the ASA inside interface', () => expectOk(secured.test('PC10', { proto: 'icmp', dst: '172.16.0.2' }), 'ping'));
check('Works cannot reach the ASA inside interface', () => expectBlocked(secured.test('PC21', { proto: 'icmp', dst: '172.16.0.2' }), 'ping'));
check('Management can SSH to the ASA', () => expectOk(secured.test('PC10', { proto: 'tcp', dst: '172.16.0.2', port: 22 }), 'ssh'));
check('Printers answer pings inside their VLAN', () => expectOk(secured.test('PC13', { proto: 'icmp', dst: '192.168.2.100' }), 'ping'));

console.log('\nInternet attacker');
check('cannot reach a private department address', () => assert.strictEqual(secured.test('Attacker-PC', { proto: 'icmp', dst: '192.168.4.18' }).status, 'unreachable'));
check('can open the public website (static NAT 209.165.200.227)', () => expectOk(secured.test('Attacker-PC', { proto: 'tcp', dst: '209.165.200.227', port: 80 }), 'http'));
check('can ping the public website address', () => expectOk(secured.test('Attacker-PC', { proto: 'icmp', dst: '209.165.200.227' }), 'ping'));
check('cannot reach FTP on the DMZ server', () => expectBlocked(secured.test('Attacker-PC', { proto: 'tcp', dst: '209.165.200.227', port: 21 }), 'ftp'));
check('cannot use the company DNS server', () => expectBlocked(secured.test('Attacker-PC', { proto: 'udp', dst: '209.165.200.227', port: 53, query: 'www.cyberlab.com' }), 'dns'));
check('cannot SSH to the ASA outside interface', () => expectBlocked(secured.test('Attacker-PC', { proto: 'tcp', dst: '209.165.200.226', port: 22 }), 'ssh'));
check('cannot reach the PAT address on any port', () => expectBlocked(secured.test('Attacker-PC', { proto: 'tcp', dst: '209.165.200.226', port: 80 }), 'http'));

console.log('\nCompromised DMZ server');
check('cannot reach the Management VLAN (no forward)', () => expectBlocked(secured.test('DMZ-Server', { proto: 'icmp', dst: '192.168.1.10' }), 'ping'));
check('cannot reach the Account VLAN', () => expectBlocked(secured.test('DMZ-Server', { proto: 'tcp', dst: '192.168.4.18', port: 80 }), 'tcp'));
check('can still reach the Internet', () => expectOk(secured.test('DMZ-Server', { proto: 'tcp', dst: '209.165.201.10', port: 80 }), 'http'));

console.log('\nRogue laptop on the Account hub');
const rogue = new Network(topo, configs, { rogue: true });
check('blocked from its gateway by port security', () => {
  const ex = rogue.test('Rogue-Laptop', { proto: 'icmp', dst: '192.168.4.1' });
  expectBlocked(ex, 'ping');
  assert.ok(/port security/i.test(ex.reason), 'reason should mention port security: ' + ex.reason);
});
check('blocked from the Internet', () => expectBlocked(rogue.test('Rogue-Laptop', { proto: 'tcp', dst: '209.165.201.10', port: 80 }), 'http'));
check('still reaches PCs on the same hub (hubs are a weakness)', () => expectOk(rogue.test('Rogue-Laptop', { proto: 'icmp', dst: '192.168.4.19' }), 'ping'));
check('legitimate Account PC is unaffected', () => expectOk(rogue.test('PC18', { proto: 'tcp', dst: '172.16.50.10', port: 80 }), 'http'));
const rogueOpen = new Network(topo, configs, { rogue: true, controls: { portSecurity: false } });
check('without port security the rogue reaches the gateway', () => expectOk(rogueOpen.test('Rogue-Laptop', { proto: 'icmp', dst: '192.168.4.1' }), 'ping'));

console.log('\nControls switched off (unsecured baseline)');
const open = new Network(topo, configs, { controls: { acls: false, vty: false, portSecurity: false, asaInbound: false } });
check('Administrative reaches Account', () => expectOk(open.test('PC13', { proto: 'icmp', dst: '192.168.4.18' }), 'ping'));
check('Works reaches Management', () => expectOk(open.test('PC21', { proto: 'icmp', dst: '192.168.1.10' }), 'ping'));
check('Any department can SSH to R1', () => expectOk(open.test('PC21', { proto: 'tcp', dst: '192.168.5.1', port: 22 }), 'ssh'));
check('Attacker reaches FTP on the DMZ server', () => expectOk(open.test('Attacker-PC', { proto: 'tcp', dst: '209.165.200.227', port: 21 }), 'ftp'));
check('NAT still hides private addresses', () => expectBlocked(open.test('Attacker-PC', { proto: 'icmp', dst: '192.168.4.18' }), 'ping'));

console.log('\nCommand output');
const lab = new Network(topo, configs);
check('first ping across R1 loses one packet to ARP, like Packet Tracer', () => {
  const r = lab.ping('PC13', '192.168.5.21');
  assert.strictEqual(r.exchanges[0].status, 'timeout');
  assert.ok(r.exchanges.slice(1).every((e) => e.status === 'echo-reply'));
  assert.ok(lab.ping('PC13', '192.168.5.21').exchanges.every((e) => e.status === 'echo-reply'), 'second ping should be 4/4');
});
check('ACL hit counters increase', () => {
  lab.ping('PC13', '192.168.4.18');
  assert.ok(lab.cli('R1', 'show access-lists').out.some((l) => /40 deny ip 192\.168\.2\.0 0\.0\.0\.255 192\.168\.4\.0 0\.0\.0\.255 \(4 match/.test(l)));
});
check('nslookup resolves www.cyberlab.com', () => assert.ok(lab.nslookup('PC16', 'www.cyberlab.com').lines.some((l) => l.includes('172.16.50.10'))));
check('browser loads the company site by name', () => assert.strictEqual(lab.browse('PC22', 'http://www.cyberlab.com').view, 'page'));
check('tracert to the Internet shows R1 then filtered hops', () => {
  const r = lab.tracert('PC10', '209.165.201.10');
  assert.ok(r.lines.some((l) => l.includes('192.168.1.1')));
  assert.ok(r.lines.some((l) => l.includes('209.165.201.10')));
});
check('show port-security lists five secured ports', () => assert.strictEqual(lab.cli('Switch0', 'show port-security').out.filter((l) => /Restrict/.test(l)).length, 5));
check('show running-config hides passwords', () => {
  const run = lab.cli('R1', 'show running-config').out.join('\n');
  assert.ok(!run.includes('Cyber@2026') && !run.includes('Console@2026'));
});
check('ASA show xlate lists the static NAT', () => assert.ok(lab.cli('ASA1', 'show xlate').out.some((l) => l.includes('209.165.200.227'))));

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
