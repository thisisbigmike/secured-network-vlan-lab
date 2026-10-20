/*
 * SecureNet VLAN Lab - physical topology, host addressing and diagram layout.
 * Mirrors Figure 3.4 of the project report (R1 1841, Switch0 2960-24TT, ASA1 5505,
 * five department hubs) and adds the ISP, Internet and DMZ segments the ASA protects.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SECURENET_TOPOLOGY = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const DNS = '172.16.50.10';

  const vlans = [
    { id: 1, name: 'Management', ptName: 'default', subnet: '192.168.1.0/24', gateway: '192.168.1.1', hub: 'Hub0', switchPort: 'FastEthernet0/1', color: 'v1' },
    { id: 2, name: 'Administrative', ptName: 'ADMINISTRATIVE', subnet: '192.168.2.0/24', gateway: '192.168.2.1', hub: 'Hub1', switchPort: 'FastEthernet0/2', color: 'v2' },
    { id: 3, name: 'Maintenance', ptName: 'MAINTENANCE', subnet: '192.168.3.0/24', gateway: '192.168.3.1', hub: 'Hub4', switchPort: 'FastEthernet0/3', color: 'v3' },
    { id: 4, name: 'Account', ptName: 'ACCOUNT', subnet: '192.168.4.0/24', gateway: '192.168.4.1', hub: 'Hub2', switchPort: 'FastEthernet0/4', color: 'v4' },
    { id: 5, name: 'Works', ptName: 'WORKS', subnet: '192.168.5.0/24', gateway: '192.168.5.1', hub: 'Hub3', switchPort: 'FastEthernet0/5', color: 'v5' }
  ];

  const pc = (vlan, n, x, y) => ({ type: 'pc', model: 'PC-PT', zone: 'v' + vlan, ip: `192.168.${vlan}.${n}`, mask: '255.255.255.0', gw: `192.168.${vlan}.1`, dns: DNS, x, y });
  const printer = (vlan, x, y) => ({ type: 'printer', model: 'Printer-PT', zone: 'v' + vlan, ip: `192.168.${vlan}.100`, mask: '255.255.255.0', gw: `192.168.${vlan}.1`, dns: '', x, y });

  const devices = {
    // ---- core ----
    R1: { type: 'router', model: 'Cisco 1841', role: 'Inter-VLAN router + ACLs', config: 'R1', x: 560, y: 262 },
    Switch0: { type: 'switch', model: 'Cisco 2960-24TT', role: 'Core switch, 5 VLANs', config: 'Switch0', x: 560, y: 410 },
    ASA1: { type: 'asa', model: 'Cisco ASA 5505', role: 'Perimeter firewall', config: 'ASA1', x: 780, y: 262 },

    // ---- VLAN 1 Management ----
    Hub0: { type: 'hub', model: 'Hub-PT', zone: 'v1', x: 300, y: 188 },
    PC10: pc(1, 10, 92, 100), Printer0: printer(1, 232, 92), PC11: pc(1, 11, 82, 208), PC12: pc(1, 12, 186, 252),

    // ---- VLAN 2 Administrative ----
    Hub1: { type: 'hub', model: 'Hub-PT', zone: 'v2', x: 300, y: 446 },
    PC13: pc(2, 13, 92, 388), Printer1: printer(2, 232, 384), PC14: pc(2, 14, 82, 488), PC15: pc(2, 15, 186, 520),

    // ---- VLAN 3 Maintenance ----
    Hub4: { type: 'hub', model: 'Hub-PT', zone: 'v3', x: 520, y: 596 },
    PC16: pc(3, 16, 446, 680), PC24: pc(3, 24, 524, 690), Printer2: printer(3, 602, 680),

    // ---- VLAN 4 Account ----
    Hub2: { type: 'hub', model: 'Hub-PT', zone: 'v4', x: 780, y: 596 },
    PC18: pc(4, 18, 706, 680), PC19: pc(4, 19, 784, 690), PC20: pc(4, 20, 862, 680), Printer3: printer(4, 866, 590),

    // ---- VLAN 5 Works ----
    Hub3: { type: 'hub', model: 'Hub-PT', zone: 'v5', x: 994, y: 470 },
    PC21: pc(5, 21, 1112, 432), PC22: pc(5, 22, 1124, 540), PC23: pc(5, 23, 1090, 650), Printer4: printer(5, 984, 646),

    // ---- DMZ ----
    'DMZ-Server': {
      type: 'server', model: 'Server-PT', zone: 'dmz', ip: '172.16.50.10', mask: '255.255.255.0', gw: '172.16.50.1', dns: DNS, x: 780, y: 112,
      services: {
        http: { title: 'CyberLab Ltd - Company Website', heading: 'Welcome to CyberLab Ltd', body: 'This page is served from the DMZ web server (172.16.50.10). Staff reach it through R1 and the ASA; the public reach it on 209.165.200.227 through static NAT.' },
        dns: { 'www.cyberlab.com': '172.16.50.10', 'cyberlab.com': '172.16.50.10', 'www.internet.com': '209.165.201.10' },
        ftp: true
      }
    },

    // ---- Internet ----
    ISP: { type: 'router', model: 'Cisco 1841', role: 'Simulated ISP', config: 'ISP', zone: 'inet', x: 1040, y: 282 },
    'ISP-Switch': { type: 'switch', model: 'Cisco 2960-24TT', role: 'Internet LAN', config: null, zone: 'inet', x: 1040, y: 176 },
    'Internet-Server': {
      type: 'server', model: 'Server-PT', zone: 'inet', ip: '209.165.201.10', mask: '255.255.255.224', gw: '209.165.201.1', dns: '', x: 962, y: 92,
      services: { http: { title: 'www.internet.com', heading: 'Public Internet website', body: 'You reached a server on the public Internet. Your request left the company through the ASA, which translated your private address to 209.165.200.226 (PAT).' } }
    },
    'Attacker-PC': { type: 'pc', model: 'PC-PT', role: 'attacker', zone: 'inet', ip: '209.165.201.20', mask: '255.255.255.224', gw: '209.165.201.1', dns: '', x: 1118, y: 92 },

    // ---- Optional: rogue device for the port-security scenario ----
    'Rogue-Laptop': { type: 'laptop', model: 'Laptop-PT', role: 'rogue', optional: true, zone: 'v4', ip: '192.168.4.66', mask: '255.255.255.0', gw: '192.168.4.1', dns: DNS, x: 692, y: 588 }
  };

  // [deviceA, portA, deviceB, portB, cable]
  const links = [
    ['R1', 'FastEthernet0/0', 'Switch0', 'FastEthernet0/24', 'straight', '802.1Q trunk'],
    ['R1', 'FastEthernet0/1', 'ASA1', 'Ethernet0/1', 'straight', '172.16.0.0/30'],
    ['ASA1', 'Ethernet0/0', 'ISP', 'FastEthernet0/0', 'straight', '209.165.200.224/29'],
    ['ASA1', 'Ethernet0/2', 'DMZ-Server', 'FastEthernet0', 'straight', ''],
    ['ISP', 'FastEthernet0/1', 'ISP-Switch', 'FastEthernet0/1', 'straight', ''],
    ['ISP-Switch', 'FastEthernet0/2', 'Internet-Server', 'FastEthernet0', 'straight', ''],
    ['ISP-Switch', 'FastEthernet0/3', 'Attacker-PC', 'FastEthernet0', 'straight', ''],

    ['Switch0', 'FastEthernet0/1', 'Hub0', 'Port 0', 'cross', ''],
    ['Switch0', 'FastEthernet0/2', 'Hub1', 'Port 0', 'cross', ''],
    ['Switch0', 'FastEthernet0/3', 'Hub4', 'Port 0', 'cross', ''],
    ['Switch0', 'FastEthernet0/4', 'Hub2', 'Port 0', 'cross', ''],
    ['Switch0', 'FastEthernet0/5', 'Hub3', 'Port 0', 'cross', ''],

    ['Hub0', 'Port 1', 'PC10', 'FastEthernet0', 'straight', ''],
    ['Hub0', 'Port 2', 'PC11', 'FastEthernet0', 'straight', ''],
    ['Hub0', 'Port 3', 'PC12', 'FastEthernet0', 'straight', ''],
    ['Hub0', 'Port 4', 'Printer0', 'FastEthernet0', 'straight', ''],

    ['Hub1', 'Port 1', 'PC13', 'FastEthernet0', 'straight', ''],
    ['Hub1', 'Port 2', 'PC14', 'FastEthernet0', 'straight', ''],
    ['Hub1', 'Port 3', 'PC15', 'FastEthernet0', 'straight', ''],
    ['Hub1', 'Port 4', 'Printer1', 'FastEthernet0', 'straight', ''],

    ['Hub4', 'Port 1', 'PC16', 'FastEthernet0', 'straight', ''],
    ['Hub4', 'Port 2', 'PC24', 'FastEthernet0', 'straight', ''],
    ['Hub4', 'Port 3', 'Printer2', 'FastEthernet0', 'straight', ''],

    ['Hub2', 'Port 1', 'PC18', 'FastEthernet0', 'straight', ''],
    ['Hub2', 'Port 2', 'PC19', 'FastEthernet0', 'straight', ''],
    ['Hub2', 'Port 3', 'PC20', 'FastEthernet0', 'straight', ''],
    ['Hub2', 'Port 4', 'Printer3', 'FastEthernet0', 'straight', ''],
    ['Hub2', 'Port 5', 'Rogue-Laptop', 'FastEthernet0', 'straight', 'optional'],

    ['Hub3', 'Port 1', 'PC21', 'FastEthernet0', 'straight', ''],
    ['Hub3', 'Port 2', 'PC22', 'FastEthernet0', 'straight', ''],
    ['Hub3', 'Port 3', 'PC23', 'FastEthernet0', 'straight', ''],
    ['Hub3', 'Port 4', 'Printer4', 'FastEthernet0', 'straight', '']
  ];

  const zones = [
    { id: 'v1', label: 'VLAN 1 · Management', sub: '192.168.1.0/24 · gw .1', x: 18, y: 18, w: 364, h: 284 },
    { id: 'v2', label: 'VLAN 2 · Administrative', sub: '192.168.2.0/24 · gw .1', x: 18, y: 318, w: 364, h: 244 },
    { id: 'v3', label: 'VLAN 3 · Maintenance', sub: '192.168.3.0/24 · gw .1', x: 400, y: 524, w: 244, h: 218 },
    { id: 'v4', label: 'VLAN 4 · Account', sub: '192.168.4.0/24 · gw .1', x: 662, y: 524, w: 244, h: 218 },
    { id: 'v5', label: 'VLAN 5 · Works', sub: '192.168.5.0/24 · gw .1', x: 924, y: 366, w: 258, h: 376 },
    { id: 'dmz', label: 'DMZ · security 70', sub: '172.16.50.0/24', x: 690, y: 22, w: 180, h: 158 },
    { id: 'inet', label: 'Internet · untrusted', sub: '209.165.201.0/27', x: 900, y: 22, w: 282, h: 324 }
  ];

  return { vlans, devices, links, zones, viewBox: [0, 0, 1200, 760] };
});
