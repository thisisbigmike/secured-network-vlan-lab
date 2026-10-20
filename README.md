# SecureNet VLAN Lab

A working build of **"Design and Implementation of a Secured Network Model for Mitigating Cybercrime (a simulation of VLAN using Packet Tracer)"**.

It has two parts:

1. **Packet Tracer kit** (`packet-tracer/`): paste-ready configs for every Cisco device, plus the addressing plan, cabling plan and a step-by-step build and test guide.
2. **Browser simulator** (`index.html`): the same network running in any browser, offline. It reads the same config files, so a ping blocked here is blocked in Packet Tracer for the same reason, down to the ACL line number.

## Open the simulator

**Live:** https://thisisbigmike.github.io/secured-network-vlan-lab/

Or double-click **`index.html`** in this folder. It works offline and needs no install or internet connection.

| Tab | What it does |
|---|---|
| **Simulator** | Click any device. PCs have a Command Prompt (`ping`, `tracert`, `ipconfig`, `nslookup`, `ssh`, `telnet`, `arp -a`) and a Web Browser. R1, Switch0, ASA1 and ISP have an IOS-style CLI (`show vlan brief`, `show access-lists`, `show port-security`, `show xlate`, ...). Each command animates the packet and lists every hop, VLAN tag, ACL line and NAT translation. The **Security controls** switches turn the ACLs, VTY lockdown, port security and ASA inbound filter off and on live. |
| **Policy matrix** | Live grid of who can reach whom. Click a cell for the exact rule. Turn on "Compare with all security controls off" to see what the controls prevent. |
| **Attack scenarios** | Six cybercrime cases: insider access, device takeover, Internet scanning, rogue laptop, compromised DMZ server, least privilege. Each runs once secured and once unsecured. |
| **Packet Tracer build kit** | Device list, cabling, addresses, configs with Copy and Download buttons, a verification checklist, the corrections made to the report, and a five-minute defence demo. Printable. |

## The network

```
                         Internet (Attacker-PC, Internet-Server)
                                      |
                                    [ISP]  209.165.200.224/29
                                      |
   DMZ-Server 172.16.50.10 --- [ASA1 5505]  inside 100 / dmz 70 / outside 0, NAT + PAT
                                      |  172.16.0.0/30
                                    [R1 1841]  Fa0/0.1-.5 router-on-a-stick + extended ACLs
                                      |  802.1Q trunk (VLANs 1-5)
                                 [Switch0 2960]  port security on Fa0/1-5
        _____________________________|_____________________________
       |            |               |              |               |
     Hub0         Hub1            Hub4           Hub2            Hub3
   VLAN 1        VLAN 2          VLAN 3         VLAN 4          VLAN 5
 Management   Administrative   Maintenance     Account          Works
192.168.1.0  192.168.2.0     192.168.3.0     192.168.4.0     192.168.5.0
```

Policy: Management can reach everything. Administrative, Maintenance and Works can reach each other, but not Management or Account. Account is reachable only from Management. Every department gets the DMZ website and DNS, and the Internet. Only Management may log in to network devices, over SSH. From the Internet, only the company website (209.165.200.227) is visible.

## Files

```
index.html                     the simulator (open this)
assets/
  topology.js                  devices, links, host addresses, diagram layout
  configs.js                   generated from packet-tracer/configs (do not edit)
  engine.js                    packet-walk engine: VLANs, trunks, hubs, ACLs, ASA, NAT
  app.js, styles.css           the interface
packet-tracer/
  BUILD-GUIDE.md               step-by-step build, tests, corrections, defence demo
  configs/R1.txt               paste into R1's CLI
  configs/Switch0.txt          paste into Switch0's CLI
  configs/ASA1.txt             paste into ASA1's CLI
  configs/ISP.txt              paste into ISP's CLI
  addressing-table.csv         every IP address
  cabling-plan.csv             every cable and port
tools/build.js                 regenerates configs.js and the CSVs
tests/engine.test.js           90 checks of the security policy
```

## Changing the configs

Edit a file in `packet-tracer/configs/`, then run:

```bash
node tools/build.js
```

```bash
node tests/engine.test.js
```

The first command re-embeds the configs into the simulator. The second confirms the policy still behaves as described. Node.js is needed only for these two commands; the simulator itself runs without it.

## Lab credentials

| What | Value |
|---|---|
| enable secret (R1, Switch0, ISP, ASA1) | `Cyber@2026` |
| console password | `Console@2026` |
| SSH user | `admin` / `Admin@2026` |

These are lab values. They appear in the config files on purpose, so the network can be rebuilt.
