# Packet Tracer build guide

**Design and Implementation of a Secured Network Model for Mitigating Cybercrime (a simulation of VLAN using Packet Tracer)**

This guide rebuilds the network from Figure 3.4 of the project in Cisco Packet Tracer 8.x, with the configuration errors in Chapters 3 and 4 corrected. It also adds the pieces the report describes but never configures: extended ACLs, the ASA DMZ, and a simulated Internet. Allow about 45 minutes.

The browser simulator (`../index.html`) runs exactly these configs, so you can check every result before or after you build.

---

## 1. Design at a glance

| Zone | VLAN | Network | Gateway | Devices |
|---|---|---|---|---|
| Management | 1 | 192.168.1.0/24 | 192.168.1.1 (R1 Fa0/0.1) | PC10, PC11, PC12, Printer0 on Hub0 |
| Administrative | 2 | 192.168.2.0/24 | 192.168.2.1 (R1 Fa0/0.2) | PC13, PC14, PC15, Printer1 on Hub1 |
| Maintenance | 3 | 192.168.3.0/24 | 192.168.3.1 (R1 Fa0/0.3) | PC16, PC24, Printer2 on Hub4 |
| Account | 4 | 192.168.4.0/24 | 192.168.4.1 (R1 Fa0/0.4) | PC18, PC19, PC20, Printer3 on Hub2 |
| Works | 5 | 192.168.5.0/24 | 192.168.5.1 (R1 Fa0/0.5) | PC21, PC22, PC23, Printer4 on Hub3 |
| R1 to ASA (inside) | - | 172.16.0.0/30 | - | R1 Fa0/1 .1, ASA1 inside .2 |
| DMZ (security 70) | - | 172.16.50.0/24 | 172.16.50.1 (ASA1) | DMZ-Server 172.16.50.10 (web + DNS) |
| ASA to ISP (outside) | - | 209.165.200.224/29 | 209.165.200.225 (ISP) | ASA1 outside .226, DMZ-Server public .227 |
| Internet | - | 209.165.201.0/27 | 209.165.201.1 (ISP) | Internet-Server .10, Attacker-PC .20 |

**Security policy**

| From \ To | Management | Administrative | Maintenance | Account | Works | DMZ web + DNS | DMZ other | Internet | Log in to R1 |
|---|---|---|---|---|---|---|---|---|---|
| Management | yes | yes | yes | yes | yes | yes | yes | yes | yes (SSH) |
| Administrative | no | yes | yes | no | yes | yes | no | yes | no |
| Maintenance | no | yes | yes | no | yes | yes | no | yes | no |
| Account | no | no | no | yes | no | yes | no | yes | no |
| Works | no | yes | yes | no | yes | yes | no | yes | no |
| Internet | no | no | no | no | no | web only, via 209.165.200.227 | ping only | yes | no |
| DMZ server | no | no | no | no | no | - | - | yes | no |

How each "no" is enforced:

- **Between departments:** named extended ACLs inbound on R1's sub-interfaces. Replies to sessions that Management opens are allowed (`echo-reply`, `established`).
- **Logging in to R1 and Switch0:** `access-class 10` plus `transport input ssh` on the VTY lines.
- **The Internet:** private addressing with ASA PAT, plus `access-group OUTSIDE-DMZ`, which lets in only HTTP and ping to the web server.
- **The DMZ:** `no forward interface Vlan1`, so a compromised server cannot start connections to inside.
- **Rogue devices:** port security on Switch0's department ports.

---

## 2. Place the devices

| Packet Tracer location | Rename to | Qty |
|---|---|---|
| Network Devices › Routers › 1841 | R1, ISP | 2 |
| Network Devices › Switches › 2960 | Switch0, ISP-Switch | 2 |
| Network Devices › Security › 5505 | ASA1 | 1 |
| Network Devices › Hubs › Hub-PT | Hub0, Hub1, Hub2, Hub3, Hub4 | 5 |
| End Devices › PC-PT | PC10–PC16, PC18–PC24, Attacker-PC (there is no PC17) | 15 |
| End Devices › Printer-PT | Printer0–Printer4 | 5 |
| End Devices › Server-PT | DMZ-Server, Internet-Server | 2 |
| End Devices › Laptop-PT (optional) | Rogue-Laptop, used only for the port-security test | 1 |

To rename a device: click it › Config › Display Name.

## 3. Cable them

Pick the cable type yourself instead of the automatic lightning cable, so each device lands on the port the configs expect. The full list is in [cabling-plan.csv](cabling-plan.csv).

| From | Port | To | Port | Cable |
|---|---|---|---|---|
| R1 | Fa0/0 | Switch0 | Fa0/24 | Straight-through (this is the 802.1Q trunk) |
| R1 | Fa0/1 | ASA1 | Ethernet0/1 | Straight-through |
| ASA1 | Ethernet0/0 | ISP | Fa0/0 | Straight-through |
| ASA1 | Ethernet0/2 | DMZ-Server | Fa0 | Straight-through |
| ISP | Fa0/1 | ISP-Switch | Fa0/1 | Straight-through |
| ISP-Switch | Fa0/2, Fa0/3 | Internet-Server, Attacker-PC | Fa0 | Straight-through |
| Switch0 | Fa0/1 | Hub0 (Management) | Port 0 | **Cross-over** |
| Switch0 | Fa0/2 | Hub1 (Administrative) | Port 0 | **Cross-over** |
| Switch0 | Fa0/3 | Hub4 (Maintenance) | Port 0 | **Cross-over** |
| Switch0 | Fa0/4 | Hub2 (Account) | Port 0 | **Cross-over** |
| Switch0 | Fa0/5 | Hub3 (Works) | Port 0 | **Cross-over** |
| Each hub | Port 1–4 | its PCs and printer | Fa0 | Straight-through |

Do **not** connect Rogue-Laptop yet.

## 4. Address the hosts

Click each PC or server › Desktop › IP Configuration › Static. For printers use Config › Settings for the gateway and Config › FastEthernet0 for the address. The complete list is in [addressing-table.csv](addressing-table.csv).

| Device | VLAN | IPv4 address | Mask | Gateway | DNS |
|---|---|---|---|---|---|
| PC10, PC11, PC12 | 1 | 192.168.1.10, .11, .12 | 255.255.255.0 | 192.168.1.1 | 172.16.50.10 |
| Printer0 | 1 | 192.168.1.100 | 255.255.255.0 | 192.168.1.1 | - |
| PC13, PC14, PC15 | 2 | 192.168.2.13, .14, .15 | 255.255.255.0 | 192.168.2.1 | 172.16.50.10 |
| Printer1 | 2 | 192.168.2.100 | 255.255.255.0 | 192.168.2.1 | - |
| PC16, PC24 | 3 | 192.168.3.16, .24 | 255.255.255.0 | 192.168.3.1 | 172.16.50.10 |
| Printer2 | 3 | 192.168.3.100 | 255.255.255.0 | 192.168.3.1 | - |
| PC18, PC19, PC20 | 4 | 192.168.4.18, .19, .20 | 255.255.255.0 | 192.168.4.1 | 172.16.50.10 |
| Printer3 | 4 | 192.168.4.100 | 255.255.255.0 | 192.168.4.1 | - |
| PC21, PC22, PC23 | 5 | 192.168.5.21, .22, .23 | 255.255.255.0 | 192.168.5.1 | 172.16.50.10 |
| Printer4 | 5 | 192.168.5.100 | 255.255.255.0 | 192.168.5.1 | - |
| DMZ-Server | DMZ | 172.16.50.10 | 255.255.255.0 | 172.16.50.1 | 172.16.50.10 |
| Internet-Server | Internet | 209.165.201.10 | 255.255.255.224 | 209.165.201.1 | - |
| Attacker-PC | Internet | 209.165.201.20 | 255.255.255.224 | 209.165.201.1 | - |
| Rogue-Laptop (later) | 4 | 192.168.4.66 | 255.255.255.0 | 192.168.4.1 | 172.16.50.10 |

The last octet of every PC matches its name (PC13 is .13), so addresses are easy to remember in front of an examiner.

## 5. Paste the configs

Open each file in `configs/`, copy everything, click the device › CLI, and paste (right-click › Paste, or Ctrl+V). You can also copy them from the **Packet Tracer build kit** tab in the simulator.

| Device | File | Before pasting |
|---|---|---|
| R1 | [configs/R1.txt](configs/R1.txt) | Answer `no` to "initial configuration dialog", press Enter |
| Switch0 | [configs/Switch0.txt](configs/Switch0.txt) | Press Enter |
| ASA1 | [configs/ASA1.txt](configs/ASA1.txt) | Type `enable`, press Enter at the blank `Password:` prompt |
| ISP | [configs/ISP.txt](configs/ISP.txt) | Answer `no` to the setup dialog, press Enter |

Lab passwords (change them if you like, but keep at least 8 characters because R1 enforces `security passwords min-length 8`):

- enable secret: `Cyber@2026`
- console: `Console@2026`
- SSH user: `admin` / `Admin@2026`

`crypto key generate rsa` asks for a key size. The config file puts `1024` on the next line, which answers the prompt.

## 6. Set up the servers

1. **DMZ-Server** › Services › HTTP: On. Edit `index.html`, for example "Welcome to CyberLab Ltd".
2. **DMZ-Server** › Services › DNS: On. Add two A records:
   - `www.cyberlab.com` → `172.16.50.10`
   - `www.internet.com` → `209.165.201.10`
3. **Internet-Server** › Services › HTTP: On. Edit `index.html` to say "Public Internet website". Turn DNS off.
4. Leave FTP on (the default) on DMZ-Server. It shows that the firewall lets only the web service through from the Internet.
5. From PC10, ping every PC and printer once. This lets Switch0 learn their sticky MAC addresses before anything else is plugged in.
6. On every network device run `write memory` (already at the end of each config), then save the `.pkt` file.

## 7. Verify

| # | Device | Command | Expected result | Shows |
|---|---|---|---|---|
| 1 | Switch0 | `show vlan brief` | VLANs 1–5 on Fa0/1–Fa0/5, unused ports in VLAN 999 | Segmentation |
| 2 | Switch0 | `show interfaces trunk` | Fa0/24 trunking, 802.1q, VLANs 1–5 | Trunk to R1 |
| 3 | PC13 | `ping 192.168.2.1` | Replies | Own gateway |
| 4 | PC13 | `ping 192.168.5.21` | First packet may time out (ARP), then replies | Allowed department traffic |
| 5 | PC13 | `ping 192.168.4.18` | `Destination host unreachable` from 192.168.2.1 | Account protected (ACL line 40) |
| 6 | R1 | `show access-lists` | Match counter on `40 deny ip 192.168.2.0 ... 192.168.4.0 ...` | Proof of the ACL working |
| 7 | PC21 | `ping 192.168.1.10` | Destination host unreachable | Management protected |
| 8 | PC10 | `ping 192.168.4.18` | Replies | Management still has full access |
| 9 | PC18 | `ping 192.168.2.13` | Destination host unreachable | Account isolated |
| 10 | PC16 | Web Browser › `http://www.cyberlab.com` | Company page loads | DNS + HTTP allowed |
| 11 | PC16 | `ping 172.16.50.10` | Destination host unreachable | Only web and DNS to the DMZ |
| 12 | PC22 | `ssh -l admin 192.168.5.1` | `% Connection refused by remote host` | VTY access-class |
| 13 | PC10 | `ssh -l admin 192.168.1.1` | Password prompt, log in | Admin access over SSH |
| 14 | PC10 | `ping 209.165.201.10` | Replies (the first one or two may time out) | Internet through PAT |
| 15 | Attacker-PC | Web Browser › `http://209.165.200.227` | Company page loads | Static NAT to the DMZ |
| 16 | Attacker-PC | `ping 192.168.4.18` | Destination host unreachable (from the ISP) | Private networks hidden |
| 17 | DMZ-Server | `ping 192.168.1.10` | Request timed out | `no forward interface Vlan1` |
| 18 | ASA1 | `show nat`, `show xlate`, `show access-list` | PAT and static NAT entries, ACL hit counts | Firewall working |
| 19 | Connect Rogue-Laptop to Hub2 Port 5, then from it | `ping 192.168.4.1` | Request timed out | Port security |
| 20 | Switch0 | `show port-security` | Fa0/4 SecurityViolation count above 0 | Port security |

## 8. Changes from the report, and why

These corrections are worth knowing in case an examiner compares the network with Chapters 3 and 4.

| Report | This build | Why |
|---|---|---|
| ASA inside `192.168.1.1`, outside `192.168.2.1` | ASA on its own links: inside 172.16.0.2/30, outside 209.165.200.226/29, DMZ 172.16.50.1/24 | The report's addresses are the same as R1 Fa0/0.1 and Fa0/0.2, which causes IP conflicts |
| Figure 3.4 labels VLANs 2–5 as `192.16.x.0/24` | `192.168.x.0/24` | Typo in the figure; the router config uses 192.168.x |
| Section 3.4 sets Fa0/24 to access VLAN 1, then VLAN 2, then trunk | Fa0/1–Fa0/5 are access ports (one per hub); only Fa0/24 is the trunk | The same port cannot be both |
| VLANs named pc10, pc11, pc12, pc13 | ADMINISTRATIVE, MAINTENANCE, ACCOUNT, WORKS; VLAN 1 stays "default" | IOS cannot rename VLAN 1; department names match Section 4.4(b) |
| `encapsulation dot1Q 1` | `encapsulation dot1Q 1 native` | VLAN 1 is untagged on the trunk |
| Chapter 5 says extended ACLs were used, but none are configured | Four named extended ACLs on R1 | Turns the VLAN design into an enforced security policy |
| Section 5.2: VLAN 1 (management) still reachable | ACLs block 192.168.1.0/24 from the other departments; VTY limited to Management over SSH | Fixes the weakness the report admits |
| Section 4.4(c) mentions `no forward interface vlan 1` | Configured on Vlan3 (dmz) before `nameif` | The ASA 5505 base licence requires it for a third zone |
| Section 4.4(b): the first message fails "because of authorisation" | The first ping is lost to ARP resolution | The router drops the first packet while it learns the destination MAC address; later pings succeed |
| Text mentions three Catalyst 3560 switches and a 2811 router | One 2960-24TT and one 1841, as in Figure 3.4 | Matches what was actually built |

**Known limitation (good to raise yourself):** the departments use hubs, as in Figure 3.4. A hub repeats every frame to every port, so a device on a hub can see and reach its neighbours on the same hub, even with port security. The fix is to replace each hub with an access switch, one port per PC. The rogue-laptop scenario in the simulator demonstrates this.

## 9. Five-minute defence demo

1. Show the topology: five department VLANs on Switch0, R1 router-on-a-stick, ASA firewall with DMZ and Internet.
2. On Switch0: `show vlan brief`, `show interfaces trunk`.
3. From PC13, ping a Works PC (allowed), then an Account PC (blocked). On R1, `show access-lists` and point at the match counter.
4. From PC10 (Management), ping the same Account PC: administrators keep access.
5. From PC22, `ssh -l admin 192.168.5.1`: refused. From PC10, `ssh -l admin 192.168.1.1`: accepted.
6. From Attacker-PC, open `http://209.165.200.227` (works), then `ping 192.168.4.18` (unreachable).
7. Plug Rogue-Laptop into Hub2 and ping its gateway: dropped by port security.
