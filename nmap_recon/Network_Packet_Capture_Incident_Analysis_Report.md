# Network Packet Capture Incident Analysis Report

**Capture file:** `open_capture_aggressive_nmap_recon.pcapng`  
**PCAP SHA-256:** `8aebf5b23dbc5b6bad5f2693e85fa78bc0efdde0f27fe93561ae219849d50526`  
**Report date:** 2026-05-21  
**Analyst scope:** Packet evidence only. No endpoint, firewall, authentication, SIEM, EDR, vulnerability scanner, or asset inventory logs were available.

---

## 1. Executive Summary

The packet capture shows a **single internal host, `192.168.10.100`, performing aggressive reconnaissance and service enumeration against `192.168.20.100`**. The traffic pattern is strongly consistent with an **Nmap aggressive/service/version scan with NSE HTTP checks**, not with ordinary user browsing or normal application traffic.

The strongest evidence is:

- `192.168.10.100` sent **1,180 TCP SYN packets** to `192.168.20.100` across **1,000 distinct TCP destination ports**.
- `192.168.20.100` responded with SYN/ACKs on **23 observed open TCP ports**, including `21`, `22`, `23`, `25`, `53`, `80`, `111`, `139`, `445`, `512`, `513`, `514`, `1099`, `1524`, `2049`, `2121`, `3306`, `5432`, `5900`, `6000`, `6667`, `8009`, and `8180`.
- HTTP probes used the explicit User-Agent: `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`.
- Service banners exposed multiple legacy/vulnerable services, including `vsFTPd 2.3.4`, `OpenSSH_4.7p1 Debian-8ubuntu1`, `Apache/2.2.8 (Ubuntu) DAV/2`, `PHP/5.2.4`, `Apache-Coyote/1.1`, `Tomcat/5.5`, `ProFTPD 1.3.1`, MySQL `5.0.51a-3ubuntu5`, PostgreSQL, VNC, IRC, SMB, X11, and RPC/NFS-related services.
- A shell-like service on TCP `1524` returned `root@metasploitable:/#`; the scanner sent `exit`. This proves exposure of an interactive root shell prompt in the capture, but does **not** prove malicious command execution beyond exiting the session.

**Most likely scenario:** a reconnaissance scan from `192.168.10.100` against an intentionally vulnerable or poorly hardened Linux host at `192.168.20.100`. The target exposes banners strongly associated with a Metasploitable-style lab system. If this is a production environment, the exposed services represent severe risk. If this is a lab, the traffic is consistent with expected training or penetration-testing activity.

**Severity assessment:** **High for exposed target risk if this is a real production asset; Medium for observed incident activity** because the PCAP confirms reconnaissance and limited service interaction, but does not show data theft, persistence, malware, lateral movement, or destructive activity.

**Immediate recommendation:** verify whether `192.168.10.100` was authorized to perform scanning. If unauthorized, isolate and investigate the scanner host. Independently, quarantine or firewall `192.168.20.100` until its exposed services and legacy software are validated, especially TCP `1524`, FTP, Telnet, r-services, SMB, databases, Tomcat, and VNC.

---

## 2. Scope and Capture Details

| Item | Value |
|---|---:|
| Capture start time | `2026-05-20T10:52:21.197332Z` |
| Capture end time | `2026-05-20T10:59:32.169737Z` |
| Duration | `430.972404` seconds, approximately 7 minutes 11 seconds |
| Local time equivalent, Nepal UTC+05:45 | `2026-05-20 16:37:21` to `16:44:32` NPT |
| Total packets | `3,483` |
| Total captured/original bytes | `262,605` bytes |
| Interface name in PCAPNG | `eth0` |
| Link type | Ethernet, link type `1` |
| Snap length | `262,144` bytes |
| Timestamp resolution | nanoseconds |
| Observed IP version | IPv4 only |

### Analysis Methods Used

The capture was parsed directly as PCAPNG and packet headers/payloads were decoded for:

- Ethernet, ARP, IPv4, TCP, UDP, ICMP.
- TCP SYN/SYN-ACK/RST behavior.
- Top endpoints, conversations, protocols, ports, and byte counts.
- DNS query behavior.
- HTTP request/response payloads and service banners.
- Visible application banners on FTP, SSH, SMTP, MySQL, PostgreSQL, VNC, IRC, HTTP, Tomcat, SMB, RPC/NFS, and r-services.

### Analysis Limitations

- No endpoint logs were available.
- No firewall, IDS/IPS, proxy, DNS server, SIEM, EDR, authentication, or vulnerability scanner logs were available.
- No packet comments or analyst annotations were present in the parsed capture metadata.
- TCP stream IDs from Wireshark are unavailable from this analysis environment, so frame numbers, addresses, ports, timestamps, and payload evidence are used instead.
- MAC vendor lookup was not performed through an authoritative vendor database. MAC addresses are listed as observed, with vendor left unverified.
- This PCAP cannot prove user intent, authorization status, process name, terminal commands outside packet payload, or whether either host was compromised before or after the capture.

---

## 3. Key Findings

### Finding 1 — Aggressive TCP Port Reconnaissance Against `192.168.20.100`

**Confidence:** High  
**Severity contribution:** Medium for activity; High if unauthorized  
**Timestamp range:** `2026-05-20T10:52:50.626462Z` to `2026-05-20T10:55:50.465038Z` for observed SYN scan activity  
**Source:** `192.168.10.100`  
**Destination:** `192.168.20.100`  
**Protocol:** TCP  
**Evidence:**

- `192.168.10.100` generated **1,180 TCP SYN packets** to a single destination host.
- The SYN packets targeted **1,000 distinct destination ports**.
- First observed TCP SYN: frame `22`, `192.168.10.100:38206 -> 192.168.20.100:443`, `2026-05-20T10:52:50.626462Z`.
- Early burst example: frames `33-36` show sequential rapid connection attempts from `192.168.10.100:38462` to ports `135`, `8888`, `3306`, and `1723`.
- Late scan examples include frames `3270-3272`, `192.168.10.100` using low source ports to `192.168.20.100:111`, and frame `3348` to TCP `8180`.

**Reproducible filters/methods:**

```wireshark
ip.src == 192.168.10.100 && ip.dst == 192.168.20.100 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

```wireshark
ip.addr == 192.168.20.100 && tcp
```

**Interpretation:** The volume, one-to-one host relationship, and broad port coverage are consistent with automated port scanning. Later service probes and explicit Nmap NSE user agents confirm the reconnaissance nature.

**Unknowns:** Authorization status cannot be determined from PCAP alone. Confirm with change tickets, penetration-test approvals, vulnerability scan schedules, EDR process records, and user activity logs from `192.168.10.100`.

---

### Finding 2 — Target Host Exposes 23 Observed Open TCP Ports

**Confidence:** High  
**Severity contribution:** High if production; expected if intentionally vulnerable lab host  
**Affected host:** `192.168.20.100`  
**Evidence method:** TCP SYN from scanner followed by SYN/ACK from target.

Observed open TCP ports based on SYN/ACK responses from `192.168.20.100`:

| Port | Likely service from packet evidence | Evidence examples |
|---:|---|---|
| 21 | FTP / vsFTPd | Frame `2244`: `220 (vsFTPd 2.3.4)` |
| 22 | SSH | Frame `2239`: `SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1` |
| 23 | Telnet | Frame `2402`: Telnet negotiation bytes |
| 25 | SMTP / Postfix | Frame `2412`: `220 metasploitable.localdomain ESMTP Postfix (Ubuntu)` |
| 53 | DNS/BIND | Frame `2324`: `version.bind` response includes `9.4.2` |
| 80 | HTTP / Apache | Frame `2381`: `Apache/2.2.8 (Ubuntu) DAV/2`, PHP `5.2.4` |
| 111 | RPCBind | Frames `2309`, `3141`, `3194`, `3229` show RPC-like responses |
| 139 | NetBIOS/SMB | Frame `2447`: SMB response with `WORKGROUP` |
| 445 | SMB | Frame `2321`: SMB response with `WORKGROUP` |
| 512 | rexec/rlogin-style service | Frame `2399`: `Where are you?` |
| 513 | rlogin/rsh-style service | Multiple one-byte responses and repeated attempts |
| 514 | shell/syslog/r-service behavior | Frame `2408`: `getnameinfo: Temporary failure in name resolution` |
| 1099 | Java RMI | Frame `2296`: payload includes `localhost` |
| 1524 | Shell/backdoor-like service | Frame `2253`: `root@metasploitable:/#`; frame `2256`: client sent `exit` |
| 2049 | NFS | Frame `2297`: RPC/NFS-like binary response |
| 2121 | FTP / ProFTPD | Frame `2557`: `220 ProFTPD 1.3.1 Server (Debian)` |
| 3306 | MySQL | Frame `2388`: `5.0.51a-3ubuntu5`; frame `2389`: `Bad handshake` |
| 5432 | PostgreSQL | Frame `2376`: PostgreSQL fatal protocol response |
| 5900 | VNC | Frame `2234`: `RFB 003.003` |
| 6000 | X11 | Frame `2353`: `Client is not authorized to connect to Server` |
| 6667 | IRC | Frames `2260`, `2395`, `2396`: IRC notices from `irc.Metasploitable.LAN` |
| 8009 | AJP/Tomcat connector | Frame `2470`: binary AJP-like response |
| 8180 | HTTP/Tomcat | Frames `2589`, `2596`, `3339`, `3360`: Apache-Coyote/Tomcat HTTP responses |

**Reproducible filters/methods:**

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.src == 192.168.20.100
```

```wireshark
ip.addr == 192.168.20.100 && tcp contains "SSH-"
```

```wireshark
ip.addr == 192.168.20.100 && tcp contains "Apache"
```

```wireshark
ip.addr == 192.168.20.100 && tcp contains "root@metasploitable"
```

**Interpretation:** The target exposes many legacy and high-risk services. The visible banners strongly suggest a deliberately vulnerable Linux host, likely a Metasploitable-style system.

**Unknowns:** Whether these services are intended, patched, isolated, or reachable from untrusted networks cannot be determined from PCAP alone.

---

### Finding 3 — Explicit Nmap Scripting Engine HTTP Probes Observed

**Confidence:** High  
**Severity contribution:** Medium  
**Timestamp range:** `2026-05-20T10:55:35.442084Z` to `2026-05-20T10:55:35.625156Z` for observed NSE HTTP probes  
**Source:** `192.168.10.100`  
**Destination:** `192.168.20.100`  
**Ports:** TCP `80`, `8180`  

**Evidence:**

| Frame | Timestamp | Source → Destination | Request evidence |
|---:|---|---|---|
| 3121 | `2026-05-20T10:55:35.442084Z` | `192.168.10.100:33898 -> 192.168.20.100:8180` | `GET /nmaplowercheck1779274535`, User-Agent contains `Nmap Scripting Engine` |
| 3122 | `2026-05-20T10:55:35.442322Z` | `192.168.10.100:33902 -> 192.168.20.100:8180` | `POST /sdk`, SOAP body, User-Agent contains `Nmap Scripting Engine` |
| 3123 | `2026-05-20T10:55:35.442387Z` | `192.168.10.100:34496 -> 192.168.20.100:80` | `GET /nmaplowercheck1779274535`, User-Agent contains `Nmap Scripting Engine` |
| 3126 | `2026-05-20T10:55:35.442576Z` | `192.168.10.100:34504 -> 192.168.20.100:80` | `POST /sdk`, SOAP body, User-Agent contains `Nmap Scripting Engine` |
| 3181 | `2026-05-20T10:55:35.566215Z` | `192.168.10.100:33918 -> 192.168.20.100:8180` | `GET /evox/about`, User-Agent contains `Nmap Scripting Engine` |
| 3182 | `2026-05-20T10:55:35.566391Z` | `192.168.10.100:34522 -> 192.168.20.100:80` | `GET /HNAP1`, User-Agent contains `Nmap Scripting Engine` |
| 3201 | `2026-05-20T10:55:35.624951Z` | `192.168.10.100:34536 -> 192.168.20.100:80` | `GET /evox/about`, User-Agent contains `Nmap Scripting Engine` |
| 3202 | `2026-05-20T10:55:35.625156Z` | `192.168.10.100:33926 -> 192.168.20.100:8180` | `GET /HNAP1`, User-Agent contains `Nmap Scripting Engine` |

**Reproducible filters/methods:**

```wireshark
http.user_agent contains "Nmap Scripting Engine"
```

```wireshark
tcp contains "Nmap Scripting Engine"
```

**Interpretation:** This is direct packet evidence that Nmap NSE-style scripts were executed against HTTP services on the target. The requests include service fingerprinting and common vulnerability-discovery probes.

**Unknowns:** Whether these NSE probes were part of an authorized vulnerability assessment cannot be determined from PCAP alone.

---

### Finding 4 — Shell-Like Service on TCP `1524` Exposed Root Prompt

**Confidence:** High for prompt exposure; Low for compromise conclusion  
**Severity contribution:** High if production  
**Timestamp:** `2026-05-20T10:52:57.054310Z` to `2026-05-20T10:52:57.057520Z`  
**Source/Destination:** `192.168.10.100` ↔ `192.168.20.100`  
**Port:** TCP `1524`  

**Evidence:**

- Frame `1144`: SYN/ACK from `192.168.20.100:1524` to `192.168.10.100:38462`, confirming port `1524` was open during scanning.
- Frame `2253`: `192.168.20.100:1524 -> 192.168.10.100`, payload: `root@metasploitable:/# `.
- Frame `2256`: `192.168.10.100 -> 192.168.20.100:1524`, payload: `exit\n`.

**Reproducible filters/methods:**

```wireshark
tcp.port == 1524
```

```wireshark
tcp contains "root@metasploitable"
```

**Interpretation:** The target exposed an interactive root shell prompt on TCP `1524`. The only visible command sent by the scanner in this capture was `exit`. The PCAP does **not** show malicious commands, file download, persistence, privilege escalation, or data exfiltration through this session.

**Unknowns:** Cannot determine whether this service existed intentionally, whether any prior commands were executed before capture, or whether a host was compromised earlier. Endpoint process logs and shell history from `192.168.20.100` are required.

---

### Finding 5 — Target Revealed Legacy Software Banners and Vulnerable-Lab Identity

**Confidence:** High  
**Severity contribution:** High if production  
**Affected host:** `192.168.20.100`

**Evidence examples:**

| Frame | Port | Banner / response evidence |
|---:|---:|---|
| 2239 | 22 | `SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1` |
| 2244 | 21 | `220 (vsFTPd 2.3.4)` |
| 2381 | 80 | `Apache/2.2.8 (Ubuntu) DAV/2`, `PHP/5.2.4`, page title `Metasploitable2 - Linux` |
| 2388 | 3306 | `5.0.51a-3ubuntu5` MySQL banner |
| 2412 | 25 | `metasploitable.localdomain ESMTP Postfix (Ubuntu)` |
| 2557 | 2121 | `ProFTPD 1.3.1 Server (Debian)` |
| 2589 | 8180 | `Apache-Coyote/1.1`, Tomcat-style content |
| 2234 | 5900 | `RFB 003.003` VNC banner |
| 2260 | 6667 | `irc.Metasploitable.LAN` |

**Reproducible filters/methods:**

```wireshark
tcp contains "Metasploitable"
```

```wireshark
tcp contains "Apache/2.2.8"
```

```wireshark
tcp contains "vsFTPd"
```

**Interpretation:** Multiple banners identify the target as a legacy Linux service host, likely an intentionally vulnerable Metasploitable-style lab VM. If this host exists outside a controlled lab segment, it is a high-risk exposure.

**Unknowns:** Cannot determine patch status, network reachability beyond this capture, or whether services are intentionally deployed.

---

## 4. Involved Assets and Network Actors

### Observed IP Actors

| IP address | Observed role | Evidence | Confidence |
|---|---|---|---|
| `192.168.10.100` | Scanner / initiating host | Sent SYNs to 1,000 ports on `192.168.20.100`; sent Nmap NSE HTTP probes; queried DNS via `192.168.10.1` | High |
| `192.168.20.100` | Scanned target / multi-service server | Responded on 23 open TCP ports; exposed many service banners; returned Metasploitable-related content | High |
| `192.168.10.1` | DNS resolver and local gateway-like peer | Received DNS queries from `192.168.10.100`; exchanged ARP with `192.168.10.100` | Medium |

### Observed MAC Addresses

| MAC address | Observed behavior | Vendor status |
|---|---|---|
| `08:00:27:6e:e4:1a` | Present in all observed Ethernet conversations | Vendor not authoritatively resolved in this analysis |
| `08:00:27:63:7b:d3` | Present in all observed Ethernet conversations | Vendor not authoritatively resolved in this analysis |

Only two MAC addresses appeared in the capture, suggesting the packets were captured on a local Ethernet/VLAN segment or virtual network path where those two layer-2 endpoints were visible. Exact topology cannot be determined from PCAP alone.

### Top IP Endpoints by Packet Appearance

| Endpoint | Packet appearances |
|---|---:|
| `192.168.10.100` | `3,471` |
| `192.168.20.100` | `3,252` |
| `192.168.10.1` | `219` |

### Top Directional Byte Flows

| Direction | Bytes |
|---|---:|
| `192.168.20.100 -> 192.168.10.100` | `129,591` |
| `192.168.10.100 -> 192.168.20.100` | `114,309` |
| `192.168.10.100 -> 192.168.10.1` | `16,839` |
| `192.168.10.1 -> 192.168.10.100` | `1,254` |

---

## 5. Timeline of Events

| Timestamp UTC | Source | Destination | Protocol/Port | Event | Interpretation |
|---|---|---|---|---|---|
| `10:52:21.197332` | `192.168.10.100` | `192.168.10.1` | UDP/53 | DNS query for `0.debian.pool.ntp.org.home.arpa` | Routine DNS behavior before scan |
| `10:52:38.521147` | `192.168.10.100` | `192.168.10.1` | ARP | ARP request for `192.168.10.1` | Local network resolution |
| `10:52:50.626356` | `192.168.10.100` | `192.168.20.100` | ICMP | Echo request | Host discovery/check |
| `10:52:50.626462` | `192.168.10.100` | `192.168.20.100:443` | TCP | First observed SYN to scan target | Beginning of TCP scan activity |
| `10:52:50.627892` | `192.168.20.100` | `192.168.10.100` | ICMP/TCP payload response | ICMP echo reply and TCP behavior observed | Target alive |
| `10:52:55.241810` | `192.168.10.100` | `192.168.20.100` | TCP | Rapid SYN burst begins across many ports | Automated scan pattern |
| `10:52:55.247343` | `192.168.20.100:3306` | `192.168.10.100:38462` | TCP | SYN/ACK | MySQL port open |
| `10:52:55.247807` | `192.168.20.100:80` | `192.168.10.100:38462` | TCP | SYN/ACK | HTTP port open |
| `10:52:55.248099` | `192.168.20.100:22` | `192.168.10.100:38462` | TCP | SYN/ACK | SSH port open |
| `10:52:56.501295` | `192.168.20.100:1524` | `192.168.10.100:38462` | TCP | SYN/ACK | Shell/backdoor-like port open |
| `10:52:57.022560` | `192.168.20.100:22` | `192.168.10.100` | TCP | `SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1` | SSH version enumeration |
| `10:52:57.038846` | `192.168.20.100:21` | `192.168.10.100` | TCP | `220 (vsFTPd 2.3.4)` | FTP version enumeration |
| `10:52:57.054310` | `192.168.20.100:1524` | `192.168.10.100` | TCP | `root@metasploitable:/#` | Root shell prompt exposed |
| `10:52:57.057520` | `192.168.10.100` | `192.168.20.100:1524` | TCP | `exit\n` | Scanner closes shell session |
| `10:53:02.992777` | `192.168.10.100` | `192.168.20.100:80` | HTTP | `GET / HTTP/1.0` | HTTP service probe |
| `10:53:03.089595` | `192.168.20.100:80` | `192.168.10.100` | HTTP | Apache/PHP/Metasploitable page returned | Web service fingerprinted |
| `10:53:07.063900` | `192.168.20.100:25` | `192.168.10.100` | SMTP | `Postfix (Ubuntu)` banner | SMTP enumeration |
| `10:53:08.001777` | `192.168.20.100:139` | `192.168.10.100` | SMB | SMB/WORKGROUP response | SMB enumeration |
| `10:53:17.001094` | `192.168.20.100:2121` | `192.168.10.100` | FTP | `ProFTPD 1.3.1 Server (Debian)` | FTP service enumeration |
| `10:55:35.442084` | `192.168.10.100` | `192.168.20.100:8180` | HTTP | Nmap NSE request `/nmaplowercheck...` | NSE script probe |
| `10:55:35.442322` | `192.168.10.100` | `192.168.20.100:8180` | HTTP | Nmap NSE `POST /sdk` SOAP probe | NSE vulnerability/service probe |
| `10:55:35.566391` | `192.168.10.100` | `192.168.20.100:80` | HTTP | Nmap NSE `GET /HNAP1` | Router/web vulnerability discovery probe |
| `10:55:50.465038` | `192.168.10.100` | `192.168.20.100:8180` | TCP | Last observed SYN in scan summary | End of main scan interaction |
| `10:59:32.169737` | `192.168.10.100` | `192.168.10.1` | UDP/53 | Final packet in capture | Routine DNS activity after scan |

---

## 6. Traffic Overview

### Protocol Hierarchy

| Protocol | Packets | Bytes |
|---|---:|---:|
| IPv4 | `3,471` | `261,993` |
| TCP | `3,280` | `244,772` |
| UDP | `182` | `15,927` |
| DNS over UDP | `181` | `15,585` |
| ICMP | `9` | `1,294` |
| ARP | `12` | `612` |

### TCP Flag Summary

| TCP flag pattern | Packet count | Interpretation |
|---|---:|---|
| `S` | `1,175` | SYN scan attempts and connection starts |
| `AR` | `1,063` | ACK/RST responses, mostly closed-port behavior or teardown |
| `A` | `414` | Established TCP acknowledgment traffic |
| `AP` | `191` | Application payload over established TCP |
| `AS` | `146` | SYN/ACK responses from open ports |
| `AF` | `139` | FIN/ACK connection teardown |
| `R` | `113` | Reset packets |
| `APF` | `26` | Application payload with FIN/ACK |

### High-Volume Destination Ports

| Destination port | Packet count | Byte count | Interpretation |
|---:|---:|---:|---|
| `38462` | `1,000` | `60,000` | Reused scanner source port receiving many scan responses |
| `53` | `189` | `16,133` | DNS queries and responses involving `192.168.10.1` and target port checks |
| `2121` | `182` | `13,105` | ProFTPD service enumeration/probing |
| `513` | `104` | `8,605` | r-service probing and repeated responses |
| `8180` | `67` | `9,013` | Tomcat/Apache-Coyote HTTP probing |
| `80` | `69` | `5,793` | Apache HTTP probing |
| `111` | `51` | `3,762` | RPCBind probing |
| `21` | `35` | `2,314` | vsFTPd probing |
| `8009` | `25` | `1,994` | AJP/Tomcat connector probing |
| `5432` | `16` | `1,250` | PostgreSQL probing |

### HTTP Method Counts Visible in Payload

| HTTP method | Count |
|---|---:|
| GET | `22` |
| OPTIONS | `9` |
| POST | `2` |

### Top TCP Conversations by Bytes

| Conversation | Bytes | Notes |
|---|---:|---|
| `192.168.10.100:60470 <-> 192.168.20.100:8180` | `5,080` | Tomcat HTTP content retrieval |
| `192.168.10.100:60472 <-> 192.168.20.100:8180` | `4,964` | Tomcat probing |
| `192.168.10.100:33314 <-> 192.168.20.100:8180` | `4,960` | Tomcat probing |
| `192.168.10.100:33916 <-> 192.168.20.100:8180` | `3,512` | Tomcat probing |
| `192.168.10.100:33902 <-> 192.168.20.100:8180` | `2,492` | NSE `/sdk` probe and 404 response |
| `192.168.10.100:60594 <-> 192.168.20.100:80` | `1,899` | Apache root page fetch |
| `192.168.10.100:34510 <-> 192.168.20.100:80` | `1,846` | Apache root page fetch |
| `192.168.10.100:34504 <-> 192.168.20.100:80` | `1,831` | NSE `/sdk` probe and 404 response |

---

## 7. Detailed Technical Analysis

### 7.1 Reconnaissance and Scanning

**Evidence observed.**

The PCAP contains strong evidence of reconnaissance and scanning:

- TCP SYN scanning from `192.168.10.100` to `192.168.20.100` across 1,000 destination ports.
- ICMP echo and timestamp-like probes early in the capture.
- Version and banner grabbing across many open services.
- HTTP service probes using Nmap NSE User-Agent strings.
- Nmap-style probe URI `/nice%20ports%2C/Tri%6Eity.txt%2ebak` sent to multiple services, including TCP `8009`, `2121`, and `513`.

**Notable reconnaissance evidence:**

| Evidence | Details |
|---|---|
| Host discovery | ICMP echo request frame `21`; ICMP echo reply frame `26` |
| TCP scan | 1,180 SYNs from `192.168.10.100`; 1,000 target ports |
| Open-port discovery | 146 SYN/ACK packets; 23 unique open service ports confirmed |
| Service detection | Banners collected from SSH, FTP, SMTP, HTTP, MySQL, PostgreSQL, VNC, IRC, SMB, Tomcat, and others |
| Scripted HTTP probing | Frames `3121-3202` include Nmap NSE User-Agent |

**Confidence:** High

---

### 7.2 Exploitation or Attack Attempts

**Limited evidence observed. No confirmed exploitation.**

The capture includes vulnerability-discovery and service-probing behavior, but does not show a confirmed exploit chain, payload delivery, malware installation, reverse shell callback, credential theft, or data staging.

Potentially concerning interactions:

| Evidence | Interpretation | Confidence |
|---|---|---|
| TCP `1524` returns `root@metasploitable:/#` at frame `2253` | Exposed root shell prompt; severe exposure if real | High |
| Frame `2256` sends `exit\n` to TCP `1524` | Scanner closed the shell session; no malicious command visible | High |
| NSE `POST /sdk` SOAP probes at frames `3122` and `3126` | Scripted web vulnerability/service checks | High |
| Requests to `/HNAP1`, `/evox/about`, `/nmaplowercheck...` | Common web fingerprint/vulnerability probes | High |
| Probe `/nice%20ports%2C/Tri%6Eity.txt%2ebak` | Classic Nmap probe string | High |

**No evidence observed in this PCAP** for:

- Exploit payload delivering a binary.
- Reverse shell connection from target to scanner or external IP.
- Download commands such as `wget`, `curl`, `tftp`, or PowerShell.
- File write, malware staging, or persistence activity.
- SQL injection payloads or webshell upload.

**Cannot determine from PCAP alone:** Whether the target was already vulnerable, intentionally configured, compromised before capture, or exploited outside the captured window. Endpoint logs, shell history, service logs, EDR telemetry, and vulnerability scan reports are required.

---

### 7.3 Authentication Activity

**No confirmed successful authentication observed.**

Checked protocols and observations:

| Protocol/service | Observation |
|---|---|
| SSH `22` | Banner observed: `OpenSSH_4.7p1 Debian-8ubuntu1`; no visible SSH authentication details because SSH payload is encrypted after handshake. No full login exchange was proven. |
| FTP `21` | `vsFTPd 2.3.4` banner and error messages observed; no username/password authentication sequence confirmed. |
| FTP `2121` | `ProFTPD 1.3.1` banner observed; service probes generated `500` errors; no successful login observed. |
| SMB `139/445` | SMB/WORKGROUP responses observed; no full authenticated SMB session or file transfer confirmed. |
| Telnet `23` | Telnet negotiation bytes observed; no username/password exchange visible in decoded payload. |
| r-services `512/513/514` | Responses observed; no confirmed successful login. |
| HTTP `80/8180` | GET/OPTIONS/POST probes observed; no HTTP Basic credentials or session-authenticated behavior observed. |
| MySQL/PostgreSQL | Service handshake/error responses observed; no successful database authentication confirmed. |

**Cannot determine from PCAP alone:** Authentication success/failure counts for encrypted or partially captured protocols. Check SSH auth logs, FTP logs, SMB logs, database logs, web access/error logs, PAM logs, and SIEM alerts.

---

### 7.4 Lateral Movement

**No evidence observed in this PCAP.**

The traffic is one-to-one between `192.168.10.100` and `192.168.20.100`, plus DNS/ARP traffic involving `192.168.10.1`. There is no observed chaining from the target to other internal hosts, no SMB file transfer, no RDP/WinRM session, no Kerberos/LDAP activity, no SSH pivot, and no internal host sweep beyond the single target.

**Checked indicators:**

- Internal-to-internal SMB/RDP/WinRM/SSH expansion.
- Multiple destination hosts contacted by the target after interaction.
- New outbound sessions from `192.168.20.100` to third-party/internal hosts.
- Database connections from target to other hosts.

**Result:** Not observed.

---

### 7.5 Command and Control

**No evidence observed in this PCAP.**

The PCAP does not show beaconing, periodic external callbacks, suspicious TLS SNI, suspicious domain generation, long-lived outbound sessions from target to unknown destinations, or direct external IP command-and-control traffic.

**Observed network scope:**

- Scanner: `192.168.10.100`
- Target: `192.168.20.100`
- DNS/gateway-like host: `192.168.10.1`

No Internet C2 infrastructure is visible in the capture.

**Cannot determine from PCAP alone:** Whether C2 existed before or after the capture window, or whether host-level malware was present without network callbacks in this window.

---

### 7.6 Data Transfer and Possible Exfiltration

**No evidence observed in this PCAP.**

The total capture size is small: `262,605` bytes. The largest conversations are HTTP/Tomcat page retrievals and scanner/service responses. There are no large outbound transfers from `192.168.20.100` to the scanner or to an external host.

**Evidence checked:**

- Large outbound transfers.
- FTP uploads.
- SMB file writes/transfers.
- HTTP POST bodies carrying large data.
- DNS tunneling indicators.
- Long TLS sessions.
- Large database exports.

**Findings:**

- HTTP `POST /sdk` payloads are small NSE SOAP probes, not evidence of exfiltration.
- The target sent banners, error pages, and service responses. These are enumeration responses, not bulk data transfer.
- No FTP `STOR`, SMB write, HTTP upload, or long outbound transfer was observed.

**Result:** No packet-supported data exfiltration identified.

---

### 7.7 DNS Analysis

**Observed DNS activity is mostly routine and scanner-side.**

| Item | Value |
|---|---:|
| DNS packets | `181` |
| Main DNS client | `192.168.10.100` |
| DNS resolver | `192.168.10.1` |
| Transport | UDP/53 |

Visible queried names include:

- `0.debian.pool.ntp.org.home.arpa`
- `1.debian.pool.ntp.org`
- `1.debian.pool.ntp.org.home.arpa`
- `2.debian.pool.ntp.org`
- `variations.brave.com`
- `variations.brave.com.home.arpa`
- `100.20.168.192.in-addr.arpa`

**Interpretation:** The DNS activity appears related to ordinary host background activity and reverse lookups, not C2 or DNS tunneling.

**No evidence observed in this PCAP** for:

- DNS tunneling.
- High-entropy/random domain generation.
- Large TXT record exfiltration.
- Suspicious external callback domains.
- Domain lookups from the target `192.168.20.100`.

---

### 7.8 HTTP and TLS Analysis

#### HTTP Analysis

HTTP is a major part of the service enumeration. The scanner probed TCP `80` and `8180`, and also sent HTTP-like probes to non-HTTP services during version detection.

**HTTP servers identified:**

| Host | Port | Server evidence |
|---|---:|---|
| `192.168.20.100` | `80` | `Apache/2.2.8 (Ubuntu) DAV/2`; `X-Powered-By: PHP/5.2.4-2ubuntu5.10`; page title `Metasploitable2 - Linux` |
| `192.168.20.100` | `8180` | `Apache-Coyote/1.1`; Tomcat-style responses including Tomcat `5.5` error page title |

**Notable HTTP requests:**

| Frame | Destination | Request | Interpretation |
|---:|---|---|---|
| 2278 | `192.168.20.100:80` | `GET / HTTP/1.0` | Basic web fingerprinting |
| 2431 | `192.168.20.100:8180` | `GET / HTTP/1.0` | Tomcat service fingerprinting |
| 2458 | `192.168.20.100:8009` | `GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0` | Nmap probe string against AJP-like service |
| 3121 | `192.168.20.100:8180` | `GET /nmaplowercheck1779274535` | Nmap NSE HTTP script probe |
| 3122 | `192.168.20.100:8180` | `POST /sdk` | Nmap NSE SOAP/service probe |
| 3123 | `192.168.20.100:80` | `GET /nmaplowercheck1779274535` | Nmap NSE HTTP script probe |
| 3126 | `192.168.20.100:80` | `POST /sdk` | Nmap NSE SOAP/service probe |
| 3181 | `192.168.20.100:8180` | `GET /evox/about` | Fingerprint/vulnerability-discovery probe |
| 3182 | `192.168.20.100:80` | `GET /HNAP1` | Common web/router discovery probe |

**HTTP response behavior:**

- Apache returned `200 OK` for `/` and `404 Not Found` for Nmap probe paths.
- Tomcat/Apache-Coyote returned `200 OK`, `404 Not Found`, and `505 HTTP Version Not Supported` depending on probe format.

#### TLS Analysis

**No evidence observed in this PCAP.**

TCP `443` was probed, but the target did not establish a visible TLS session in the analyzed payload. No TLS ClientHello, SNI, certificate, or TLS version information was observed.

---

## 8. Indicators of Compromise / Indicators of Activity

No packet-supported malware IOCs were identified. The following are **indicators of activity** and exposure, not proof of compromise.

| Type | Indicator | Context | Confidence |
|---|---|---|---|
| Scanner IP | `192.168.10.100` | Initiated scan, Nmap NSE probes, DNS queries | High |
| Target IP | `192.168.20.100` | Scanned host exposing multiple services | High |
| DNS resolver | `192.168.10.1` | DNS/ARP peer for scanner | Medium |
| User-Agent | `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)` | Explicit NSE HTTP probe string | High |
| URI | `/nmaplowercheck1779274535` | Nmap HTTP case/check probe | High |
| URI | `/nice%20ports%2C/Tri%6Eity.txt%2ebak` | Nmap service probe string | High |
| URI | `/HNAP1` | Web/router discovery probe | High |
| URI | `/evox/about` | Web fingerprint/vulnerability-discovery probe | High |
| URI | `/sdk` | SOAP service probe used by scanner | High |
| Service banner | `root@metasploitable:/#` | Root shell prompt on TCP `1524` | High |
| Service banner | `vsFTPd 2.3.4` | FTP service on TCP `21` | High |
| Service banner | `OpenSSH_4.7p1 Debian-8ubuntu1` | SSH service on TCP `22` | High |
| Service banner | `Apache/2.2.8 (Ubuntu) DAV/2` | HTTP service on TCP `80` | High |
| Service banner | `PHP/5.2.4-2ubuntu5.10` | HTTP/PHP exposure on TCP `80` | High |
| Service banner | `ProFTPD 1.3.1 Server (Debian)` | FTP service on TCP `2121` | High |
| Service banner | `Apache-Coyote/1.1` | Tomcat-like service on TCP `8180` | High |
| Service banner | `RFB 003.003` | VNC service on TCP `5900` | High |
| Service banner | `irc.Metasploitable.LAN` | IRC service on TCP `6667` | High |

**No packet-supported IOCs identified** for malware hashes, filenames, downloaded binaries, attacker-controlled public domains, external C2 IPs, credentials, or exfiltration destinations.

---

## 9. Severity and Risk Assessment

### Assigned Severity

**Observed incident activity severity:** **Medium**  
**Target exposure severity if production:** **High**

### Why Not Critical?

The PCAP does not prove successful malicious exploitation, malware execution, data theft, persistence, destructive activity, or lateral movement. The only shell-like interaction visible is the target presenting a root prompt on TCP `1524`, followed by the scanner sending `exit`.

### Why Not Low?

The activity is not routine business traffic. It includes broad TCP scanning, version enumeration, Nmap NSE probes, and service interaction across many sensitive services. If unauthorized, this is a meaningful security event. Independently, the target exposes many legacy and dangerous services.

### Business Risk Translation

If `192.168.20.100` is a lab VM:

- Business impact is likely low, assuming it is isolated and scanning was authorized.
- The capture represents expected training or penetration-test traffic.

If `192.168.20.100` is a production or corporate asset:

- The business risk is high.
- Exposed services include FTP, Telnet, SMB, r-services, databases, VNC, X11, Tomcat, IRC, NFS/RPC, and an apparent root shell prompt.
- An unauthorized actor could potentially enumerate services, attempt known vulnerabilities, brute-force credentials, access legacy services, or obtain shell/database access depending on configuration.
- The host may violate hardening baselines and segmentation policies.

---

## 10. Recommended Actions

### Immediate Actions

1. **Confirm authorization for `192.168.10.100`.**
   - Check vulnerability scan schedules, penetration-test approvals, lab activity, and user/process logs.
   - If unauthorized, isolate `192.168.10.100` and preserve evidence.

2. **Validate the role of `192.168.20.100`.**
   - Determine whether it is an intentionally vulnerable lab VM or a real business system.
   - If it is production, treat it as high-risk and immediately restrict access.

3. **Restrict or isolate dangerous services on `192.168.20.100`.**
   - Prioritize TCP `1524`, `21`, `23`, `512`, `513`, `514`, `139`, `445`, `3306`, `5432`, `5900`, `6000`, `6667`, `8009`, and `8180`.
   - Remove external or cross-segment reachability unless business-justified.

4. **Preserve host evidence.**
   - Capture process lists, listening sockets, shell history, authentication logs, service logs, and EDR telemetry from both `192.168.10.100` and `192.168.20.100`.

5. **Do not assume compromise from this PCAP alone.**
   - Investigate proportionally. The evidence supports scanning and service exposure, not confirmed data theft or malware.

### Short-Term Actions

1. **Endpoint triage on `192.168.10.100`.**
   - Identify the process that generated the scan.
   - Look for `nmap` execution, command history, script arguments, and user account context.

2. **Endpoint triage on `192.168.20.100`.**
   - Verify whether TCP `1524` is intentionally enabled.
   - Review service configurations and authentication logs.
   - Check whether any commands were executed through the exposed shell before or after this capture.

3. **Review service logs.**
   - Apache, Tomcat, FTP, SSH, Postfix, SMB/Samba, MySQL, PostgreSQL, VNC, IRC, RPC/NFS, Telnet, and r-services.

4. **SIEM/firewall correlation.**
   - Search for additional scans from `192.168.10.100`.
   - Search for other hosts contacting `192.168.20.100`.
   - Search for outbound traffic from `192.168.20.100` after the scan window.

5. **Vulnerability validation.**
   - Run an authorized vulnerability assessment against `192.168.20.100` after containment decisions.
   - Confirm whether detected banners are accurate and whether services are exploitable.

### Long-Term Actions

1. **Network segmentation.**
   - Place lab/vulnerable VMs in isolated networks with explicit access control.
   - Prevent cross-segment scanning unless authorized.

2. **Service hardening.**
   - Disable Telnet, r-services, legacy FTP, exposed databases, VNC, X11, and unnecessary RPC/NFS services.
   - Remove unauthenticated shell services immediately.

3. **Patch and lifecycle management.**
   - Replace or upgrade obsolete services and operating systems.
   - Enforce asset inventory and owner accountability.

4. **Detection engineering.**
   - Add alerts for:
     - One host contacting hundreds of ports on one destination.
     - Nmap NSE User-Agent strings.
     - `/nice%20ports%2C/Tri%6Eity.txt%2ebak` requests.
     - Access to TCP `1524`, r-services, and legacy admin services.
     - Unexpected exposure of `Metasploitable` banners.

5. **Authorized scanning controls.**
   - Maintain scanner allowlists.
   - Require scan tickets and labels.
   - Log vulnerability scanner source IPs and expected scan windows.

---

## 11. Evidence Gaps and Limitations

This PCAP can prove:

- `192.168.10.100` scanned and probed `192.168.20.100`.
- `192.168.20.100` exposed many open services during the capture window.
- Nmap NSE-style HTTP probing occurred.
- Service banners revealed legacy services and Metasploitable-related identity.
- TCP `1524` returned a root shell prompt and the scanner sent `exit`.
- No large data transfer, malware download, C2 beaconing, or lateral movement was visible during the capture window.

This PCAP cannot prove:

- Whether the scan was authorized.
- Which user or process launched the scan.
- Whether `192.168.10.100` was compromised or simply operated by an analyst.
- Whether `192.168.20.100` was compromised before the capture.
- Whether credentials were successfully used in encrypted sessions.
- Whether the target was exploited outside the captured time window.
- Whether the exposed root shell is reachable from other networks.
- Whether any business data was accessed outside this capture.

Additional data sources needed:

- Endpoint process execution logs from `192.168.10.100`.
- Shell history and service logs from `192.168.20.100`.
- Firewall and router logs between the `192.168.10.0/24` and `192.168.20.0/24` networks.
- DNS resolver logs from `192.168.10.1`.
- IDS/IPS alerts for the same time window.
- SIEM correlation for both IPs before and after the capture.
- Asset inventory and vulnerability management records.
- Change/approval tickets for scans or lab exercises.

---

## 12. Final Executive Conclusion

The PCAP supports a clear conclusion: **`192.168.10.100` performed aggressive reconnaissance and service enumeration against `192.168.20.100` on 2026-05-20 between approximately `10:52:50Z` and `10:55:50Z`**. The scan contacted 1,000 TCP destination ports and identified 23 open services. Several later HTTP requests explicitly used the `Nmap Scripting Engine` User-Agent, confirming that scripted Nmap-style checks were performed.

The target, `192.168.20.100`, exposed a broad set of legacy and high-risk services. Packet payloads revealed banners including `vsFTPd 2.3.4`, `OpenSSH_4.7p1`, `Apache/2.2.8`, `PHP/5.2.4`, `ProFTPD 1.3.1`, `Apache-Coyote/1.1`, `Tomcat/5.5`, MySQL, PostgreSQL, VNC, IRC, SMB, RPC/NFS, and Metasploitable-related identity strings. The most serious observed exposure was TCP `1524`, where the target returned `root@metasploitable:/#`. However, the only visible scanner command to that shell was `exit`, so this PCAP does **not** prove malicious command execution.

No packet evidence was found for data exfiltration, malware download, command-and-control beaconing, lateral movement, brute-force authentication, or confirmed compromise during the captured interval. The realistic incident judgment is therefore: **confirmed reconnaissance and serious service exposure, but no confirmed compromise from PCAP alone**.

The correct operational response depends on authorization and environment. If this was a lab or approved penetration test, the activity is expected, though the lab should remain isolated. If this was production or unauthorized, the organization should treat the event as a significant security incident: validate the scanner host, isolate or firewall the target, investigate the exposed shell service, review service logs, and confirm whether any activity occurred before or after the capture window.

**Final severity:** Medium for observed scanning activity; High for target exposure if the system is not an intentionally isolated lab asset.
