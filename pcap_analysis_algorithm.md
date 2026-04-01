# PCAP Analysis — Field Guide for L1 SOC Analysts
### How to open a packet capture, understand what happened, and write a report about it

---

> **Who this is for:**
> You know what a packet is. You understand that computers talk over a network by sending data back and forth. You have opened Wireshark at least once. This guide will walk you through a real analysis from start to finish — and teach you how to think like an analyst while doing it.

---

## Table of Contents

1. [Before You Start — The Analyst Mindset](#1-before-you-start--the-analyst-mindset)
2. [Phase 1 — Open the File and Get the Big Picture](#2-phase-1--open-the-file-and-get-the-big-picture)
3. [Phase 2 — Map the Network: Who Is Talking?](#3-phase-2--map-the-network-who-is-talking)
4. [Phase 3 — Protocol Analysis: What Are They Saying?](#4-phase-3--protocol-analysis-what-are-they-saying)
5. [Phase 4 — Recognizing Attack Scenarios](#5-phase-4--recognizing-attack-scenarios)
6. [Phase 5 — Collecting Evidence](#6-phase-5--collecting-evidence)
7. [Phase 6 — Writing the Incident Report](#7-phase-6--writing-the-incident-report)
8. [Quick Filter Reference](#8-quick-filter-reference)

---

## 1. Before You Start — The Analyst Mindset

Before you click anything, stop for 30 seconds and anchor yourself to three questions. Everything you do after this should be answering these.

### Ask yourself:

**1. What is the context of this capture?**
Where was it taken from? A user's laptop? A web server? A firewall? A network tap that sees all traffic?
This matters because the baseline — what "normal" looks like — is completely different in each case. A web server handling 10,000 connections per minute is normal. A single user laptop doing the same is not.

**2. What do we suspect happened?**
Did someone report a slow network? Did an alert fire? Was a user's machine flagged by antivirus?
Your suspicion is your starting hypothesis. It tells you where to look first. But it is not the answer — it is just the first thread to pull.

**3. What is the time window?**
Is this a 2-minute capture or a 48-hour file? The size changes your approach significantly. A small file is likely targeted around a specific event. A large file requires you to triage before diving deep.

### Rules to work by:

- **Follow the data.** Your hypothesis is a starting point, not a verdict. Let the evidence change your mind.
- **Write notes as you go.** Notes taken during analysis are 10x more accurate than notes written from memory afterward.
- **Not seeing something suspicious is not the same as the traffic being clean.** Be careful with absence of evidence.
- **One indicator means nothing. Converging indicators mean something.** A weird DNS query alone could be an auto-update. A weird DNS query + outbound binary data + a self-signed TLS certificate together is a story.

---

## 2. Phase 1 — Open the File and Get the Big Picture

*Goal: Understand the scale and shape of this capture before you invest time in deep analysis.*

Think of this like being handed a box of evidence at a crime scene. Before you examine each piece, you take a look at the whole box first. How big is it? What's obviously in it? Does anything jump out immediately?

---

### Step 1.1 — Check File Properties

```
Menu → Statistics → Capture File Properties
```

This tells you the basics. Record:

| What to check | Why it matters |
|---|---|
| **Capture duration** | A 5-second file is very different from a 3-day file. Know your window. |
| **Total packets** | 500 packets vs 5 million packets — completely different strategies. |
| **Average packet size** | Very small packets consistently (under 100 bytes) can mean scanning or beaconing. Very large packets can mean bulk data transfer. |
| **File format** | `.pcapng` can store more metadata (interface names, comments) than `.pcap`. Good to know. |

> **📝 Learning Point:** Before you filter for anything specific, knowing "this is a 2-minute file with 50,000 packets averaging 60 bytes each" tells you something already. 50,000 packets in 2 minutes means roughly 416 packets per second — that's a lot. Something was generating high-volume traffic. You should go find out what.

---

### Step 1.2 — Set Timestamps to Absolute Time

By default Wireshark shows time as relative (seconds since the first packet). Switch to real wall-clock time so your analysis lines up with incident timelines:

```
View → Time Display Format → Date and Time of Day
```

> **⚠️ Important:** Check whether the timestamps make sense with your incident timeline. The machine that captured this traffic might have had the wrong system clock. If timestamps seem off, note that in your report — don't discard the data, just document the uncertainty.

---

### Step 1.3 — Check Expert Information for Obvious Problems

```
Analyze → Expert Information
```

This panel automatically flags issues Wireshark detected:

- **Red (Errors):** Malformed packets, truncated data. If you see many of these, your capture may be incomplete.
- **Yellow (Warnings):** TCP retransmissions, out-of-order packets, zero-window alerts.
- **Cyan (Notes):** Things worth looking at — checksum failures, protocol flags.

> **📝 Learning Point:** Heavy TCP retransmissions at the beginning of a file often mean the capture started midway through a connection. The 3-way handshake already happened before recording started — you won't be able to reconstruct the full session. Note this limitation.

---

### Step 1.4 — Get the Protocol Breakdown

```
Menu → Statistics → Protocol Hierarchy
```

This shows you every protocol in the capture, what percentage of traffic it makes up, and how many packets.

**What you're doing here:** Scanning for anything unexpected.

**Ask yourself:**
- What protocols do I expect to see on this network? (HTTP/S, DNS, email clients, etc.)
- What do I see that I *don't* expect?
- Is TLS dominating, meaning most traffic is encrypted?

**Red flags at this stage:**

| If you see this unexpectedly... | It could mean... |
|---|---|
| FTP or Telnet | Cleartext protocol in use — credentials might be exposed |
| IRC or IRC-like traffic | Older botnet C2 style communication |
| Huge volume of DNS compared to everything else | DNS tunneling or DGA malware |
| Lots of UDP with no matching protocol | Custom or encrypted communication, C2, tunneling |
| ICMP making up a large percentage | Possible ICMP flood, scanning, or tunneling |

---

## 3. Phase 2 — Map the Network: Who Is Talking?

*Goal: Build a list of every host in this capture, what role they play, and who they're communicating with.*

---

### Step 2.1 — Find All IP Conversations

```
Menu → Statistics → Conversations → IPv4 tab
```

Sort by **Bytes** (descending). This shows you the heaviest conversations first.

**Record for each unique IP:**
- Is it internal (private range: `10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`) or external (public IP)?
- How much total data is it involved in?
- Who is it talking to?

**Classify the IPs you find:**

| IP Type | How to identify it |
|---|---|
| Regular workstation | RFC 1918 address, moderate traffic in many directions |
| Router / Gateway | Usually ends in `.1` on the subnet, passes most external traffic |
| DNS server | High volume of port 53 traffic both directions |
| Web server | Receives connections on port 80 or 443 from many different IPs |
| Suspicious external IP | Public IP, no known hostname, receiving large volumes of data from internal hosts |

> **📝 Important:** Do not assume internal IPs are safe. Lateral movement (an attacker moving through the network after getting in) and insider threats both look like internal-to-internal traffic. Map every IP regardless.

For external IPs you don't recognize, look them up:
- [VirusTotal](https://www.virustotal.com/) — check if the IP is flagged as malicious
- [AbuseIPDB](https://www.abuseipdb.com/) — check abuse reports
- [Shodan](https://www.shodan.io/) — see what services this IP is running publicly
- [WHOIS](https://lookup.icann.org/) — find out who owns the IP

---

### Step 2.2 — Check TCP and UDP Conversations for Unusual Ports

```
Menu → Statistics → Conversations → TCP tab
Menu → Statistics → Conversations → UDP tab
```

**Look for ports that shouldn't be there.** Common legitimate ports: 80 (HTTP), 443 (HTTPS), 53 (DNS), 25/587 (email), 22 (SSH), 3389 (RDP).

Common attacker-used ports: **4444** (Metasploit default), **8443, 9001** (common C2), **1337** (classic hackery), and any random high port used for sustained traffic.

> **⚠️ Caution:** Do not assume a port tells you the protocol. Malware frequently runs over port 443 simply because firewalls let 443 through. Traffic on port 443 that isn't actually HTTPS will look wrong when you inspect it. Always verify.

---

### Step 2.3 — Build Your Network Map

At this point, take a piece of paper or a notes file and sketch out what you know:
- List all the hosts
- Note which are internal vs external
- Draw arrows between the ones that are communicating
- Flag anything that looks unusual

This isn't optional. Your report will need this, and it also helps you catch patterns you'd miss just staring at packet lists.

---

## 4. Phase 3 — Protocol Analysis: What Are They Saying?

*Goal: Go protocol by protocol and extract meaningful information from each.*

---

### Step 3.1 — DNS: The Nervous System of the Network

DNS is where you start because almost everything — including malware — needs DNS. Even if traffic is encrypted, the DNS query that happened right before the encrypted connection reveals the destination.

**Display Filter:**
```
dns
```

**What to extract:**
- Every unique domain name queried
- Which internal host is querying what
- How many times the same domain was queried
- Responses — did the query succeed or return NXDOMAIN (domain not found)?

**Red flags in DNS:**

| What you see | What it likely means | What to do next |
|---|---|---|
| Queries for random-looking domain names like `xkj23fn2.net` | DGA malware — malware auto-generates domain names to find its C2 server | Run the domain through VirusTotal, check if other similar domains were queried |
| Very long subdomains (`abcdefghij.longstring.malware.com`) | DNS tunneling — data is being encoded and smuggled inside DNS queries | Check query length filter below, inspect payloads |
| 50+ unique domains queried by one host in a few minutes, most returning NXDOMAIN | DGA in action — malware cycling through generated names looking for an active one | The one that succeeds (returns an IP) is your C2 endpoint |
| DNS TXT record queries that return large blobs of data | DNS tunneling — responses carry encoded data | Inspect TXT response payloads carefully |

**Filter for suspiciously long DNS queries (possible tunneling):**
```
dns.qry.name.len > 50
```

**Filter for failed DNS lookups (NXDOMAIN):**
```
dns.flags.rcode == 3
```

**Get a summary of all DNS queries:**
```
Menu → Statistics → DNS
```

---

### Step 3.2 — HTTP: Cleartext Web Traffic

If HTTP is present, it's a gift — you can read it directly.

**Display Filter:**
```
http
```

**Key things to extract:**

- All URLs being requested (what is the host asking for?)
- All `User-Agent` strings (what software is claiming to make these requests?)
- POST vs GET requests (GET = retrieving data, POST = sending data *to* a server)
- Server responses — 200 OK, 404 Not Found, 301/302 redirects

**Useful filters:**
```
# Show only GET requests
http.request.method == "GET"

# Show only POST requests (data being uploaded)
http.request.method == "POST"

# Find suspicious user agents
http.user_agent contains "python"
http.user_agent contains "curl"

# Find file downloads (binary content)
http contains "Content-Type: application/octet-stream"
```

**Follow an HTTP conversation to read it:**
```
Right-click any HTTP packet → Follow → HTTP Stream
```

**Red flags in HTTP:**

| What you see | What it likely means |
|---|---|
| POST requests to an IP address (not a domain name) | Likely C2 traffic — malware avoiding DNS by going direct to IP |
| User-Agent looks like a script or tool (python-requests, curl, Go HTTP) | Automated request — could be legitimate tooling or attacker tool |
| Large binary response from an unknown server | Possible malware payload or tool being downloaded |
| URIs containing Base64 strings or encoded gibberish | Encoded commands or exfiltrated data in the URL |

**Export files from HTTP traffic:**
```
File → Export Objects → HTTP
```
This lets you save every file that was transferred over HTTP. Look for `.exe`, `.dll`, `.ps1`, `.bat`, `.zip` files.

> **⚠️ Safety:** Never open extracted files on your own machine. Use a sandbox like [Any.run](https://any.run/) or [Hybrid Analysis](https://www.hybrid-analysis.com/).

---

### Step 3.3 — TLS / HTTPS: Encrypted Traffic

You cannot read the content of TLS traffic without the server's private key. But you can still learn a lot.

**Display Filter:**
```
tls
```

**What you CAN see without decryption:**

| Field | Where to find it | What it reveals |
|---|---|---|
| **SNI (Server Name Indication)** | TLS Client Hello → Extensions → server_name | The domain the client is connecting to — visible even in encryption |
| **TLS version** | TLS Client Hello header | TLS 1.0 / 1.1 in a modern network is a red flag — outdated |
| **Certificate details** | TLS Server Hello → Certificate | Subject, issuer, validity period |
| **Certificate issuer** | Certificate → Issuer | Self-signed certificate = no trusted CA signed it — common in attacker infrastructure |
| **Cipher suites** | TLS Client Hello | Very old or weak ciphers are suspicious |

**Filter by SNI (find traffic to a specific domain):**
```
tls.handshake.extensions_server_name contains "suspicious.domain"
```

> **📝 Learning Point:** Even without reading encrypted traffic, patterns reveal themselves. A host connecting to the same IP every 60 seconds with the same TLS fingerprint and the same payload size is a beacon — identifiable without decryption.

---

### Step 3.4 — TCP Flags: The Handshake and What Goes Wrong

Understanding TCP flags lets you identify scanning, connection attempts, and protocol abuse.

**The normal TCP lifecycle:**
```
Client → Server:  SYN          (I want to connect)
Server → Client:  SYN-ACK      (OK, I acknowledge)
Client → Server:  ACK          (Great, connection established)
--- data flows ---
Either side:      FIN-ACK      (I'm done)
Other side:       FIN-ACK      (Me too, goodbye)
```

**Anything that deviates from this pattern is worth investigating:**

| Flag pattern observed | What it means |
|---|---|
| SYN only, no SYN-ACK follows | Port is closed or host is down — or attacker is scanning and not completing connections |
| Many SYNs to many ports in rapid sequence | Port scan |
| SYN → SYN-ACK → RST (immediate reset) | Port is open but connection was refused or scanner is checking |
| RST flood | Aggressive scanning or a reset attack |
| FIN packets with no prior connection | Stealth scan — trying to probe ports without a full handshake that IDS might catch |

**Filter for SYN-only packets (scan/flood detection):**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Filter for RST packets:**
```
tcp.flags.reset == 1
```

---

## 5. Phase 4 — Recognizing Attack Scenarios

*Goal: Learn to recognize specific attack types from the traffic patterns they leave behind.*

This is the section you will use the most. Each scenario below follows the same structure:
- **What is actually happening** (plain language explanation)
- **What you will see in Wireshark**
- **Filters to apply**
- **What to conclude and escalate**

---

### Scenario 1 — DoS / DDoS Attack

**What is actually happening:**

A Denial of Service attack is an attempt to make a server unavailable to legitimate users — not by hacking into it, but by overwhelming it with so much traffic that it can't process real requests anymore.

The most common type you'll see in a PCAP is a **SYN flood**:
- A normal TCP connection requires a 3-way handshake: SYN → SYN-ACK → ACK
- In a SYN flood, the attacker sends thousands of SYN packets but **never sends the final ACK**
- The server allocates memory for each half-open connection and waits
- With enough SYN packets flooding in, the server's connection table fills up — it runs out of room to accept legitimate connections
- A DDoS (Distributed) version means many different source IPs are doing this simultaneously — which is how attackers bypass simple IP blocking

Other variants:
- **UDP flood** — flooding the target with UDP packets, forcing it to process them and send ICMP "unreachable" responses, burning CPU
- **ICMP flood (Ping flood)** — flooding the target with ICMP echo requests, overwhelming bandwidth or CPU

**What you will see in Wireshark:**

- An enormous number of SYN packets going to one destination IP and one destination port
- Very few or zero SYN-ACK responses (because the handshake never completes)
- In a DDoS: the source IPs are either many different addresses, or they may be spoofed (fake)
- Traffic volume will be dramatically higher than anything else in the capture
- Capture timestamps will show this all happening in a very short time window

**Filters to apply:**

```
# Isolate SYN-only packets (incomplete handshakes)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Focus on traffic to the suspected victim server
ip.dst == <victim IP> && tcp.flags.syn == 1 && tcp.flags.ack == 0

# UDP flood — look at UDP volume to one destination
udp && ip.dst == <victim IP>

# ICMP flood
icmp && ip.dst == <victim IP>
```

**Use conversations to see the scale:**
```
Statistics → Conversations → TCP tab
```
Sort by packet count. If one conversation has 100x more packets than anything else, that's your target.

**What to note in your finding:**
- Victim IP and port being targeted
- Start and end time of the attack
- Approximate number of packets per second
- Source IP(s) — many different sources = DDoS
- Whether the server stopped responding (look for no SYN-ACK after a certain point)

> **📝 Analyst Tip:** In a SYN flood you'll often see the source IPs are spoofed (fake), so you can't block them individually. Note this in your report. The finding is the attack pattern, not necessarily an actionable source IP.

---

### Scenario 2 — Port Scanning

**What is actually happening:**

Before an attacker attacks a system, they need to know what is running on it. A port scan is reconnaissance — the attacker is knocking on every door one by one to see which ones are open.

Think of it like a burglar walking down a street trying every door handle. They're not breaking in yet — they're just figuring out which doors are unlocked.

There are different types:
- **TCP SYN Scan (most common):** Send SYN to each port. If SYN-ACK comes back, the port is open. Send RST to close it without completing the handshake. Move to the next port. Fast, relatively quiet.
- **TCP Connect Scan:** Full 3-way handshake — noisier, easier to detect.
- **UDP Scan:** Send UDP packet to each port. If ICMP "port unreachable" comes back, the port is closed. No response = possibly open.
- **FIN/NULL/Xmas Scans:** Stealth variants that try to avoid being flagged by IDS systems.

**What you will see in Wireshark:**

- One source IP sending packets to one target IP but across **many different destination ports**
- Ports are usually sequential (22, 23, 24, 25...) or random but in rapid succession
- This happens very fast — hundreds or thousands of ports in seconds to minutes
- Most will return RST (closed port) or nothing (filtered port)
- The few that return SYN-ACK are the open ports the attacker is interested in

**Filters to apply:**

```
# Find all SYN-only packets from one source to one target
ip.src == <scanner IP> && ip.dst == <target IP> && tcp.flags.syn == 1 && tcp.flags.ack == 0

# See RST responses back (closed ports)
ip.src == <target IP> && tcp.flags.reset == 1

# Get all TCP conversations from scanner to target to see which ports were hit
Statistics → Conversations → TCP tab → filter by scanner IP
```

**After filtering, check:**
- How many different destination ports did the scanner touch?
- How fast (what was the time from first to last port probed)?
- Did any ports respond with SYN-ACK? Those are the open ports the attacker found.
- Did scanning stop at a specific point, or is it ongoing?

**A real-world pattern example:**
You filter and see: `192.168.1.50 → 10.0.0.5` at ports 21, 22, 23, 25, 80, 443, 445, 3389... 200 ports probed in 4 seconds. 80 and 443 returned SYN-ACK. Everything else returned RST or nothing. This is a textbook SYN scan.

> **📝 Learning Point:** A scanner finding open ports is recon — the attack may not have happened yet. Your job is to identify this early and allow defenders to act before the exploitation phase begins.

---

### Scenario 3 — Vulnerability Exploitation

**What is actually happening:**

After reconnaissance, an attacker knows which ports are open and what services are running. Exploitation is when they attempt to abuse a vulnerability in that service to gain unauthorized access or execute code.

Common patterns:
- **Sending malformed data** to crash or hijack a service (buffer overflow)
- **Sending specially crafted requests** that trigger a vulnerability in web apps, SMB, RDP, etc.
- **Brute-forcing credentials** — trying many username/password combinations rapidly

**What you will see in Wireshark:**

*Buffer overflow / shellcode:*
- A packet or series of packets with unusually large payloads going to a service port
- Payloads containing repeating patterns ("AAAAAAA..." or hex NOP sleds `0x90909090...`)
- Payload followed by what looks like random binary data (this is the shellcode)
- The connection behavior changes after the exploit — if it succeeds, you might see a shell session open

*Credential brute force (e.g., SMB, HTTP):*
- Many rapid login attempts from the same source IP
- Short time between each attempt (humans don't log in 50 times per second)
- Alternating `USER` and `PASS` or `AUTHENTICATE` requests

*Web application exploitation:*
- HTTP GET or POST requests containing SQL injection patterns: `' OR 1=1 --`, `UNION SELECT`, etc.
- Requests to paths that shouldn't exist: `../../etc/passwd`, `/admin/shell.php`
- Large numbers of requests to the same endpoint in rapid succession

**Filters to apply:**

```
# Large packets to a specific service port (possible exploit payload)
ip.dst == <target IP> && tcp.dstport == <service port> && frame.len > 1000

# SMB authentication attempts (brute force)
smb2 && smb2.cmd == 0x00

# HTTP requests with suspicious patterns
http.request.uri contains "../"
http.request.uri contains "select"
http.request.uri contains "cmd="

# FTP brute force
ftp.request.command == "PASS"
```

**What to check:**
- What happened to the connection after the suspicious packet? Did it continue normally (exploit failed) or change behavior (possible success)?
- If exploitation succeeded, look for what followed — reverse shell traffic, commands being issued, new connections appearing

---

### Scenario 4 — C2 Beaconing

**What is actually happening:**

Once malware infects a machine, it needs to "phone home" to receive instructions. This is called Command and Control (C2). The infected machine sends a small packet to the attacker's server at regular intervals saying essentially "I'm here, do you have new instructions for me?"

This regular heartbeat is called **beaconing**.

Why it's detectable: Humans don't behave with robotic regularity. Software does. If a machine makes an outbound connection to the same IP every 60 seconds, perfectly on schedule, that precision is a red flag.

**What you will see in Wireshark:**

- One internal IP repeatedly contacting the same external IP
- The connections happen at suspiciously regular intervals (e.g., every 30s, 60s, 300s, or 3600s)
- Each connection is short — just enough to check in and receive commands
- Payload sizes are often very consistent (same amount of data each time)
- The protocol may be HTTP, HTTPS, or a custom protocol
- If HTTPS, the TLS certificate is often self-signed or issued by an unusual authority

**How to spot it step by step:**

1. Filter to traffic between your suspected host and the suspected C2:
```
ip.src == <internal host> && ip.dst == <external IP>
```

2. Look at the **Time column**. Does the same connection repeat at regular intervals?

3. Check the packet/payload size. Are they all the same size?

4. Calculate the time delta between connections — if it's consistent, that's your evidence.

5. Follow a TCP stream to see the payload:
```
Right-click any packet → Follow → TCP Stream
```
Is the payload human-readable or encoded/garbled binary? Encoded = likely malware.

**Timing patterns by implant sophistication:**

| Pattern | What it means |
|---|---|
| Perfect interval every 60s | Simple beacon, likely no jitter configured |
| Interval varies ±10–15% | Jitter enabled — attacker trying to avoid detection by timing analysis |
| Interval is very long (24h) | Sleeping implant — low-and-slow, hard to catch in short captures |

> **📝 Learning Point:** If you see a host connect to an IP on port 443 every 60 seconds, but when you look at the TLS handshake the certificate is self-signed by "localhost" or has some made-up organization name — that's not legitimate HTTPS traffic. That's a C2 using port 443 as camouflage.

---

### Scenario 5 — Man-in-the-Middle (MITM)

**What is actually happening:**

In a MITM attack, an attacker positions themselves between two communicating parties and intercepts (and sometimes modifies) the traffic. Neither side knows a third party is in the middle.

The most common type on a local network is **ARP Poisoning**:
- ARP (Address Resolution Protocol) is how computers on the same network find each other's MAC address from an IP address
- Normally: "Who has IP 192.168.1.1? Tell me your MAC address."
- In ARP poisoning: The attacker sends fake ARP replies saying "I am 192.168.1.1, my MAC is [attacker's MAC]"
- Both victim and router now think they're talking to each other, but traffic routes through the attacker's machine

**What you will see in Wireshark:**

- Multiple ARP announcements (called gratuitous ARPs) coming from one MAC address claiming to be different IPs
- Two IP addresses in the ARP table mapping to the same MAC address (dead giveaway)
- ARP replies that were not requested (no one asked, but the attacker answered anyway)

**Filters to apply:**

```
# View all ARP traffic
arp

# View only ARP replies (often unsolicited in MITM)
arp.opcode == 2
```

**How to spot the duplicate MAC:**
```
Statistics → Conversations → Ethernet tab
```
Look for a MAC address that appears in conversations with two different IP addresses — especially if one of those IPs is the gateway (router).

**What to note:**
- The attacker's MAC address
- Which IPs they claimed to be (victim and gateway)
- Timestamp when the poisoning started
- Whether any cleartext traffic (HTTP, FTP, Telnet) was flowing through the attacker — that traffic is now compromised

---

### Scenario 6 — Malware Propagation / Lateral Movement

**What is actually happening:**

After malware infects one machine, it tries to spread across the network. This is lateral movement — an attacker (or automated malware) moving from one system to others using credentials, vulnerabilities, or network shares.

Common methods:
- **SMB (file sharing):** Connect to remote machines using stolen credentials or pass-the-hash attacks, then copy malware or run remote commands
- **RDP (Remote Desktop):** Log into other machines remotely after compromising credentials
- **WMI/WinRM (remote management):** Execute commands on remote machines via PowerShell remoting

**What you will see in Wireshark:**

- A **workstation** (not a server) initiating SMB, RDP, or WinRM connections to many other machines
- These connections happen in rapid succession — not how a human would naturally use Remote Desktop
- If credentials are being sprayed, you'll see repeated authentication failures (NTLM authentication failures in SMB)
- ARP requests for many IPs in the subnet (the malware mapping out its target network)

**Filters to apply:**

```
# SMB traffic from a workstation (lateral movement indicator)
smb2 && ip.src == <suspected compromised host>

# RDP connections from internal host
tcp.port == 3389 && ip.src == <suspected host>

# WinRM / PowerShell remoting
tcp.port == 5985 || tcp.port == 5986

# ARP sweep (host discovery — malware mapping the network)
arp

# Kerberos traffic (authentication — check for unusual volumes)
kerberos
```

**Pattern recognition:**
A workstation hitting 12 other workstations over SMB in 30 seconds does not happen organically. People don't open 12 file shares in 30 seconds. Malware does.

> **📝 Learning Point:** Lateral movement always happens inside the network — internal-to-internal traffic. This is why monitoring internal traffic is just as important as perimeter traffic.

---

## 6. Phase 5 — Collecting Evidence

*Goal: Extract concrete artifacts you can reference in your report.*

---

### Extract Files Transferred Over HTTP

```
File → Export Objects → HTTP
```

Save any suspicious file (`.exe`, `.dll`, `.ps1`, `.bat`, `.js`, `.zip`). Note the:
- Filename
- Source server IP/domain
- Time of transfer
- File size

> **⚠️ Never open extracted files directly.** Use [Any.run](https://any.run/) or [Hybrid Analysis](https://www.hybrid-analysis.com/) for sandboxed analysis.

---

### Extract Credentials from Cleartext Protocols

**FTP:**
```
ftp.request.command == "USER" || ftp.request.command == "PASS"
```

**HTTP Basic Authentication:**
```
http.authbasic
```

**Telnet:** Follow the TCP stream and read the session directly.

> **📝 Policy Note:** If you find exposed credentials, notify your team lead immediately. Don't store passwords in plain text in your report — instead note "FTP credentials transmitted in cleartext, see Appendix A for details" and handle the actual credential securely.

---

### Build Your IOC List

Every piece of evidence should become an Indicator of Compromise (IOC) entry. Use defanged format to prevent accidental clicking:

| Type | Safe format |
|---|---|
| IP address | `185[.]220[.]101[.]10` |
| URL | `hxxp://malicious[.]domain/path` |
| Domain | `bad-domain[.]com` |

For each IOC, note: **value**, **type**, **where you found it**, **your confidence level** (Low / Medium / High).

---

### Save a Filtered Capture for Handoff

If you isolate specific malicious traffic, save it as a new file for your colleagues or the next analyst:

```
File → Export Specified Packets
```

Only export the packets relevant to your finding. This becomes an appendix to your report.

---

## 7. Phase 6 — Writing the Incident Report

*Goal: Communicate your findings clearly and professionally to both technical and non-technical audiences.*

---

### How to approach writing the report

A good report answers four questions in this order:
1. **What happened?** (the conclusion, stated first)
2. **What did we observe?** (the evidence)
3. **How do we know?** (the analysis that connects evidence to conclusion)
4. **What should happen next?** (recommendations)

Write for two audiences simultaneously:
- The **executive summary** at the top is for non-technical managers — 3 sentences max, plain English
- The **body** is for your technical colleagues who need to reproduce your findings or hand off to IR

---

### Report Template

Use this template every time. The explanatory notes in `>` blocks are there to guide you — remove them (or keep them as a reference) when submitting your actual report.

---

```markdown
# Incident Analysis Report

**Report Title:** [Brief description — e.g., "Suspected Malware Beaconing — Workstation PC-042"]
**Analyst:** [Your name]
**Date of Analysis:** [Today's date]
**Report ID:** [e.g., IR-2024-001 — increment per incident]
**Classification:** [Internal Use Only / Confidential / TLP:WHITE, etc.]

---

## 1. Executive Summary

> GUIDE: Write 2–3 sentences only. No technical jargon. A manager reading this at 7am 
> should immediately understand: what happened, what machine was involved, what the risk is.
> Example: "On [date], a workstation on the internal network was found communicating with
> an external server in a pattern consistent with malware infection. The host transmitted
> approximately [X MB] of data to an unrecognized external IP. Immediate isolation is recommended."

[Write your 2-3 sentence executive summary here]

---

## 2. Scope and Capture Information

> GUIDE: This section is basic facts about the evidence itself. Future analysts need this
> to understand the context of your findings.

| Field | Value |
|---|---|
| **PCAP Filename** | [filename.pcapng] |
| **Capture Start Time** | [YYYY-MM-DD HH:MM:SS UTC] |
| **Capture End Time** | [YYYY-MM-DD HH:MM:SS UTC] |
| **Duration** | [e.g., 2 hours, 14 minutes] |
| **Total Packets** | [number] |
| **Capture Source** | [e.g., "Firewall TAP on perimeter segment" or "Host-based capture on PC-042"] |
| **Capture Tool** | [e.g., Wireshark 4.2, tshark, tcpdump] |
| **Analyst Notes on Capture Quality** | [e.g., "Timestamps appear consistent with incident timeline" or "Probable midstream capture — no handshake visible for stream #3"] |

---

## 3. Network Inventory

> GUIDE: List every host you identified in the capture. Give each one a role.
> This helps readers understand who the players are before they read the findings.
> You built this in Phase 2 of your analysis.

| IP Address | Hostname (if known) | MAC Address (if available) | Role |
|---|---|---|---|
| 192.168.1.25 | PC-042 | AA:BB:CC:DD:EE:FF | User workstation — suspected compromised host |
| 192.168.1.1 | GATEWAY-01 | ... | Internal gateway / router |
| 185.220.101.10 | Unknown | N/A | External — suspected C2 server |
| 8.8.8.8 | dns.google | N/A | Google DNS — seen in normal DNS traffic |

> GUIDE: For any external IP you don't recognize, include a one-line note on what you 
> found when you looked it up. Example: "185.220.101.10 — no associated hostname,
> flagged as malicious on AbuseIPDB (42 reports), hosted by AS [number]"

---

## 4. Key Findings

> GUIDE: This is the main body. Each finding gets its own numbered section.
> Structure each finding the same way: observation → evidence → analysis → impact.
> One finding per distinct malicious activity type. Don't cram everything into one finding.

### Finding 1 — [Short name of finding, e.g., "Suspected C2 Beacon from PC-042"]

**Severity:** [Critical / High / Medium / Low]

**Observation:**
> GUIDE: What did you see? State the facts without interpretation yet.

[e.g., "Host 192.168.1.25 made repeated outbound HTTPS connections to 185.220.101.10:443 
at approximately 60-second intervals beginning at 08:12 UTC and continuing for 2 hours 
and 14 minutes (the full duration of the capture)."]

**Evidence:**

> GUIDE: List the specific artifacts that support your observation. Include timestamps, 
> filter expressions, stream numbers, or whatever makes this reproducible.

- **Timestamp range:** 08:12:03 UTC – 10:26:41 UTC
- **TCP Streams:** Streams #4, #11, #18, #25 ... (repeating pattern, same IPs, same port)
- **Payload size:** 344 bytes outbound / 88 bytes inbound (consistent across all connections)
- **TLS certificate:** Self-signed, issued to "localhost", valid 2024-01-01 – 2025-01-01
- **Wireshark filter used:** `ip.src == 192.168.1.25 && ip.dst == 185.220.101.10`
- **Packet count:** 156 connection events in scope period

**Analysis:**
> GUIDE: Here you explain what you believe is happening and why. Connect your evidence 
> to your conclusion. This is where your deduction goes.

[e.g., "The regularity of connections (approximately every 58–62 seconds), combined with 
the consistent payload size and a self-signed TLS certificate not associated with any 
known service, is consistent with automated C2 beaconing behavior. Legitimate software 
does not maintain such precise connection intervals. The self-signed certificate indicates 
the destination server is not a commercially operated service."]

**Impact:**
> GUIDE: What does this mean for the business? What could an attacker do with this 
> if it is what you think it is?

[e.g., "If confirmed, this host is under attacker control. The attacker has the ability 
to issue commands to the host, exfiltrate data, and potentially use it as a pivot point 
for lateral movement within the network."]

---

### Finding 2 — [Next finding title]

[Repeat the same structure: Observation → Evidence → Analysis → Impact]

---

## 5. Indicators of Compromise (IOCs)

> GUIDE: This is a clean, consolidated table of everything malicious you found.
> Use defanged format so nobody accidentally clicks on a malicious link.
> Confidence: High = strong evidence, Medium = likely but not certain, Low = possible but speculative.

| Type | Value | Confidence | Source |
|---|---|---|---|
| IPv4 Address | `185[.]220[.]101[.]10` | High | C2 beacon destination (Finding 1) |
| Domain | `xkj23s[.]net` | High | DGA-pattern DNS query, resolved to C2 IP |
| URL | `hxxp://185[.]220[.]101[.]10/update[.]php` | Medium | HTTP GET at infection start |
| File Hash (MD5) | `d41d8cd98f00b204e9800998ecf8427e` | Medium | Extracted PE binary from HTTP export |
| User-Agent | `Mozilla/5.0 (Windows NT; NAnt/0.92)` | Medium | Abnormal User-Agent string in HTTP requests |
| MAC Address | `AA:BB:CC:DD:EE:FF` | High | ARP poisoner MAC (if MITM scenario) |

---

## 6. Attack Timeline

> GUIDE: Construct a chronological story of the incident. Even if you don't know every 
> detail, put what you can observe in order. This is often the most valuable part of 
> your report because it shows the sequence of events.
> Always use UTC. Always include the timestamp down to seconds when possible.

| Timestamp (UTC) | Event | Source of Evidence |
|---|---|---|
| 2024-01-15 08:11:47 | Host 192.168.1.25 begins DNS queries for random-looking domains | DNS filter, stream #1 |
| 2024-01-15 08:11:59 | DNS query for `xkj23s.net` returns IP 185.220.101.10 | DNS response, frame #234 |
| 2024-01-15 08:12:03 | First HTTPS connection to 185.220.101.10:443 | TCP stream #4 |
| 2024-01-15 08:13:03 | Second HTTPS connection — beaconing interval confirmed at ~60s | TCP stream #11 |
| 2024-01-15 08:45:12 | Large outbound HTTP POST to 185.220.101.10 — 4.2 MB | TCP stream #82, frame #14501 |
| 2024-01-15 10:26:41 | Last observed connection — end of capture | TCP stream #156 |

> GUIDE: If you see a gap in the timeline (e.g., activity stops for 2 hours then 
> resumes), note it. It could mean the malware was sleeping, or this is a multi-day 
> infection and you only have a partial window.

---

## 7. Analyst Conclusions

> GUIDE: Write your overall assessment. What do you believe happened, with what 
> level of certainty? What are you confident about? What requires further investigation?
> Be honest about what you don't know.

**What we can say with high confidence:**
[e.g., "Host 192.168.1.25 established persistent, automated communication with an 
external IP. The communication pattern and TLS characteristics are consistent with 
malware C2 beaconing."]

**What requires further investigation:**
[e.g., "The initial infection vector is not visible in this capture — we cannot determine 
from this PCAP alone how the malware arrived on the host. Host-based forensics on PC-042 
is recommended."]

**MITRE ATT&CK mapping (if applicable):**
> GUIDE: MITRE ATT&CK is a framework that categorizes attacker techniques. Mapping your 
> findings to it gives your report credibility and helps the IR team understand what 
> to look for. Look up techniques at https://attack.mitre.org/

| Observed Activity | MITRE Technique |
|---|---|
| C2 beaconing over HTTPS | T1071.001 — Application Layer Protocol: Web Protocols |
| DGA domain generation | T1568.002 — Dynamic Resolution: Domain Generation Algorithms |
| Data exfiltration via HTTP POST | T1048.003 — Exfiltration Over Alternative Protocol |
| Port scan reconnaissance | T1046 — Network Service Discovery |

---

## 8. Recommendations

> GUIDE: What should happen next? Be specific. Vague recommendations are useless.
> "Improve security" is not a recommendation. "Isolate host PC-042 and reset credentials 
> for user jsmith" is a recommendation.

**Immediate (within 24 hours):**
- [ ] Isolate host [IP/hostname] from the network
- [ ] Block destination IP `185[.]220[.]101[.]10` at the perimeter firewall
- [ ] Reset credentials for the user account associated with this host
- [ ] Preserve the PCAP and host disk image for further forensic analysis

**Short-term (within 1 week):**
- [ ] Conduct host-based forensic investigation on the isolated machine
- [ ] Search endpoint logs for the identified IOCs on all other hosts
- [ ] Review firewall rules to determine how the host was able to reach the external C2

**Long-term:**
- [ ] Consider deploying network-level IDS/IPS to detect similar beaconing patterns
- [ ] Review DNS logging to detect DGA activity earlier

---

## 9. Appendix

> GUIDE: Appendixes hold reference material that supports your report but would 
> clutter the main findings. Always include at minimum: the filters you used and any 
> files you exported. This lets someone reproduce your work exactly.

### Appendix A — Wireshark Filters Used

```
# Identify beaconing traffic
ip.src == 192.168.1.25 && ip.dst == 185.220.101.10

# Isolate DNS queries from suspect host
ip.src == 192.168.1.25 && dns

# Find NXDOMAIN responses (failed DGA lookups)
dns.flags.rcode == 3

# Export filter for standalone PCAP of suspicious traffic
ip.addr == 185.220.101.10
```

### Appendix B — Exported Artifacts

| Filename | Type | MD5 Hash | Notes |
|---|---|---|---|
| `stream_4_payload.bin` | Binary — possible implant | [hash] | Extracted from TCP stream #4 |
| `http_export_update.exe` | PE Executable | [hash] | Exported via File → Export Objects → HTTP |

### Appendix C — External Lookup Results

| IOC | Lookup Source | Result |
|---|---|---|
| `185.220.101.10` | AbuseIPDB | 42 reports — flagged as C2/malware host |
| `xkj23s.net` | VirusTotal | 14/90 vendors flagged as malicious |
| `185.220.101.10` | Shodan | Port 443 open, no hostname, AS [number] |

---

*Report prepared by: [Analyst Name]*
*Date: [YYYY-MM-DD]*
*Reviewed by: [Reviewer Name, if applicable]*
```

---

## 8. Quick Filter Reference

Keep this open while working. These are your most-used filters.

```
# ─── General ─────────────────────────────────────────
ip.addr == 192.168.1.100         # Traffic to/from any IP
ip.src == 192.168.1.100          # Traffic FROM this IP
ip.dst == 10.0.0.1               # Traffic TO this IP
tcp.port == 443                  # Any TCP on port 443
tcp.dstport == 4444              # TCP to destination port

# ─── Scanning Detection ───────────────────────────────
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN only — scan/flood
tcp.flags.reset == 1                        # RST packets

# ─── DoS / DDoS ──────────────────────────────────────
icmp                             # All ICMP
icmp && ip.dst == <victim IP>    # ICMP flood to target
udp && ip.dst == <victim IP>     # UDP flood to target

# ─── DNS ─────────────────────────────────────────────
dns                              # All DNS
dns.flags.response == 0          # Queries only
dns.flags.response == 1          # Responses only
dns.flags.rcode == 3             # NXDOMAIN (failed lookups)
dns.qry.name.len > 50            # Long names — possible tunneling

# ─── HTTP ────────────────────────────────────────────
http                             # All HTTP
http.request.method == "GET"     # GET requests
http.request.method == "POST"    # POST (data upload) requests
http.user_agent contains "curl"  # Suspicious user agents
http.authbasic                   # Basic auth credentials visible

# ─── TLS / HTTPS ─────────────────────────────────────
tls                              # All TLS
tls.handshake.type == 1          # Client Hello (start of handshake)
tls.handshake.type == 2          # Server Hello
tls.handshake.extensions_server_name contains "domain.com"   # By SNI

# ─── SMB / Lateral Movement ───────────────────────────
smb2                             # All SMBv2
tcp.port == 3389                 # RDP
tcp.port == 5985 || tcp.port == 5986   # WinRM

# ─── ARP / MITM ──────────────────────────────────────
arp                              # All ARP
arp.opcode == 2                  # ARP replies (watch for unsolicited ones)

# ─── Utility ─────────────────────────────────────────
tcp.stream eq 5                  # Follow a specific stream
frame.len > 1500                 # Large packets — exfil or exploit payloads
not (dns or arp or mdns or ssdp) # Exclude common background noise
```

---

*Guide version 2.0 — Written for Wireshark 4.x*
*Cross-reference with `readme.md` for tool setup and workspace configuration.*
