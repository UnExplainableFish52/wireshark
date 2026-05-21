# Wireshark Filters: Practical Thinking Guide

This file is about Wireshark display filters. The goal is not to memorize a long list of filters. The goal is to understand how filters are built, how to discover field names inside Wireshark, and how to use filters to answer real investigation questions.

A good filter is not just syntax. A good filter answers a question:

- Which host is talking?
- Which service is being used?
- Which connections failed?
- Which packets look abnormal?
- Which traffic is expected noise, and which traffic is left after that noise is removed?

If you keep the question clear, the filter becomes much easier to write.

---

## 1. Display Filters vs Capture Filters

Wireshark has two filter languages. They are not the same.

| Type | Used when | Example | What it is good for |
| --- | --- | --- | --- |
| Display filter | After packets are captured | `ip.addr == 10.0.0.5` | Investigation, triage, drilling into details |
| Capture filter | Before or during capture | `host 10.0.0.5` | Reducing what gets saved to disk |

Display filters are safer for learning and analysis because they do not delete evidence. They only hide packets from the current view. If the filter is wrong, clear it and the packets come back.

Capture filters are stricter. If a capture filter excludes traffic, that traffic is never saved. Use capture filters only when the traffic volume is too large or when you already know exactly what you need.

Common examples:

| Goal | Display filter | Capture filter |
| --- | --- | --- |
| One IP address | `ip.addr == 10.0.0.5` | `host 10.0.0.5` |
| One TCP port | `tcp.port == 443` | `tcp port 443` |
| One subnet | `ip.addr == 192.168.1.0/24` | `net 192.168.1.0/24` |
| Exclude one host | `not (ip.addr == 10.0.0.5)` | `not host 10.0.0.5` |

Most of this guide uses display filters.

---

## 2. The Mental Model

Think of each packet as one row in a table. Wireshark has hundreds of possible fields for that packet: source IP, destination IP, TCP flags, DNS query name, HTTP user agent, TLS server name, and many more.

A display filter is a true or false test against each packet. If the packet passes the test, Wireshark shows it. If it fails, Wireshark hides it.

Basic examples:

```wireshark
dns
```

Show packets that Wireshark dissected as DNS.

```wireshark
ip.addr == 10.0.0.5
```

Show packets where either the source IP or destination IP is `10.0.0.5`.

```wireshark
ip.src == 10.0.0.5
```

Show packets where `10.0.0.5` is the sender.

```wireshark
ip.dst == 10.0.0.5
```

Show packets where `10.0.0.5` is the receiver.

That direction matters. `ip.addr` is useful when you want both sides of a host's traffic. `ip.src` and `ip.dst` are useful when you care who started or received something.

---

## 3. Operators You Actually Need

Wireshark supports symbolic operators and word operators. Both forms work.

| Meaning | Symbol | Word |
| --- | --- | --- |
| Equal | `==` | `eq` |
| Not equal | `!=` | `ne` |
| Greater than | `>` | `gt` |
| Less than | `<` | `lt` |
| Greater than or equal | `>=` | `ge` |
| Less than or equal | `<=` | `le` |
| And | `&&` | `and` |
| Or | `\|\|` | `or` |
| Not | `!` | `not` |
| Contains text or bytes | `contains` | `contains` |
| Regex match | `matches` | `matches` |
| In a set or range | `in` | `in` |

These two filters mean the same thing:

```wireshark
ip.addr == 10.0.0.5
ip.addr eq 10.0.0.5
```

These also mean the same thing:

```wireshark
tcp.flags.syn == 1 and tcp.flags.ack == 0
tcp.flags.syn eq 1 && tcp.flags.ack eq 0
```

Use whichever style is easier to read. For notes and teaching, the word operators usually read better.

---

## 4. Parentheses Are Not Optional When Logic Gets Busy

When a filter mixes `and`, `or`, and `not`, use parentheses. Do not make yourself remember precedence rules while investigating traffic.

Unclear:

```wireshark
dns or http and ip.src == 10.0.0.5
```

Clear:

```wireshark
dns or (http and ip.src == 10.0.0.5)
```

Another clear example:

```wireshark
not (arp or stp or lldp) and not (tcp.port in {80 443})
```

This means:

- Hide ARP, STP, and LLDP.
- Hide TCP traffic on ports 80 and 443.
- Show what remains.

The parentheses make the first `not` apply to the whole protocol group.

---

## 5. Discover Field Names Instead of Memorizing Them

The strongest Wireshark skill is field discovery. You do not need to guess field names.

### Right-click the field

In the Packet Details pane, expand the protocol you care about and right-click a field.

Useful options:

- `Apply as Filter`: apply the filter immediately.
- `Prepare as Filter`: put the filter in the filter bar so you can edit it first.
- `Apply as Column`: turn that field into a visible column.

`Prepare as Filter` is especially useful because it teaches the exact field name without committing you to the filter yet.

### Watch the status bar

When you click a field in the Packet Details pane, Wireshark shows the internal field name near the bottom of the window. If you click a TCP source port, you will see a field name like `tcp.srcport`.

That field name is what you use in the display filter bar.

### Use autocomplete

Start typing in the display filter bar:

```wireshark
tcp.
```

Wireshark will show available TCP fields. This is usually faster than searching online.

### Add columns for repeated work

If you keep filtering on the same field, make it a column. For example, during DNS analysis, add columns for:

- `dns.qry.name`
- `dns.flags.rcode`
- `ip.src`
- `ip.dst`

Columns reduce the need to open packet details repeatedly.

---

## 6. Build Filters as an Investigation Path

Do not start with a complicated filter. Start broad, then narrow it.

Example question: What is host `10.0.0.23` doing with DNS?

Start with the host:

```wireshark
ip.addr == 10.0.0.23
```

Limit to DNS:

```wireshark
ip.addr == 10.0.0.23 and dns
```

Look at DNS queries from that host:

```wireshark
ip.src == 10.0.0.23 and dns.flags.response == 0
```

Look at failed DNS responses involving that host:

```wireshark
ip.addr == 10.0.0.23 and dns.flags.response == 1 and dns.flags.rcode != 0
```

That is the normal pattern:

1. Pick the host or conversation.
2. Pick the protocol.
3. Pick the behavior.
4. Read the packets and adjust.

The filter should follow your question.

---

## 7. High-Value Filters and How to Read Them

### Isolate One Host

```wireshark
ip.addr == 10.0.0.23
```

Shows all IPv4 traffic where `10.0.0.23` is either source or destination.

Use this when you want the whole picture for one machine.

```wireshark
ip.src == 10.0.0.23
```

Shows what the host sent.

```wireshark
ip.dst == 10.0.0.23
```

Shows what the host received.

Use direction-specific filters when you care who initiated the behavior.

---

### Isolate One TCP Conversation

Best method:

```text
Right-click a packet -> Conversation Filter -> TCP
```

Wireshark will generate a filter like this:

```wireshark
(ip.addr == 10.0.0.23 and ip.addr == 172.217.3.46) and (tcp.port == 51514 and tcp.port == 443)
```

This keeps both directions of the connection in the packet list. That matters because timing, retransmissions, resets, sequence numbers, and ACK behavior stay visible.

Use `Follow TCP Stream` when you want to read reconstructed payload. Use a conversation filter when you want to understand connection behavior.

---

### Remove Common Noise

```wireshark
not (arp or stp or lldp or mdns or nbns) and not (tcp.port in {80 443})
```

This hides common infrastructure and web traffic so unusual traffic is easier to see.

Use this as a triage lens, not as proof that the remaining traffic is malicious. Also remember that attackers often use ports 80 and 443. Do not exclude those ports too early if web traffic is part of the question.

Good use:

- You already looked at normal web traffic.
- You want to see odd protocols and uncommon ports.
- You are looking for traffic that does not fit the local baseline.

Bad use:

- You are hunting malware that may beacon over HTTPS.
- You have not looked at the main traffic volume yet.
- You are using the filter as a shortcut instead of analysis.

---

### Find TCP Problems Wireshark Detected

```wireshark
tcp.analysis.flags and not tcp.analysis.window_update
```

Wireshark marks packets that look interesting from a TCP behavior point of view. This filter shows those packets while hiding many harmless window update packets.

Useful subfilters:

```wireshark
tcp.analysis.retransmission
tcp.analysis.fast_retransmission
tcp.analysis.duplicate_ack
tcp.analysis.out_of_order
tcp.analysis.lost_segment
tcp.analysis.zero_window
```

How to read the results:

- Retransmissions suggest packet loss, delayed ACKs, or a capture taken from a point that missed packets.
- Duplicate ACKs usually mean the receiver noticed a gap.
- Out-of-order packets may mean path behavior, capture placement, or actual network disorder.
- Zero window means the receiver told the sender to stop because its receive buffer was full.

Do not treat one retransmission as a major finding. Look for volume, repeated patterns, and whether the same host or path keeps appearing.

---

### Find TCP Connection Attempts

```wireshark
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

This shows SYN packets that start TCP connections.

Use it to spot:

- Port scans from one source to many ports.
- Connection attempts to one service from many sources.
- Repeated failed attempts with no matching SYN-ACK.

Focus on one host:

```wireshark
ip.src == 10.0.0.23 and tcp.flags.syn == 1 and tcp.flags.ack == 0
```

Find SYN-ACK replies:

```wireshark
tcp.flags.syn == 1 and tcp.flags.ack == 1
```

If you see many SYN packets and very few SYN-ACK packets, ask why the connections are not completing. It could be scanning, filtering, packet loss, or a service that is down.

---

### Find TCP Resets

```wireshark
tcp.flags.reset == 1
```

Resets mean a TCP connection was forcefully closed.

How to read them:

- A reset from a server can mean the service rejected the connection.
- A reset from a client can mean the client gave up or closed abruptly.
- Repeated resets can suggest scanning, blocked services, broken applications, or middlebox interference.

Direction matters. Add `ip.src ==` or `ip.dst ==` to see who is sending the reset.

```wireshark
ip.src == 10.0.0.23 and tcp.flags.reset == 1
```

---

### Detect Abnormal TCP Flag Combinations

NULL scan style:

```wireshark
tcp.flags == 0x000
```

SYN and FIN together:

```wireshark
tcp.flags.syn == 1 and tcp.flags.fin == 1
```

Xmas scan style:

```wireshark
tcp.flags.fin == 1 and tcp.flags.push == 1 and tcp.flags.urg == 1 and tcp.flags.ack == 0
```

Normal TCP stacks do not usually create these combinations. If you see them, think scanning, crafted packets, evasion testing, or packet injection.

The next step is not to stop at the filter. Check the source IP, destination ports, timing, and whether the traffic repeats across many targets.

---

### Find DNS Failures

```wireshark
dns.flags.response == 1 and dns.flags.rcode != 0
```

This shows DNS responses that are not clean successes.

Common DNS response codes:

| RCODE | Meaning | What it can suggest |
| --- | --- | --- |
| `1` | Format error | Bad or malformed query |
| `2` | Server failure | Resolver or upstream problem |
| `3` | NXDOMAIN | Domain does not exist |
| `5` | Refused | Policy block or server refusing the query |

NXDOMAIN specifically:

```wireshark
dns.flags.rcode == 3
```

How to read it:

- A few NXDOMAIN responses are normal.
- Many NXDOMAIN responses from one host in a short time can indicate typos, broken software, malware domain generation, or failed beaconing.
- Random-looking domain names are more suspicious than readable business domains.

Focus on one suspected host:

```wireshark
ip.addr == 10.0.0.23 and dns.flags.rcode == 3
```

---

### Find Long DNS Query Names

```wireshark
dns.qry.name.len > 50
```

Long DNS names can be a sign of DNS tunneling or data encoded into subdomains.

Example of what to look for:

```text
dGhpcy1sb29rcy1saWtlLWVuY29kZWQtZGF0YQ.example.com
```

Use a higher threshold if your environment has CDNs, analytics tools, or security products that generate long but legitimate names.

Regex option for random-looking labels:

```wireshark
dns.qry.name matches "(?i)[a-z0-9]{30,}"
```

This does not prove tunneling. It gives you candidates to inspect.

---

### Hunt for Domains Across DNS, TLS, and HTTP

DNS query names:

```wireshark
dns.qry.name contains "example.com"
```

TLS server name from Client Hello:

```wireshark
tls.handshake.extensions_server_name contains "example.com"
```

HTTP Host header:

```wireshark
http.host contains "example.com"
```

Case-insensitive broad search:

```wireshark
frame matches "(?i)example"
```

How to read it:

- DNS shows name resolution.
- TLS SNI shows the requested encrypted destination when SNI is present.
- HTTP Host shows cleartext web requests.
- A broad `frame matches` search can find strings across the packet, but it is slower and less precise.

Modern encrypted protocols may hide some metadata. If you do not see SNI, that does not automatically mean there is no encrypted connection.

---

### Find TLS Client Hello Packets

```wireshark
tls.handshake.type == 1
```

Client Hello packets start TLS sessions. They often contain useful metadata like SNI, supported versions, cipher suites, and sometimes ALPN.

Show Client Hello packets that include a server name:

```wireshark
tls.handshake.type == 1 and tls.handshake.extensions_server_name
```

Why this matters:

- You can often see the destination domain without decrypting traffic.
- Repeated Client Hello packets to the same domain at regular intervals may indicate beaconing.
- Unknown domains over port 443 are often easier to triage through SNI than through raw IPs.

---

### Find Scripted or Tool-Based HTTP Clients

```wireshark
http.user_agent matches "(?i)(python|curl|wget|go-http-client|nmap|masscan|zgrab|nuclei)"
```

This finds HTTP requests using common tool or library user agents.

How to read it:

- A browser usually does not identify as `python-requests` or `curl`.
- Scanners often keep default user agents.
- Internal automation may also use these strings, so verify source host, destination, timing, and purpose.

This only works for cleartext HTTP or decrypted HTTP. It will not inspect normal encrypted HTTPS payload unless decryption is configured.

---

### Find HTTP Errors

```wireshark
http.response.code >= 400
```

This shows HTTP client and server errors.

Useful focused filters:

```wireshark
http.response.code == 401
http.response.code == 403
http.response.code == 404
http.response.code in {500..599}
```

How to read it:

- Many `401` responses can suggest failed authentication.
- Many `403` responses can suggest blocked access or probing.
- Many `404` responses from one client can suggest path scanning.
- Many `5xx` responses can suggest service instability or an application under stress.

Pair with source and destination filters:

```wireshark
ip.src == 10.0.0.23 and http.response.code >= 400
```

---

### Find Cleartext Credential Exposure

FTP username or password commands:

```wireshark
ftp.request.command == "USER" or ftp.request.command == "PASS"
```

HTTP Basic Authentication:

```wireshark
http.authbasic
```

Telnet traffic:

```wireshark
telnet
```

How to read it:

If you see credentials in cleartext protocols, that is a real exposure. FTP and Telnet send data without encryption. HTTP Basic Authentication only base64-encodes the credential string unless it is protected inside HTTPS.

Do not paste recovered credentials into notes unless you have a clear reason and permission. Record the protocol, host, time, and evidence location instead.

---

### Find SMB and Windows Lateral Movement Signals

SMB2 from one host:

```wireshark
smb2 and ip.src == 10.0.0.23
```

Windows file sharing and remote management ports:

```wireshark
tcp.port in {135 139 445 5985 5986} and ip.src == 10.0.0.23
```

How to read it:

- A workstation touching many hosts over SMB in a short time is suspicious.
- WinRM traffic on ports `5985` and `5986` can be normal administration or lateral movement.
- The pattern matters more than one packet. Look at destination count, timing, and whether the source is expected to administer other machines.

---

### Use GeoIP as Triage, Not Proof

GeoIP filters require MaxMind databases to be configured in Wireshark.

Country name:

```wireshark
ip.geoip.country == "China"
```

Country code:

```wireshark
ip.geoip.country_iso == "RU"
```

Connection attempts to a country:

```wireshark
ip.geoip.country_iso == "RU" and tcp.flags.syn == 1 and tcp.flags.ack == 0
```

How to read it:

GeoIP can help you quickly notice external traffic by country. It is not proof of attacker location. IP geolocation can be wrong, cloud hosting moves, and VPNs change the apparent source or destination.

---

## 8. Common Mistakes

### Using capture filter syntax in the display filter bar

Wrong for display filters:

```text
host 10.0.0.5
tcp port 443
```

Correct display filters:

```wireshark
ip.addr == 10.0.0.5
tcp.port == 443
```

### Using `and` when you mean `or`

If you want to see DNS and HTTP traffic together:

```wireshark
dns or http
```

This means show packets that are DNS or packets that are HTTP.

This is different:

```wireshark
dns and http
```

That means show packets that are both DNS and HTTP at the same time. That is usually not what you want.

There are exceptions, such as one protocol being transported inside another, but for normal top-level protocol viewing, `or` is usually the right choice.

### Following streams too early

`Follow TCP Stream` is useful for reading payload. It is not the best first step for behavior analysis because it hides packet timing, retransmissions, flags, and resets.

Use the packet list and conversation filters first. Follow the stream after you know which conversation matters.

### Filtering out 443 too early

HTTPS is common, but that does not make it harmless. Many malicious connections use port 443 because it blends in. Exclude it only when your current question allows it.

### Treating one filter hit as proof

A filter gives you a lead. It does not automatically give you a conclusion. Always check:

- Source and destination.
- Direction.
- Timing.
- Frequency.
- Whether the behavior is expected in that environment.

---

## 9. Quick Reference

| Goal | Filter |
| --- | --- |
| Show one host, both directions | `ip.addr == 10.0.0.23` |
| Show traffic sent by one host | `ip.src == 10.0.0.23` |
| Show traffic received by one host | `ip.dst == 10.0.0.23` |
| Show one TCP or UDP port | `tcp.port == 443` |
| Show a list of TCP ports | `tcp.port in {80 443 8080 8443}` |
| Show a TCP port range | `tcp.port in {8000..8099}` |
| Show DNS traffic | `dns` |
| Show DNS queries only | `dns.flags.response == 0` |
| Show DNS responses only | `dns.flags.response == 1` |
| Show DNS failures | `dns.flags.response == 1 and dns.flags.rcode != 0` |
| Show NXDOMAIN | `dns.flags.rcode == 3` |
| Show long DNS names | `dns.qry.name.len > 50` |
| Show TCP problem indicators | `tcp.analysis.flags and not tcp.analysis.window_update` |
| Show TCP retransmissions | `tcp.analysis.retransmission` |
| Show TCP SYN attempts | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| Show TCP resets | `tcp.flags.reset == 1` |
| Show NULL scan style packets | `tcp.flags == 0x000` |
| Show SYN and FIN together | `tcp.flags.syn == 1 and tcp.flags.fin == 1` |
| Show Xmas scan style packets | `tcp.flags.fin == 1 and tcp.flags.push == 1 and tcp.flags.urg == 1 and tcp.flags.ack == 0` |
| Show TLS Client Hello packets | `tls.handshake.type == 1` |
| Show TLS Client Hello with SNI | `tls.handshake.type == 1 and tls.handshake.extensions_server_name` |
| Search for a domain in TLS SNI | `tls.handshake.extensions_server_name contains "example.com"` |
| Search HTTP hosts | `http.host contains "example.com"` |
| Search for HTTP tool user agents | `http.user_agent matches "(?i)(python|curl|wget|nmap|masscan|zgrab|nuclei)"` |
| Show HTTP errors | `http.response.code >= 400` |
| Show cleartext FTP login commands | `ftp.request.command == "USER" or ftp.request.command == "PASS"` |
| Show HTTP Basic Authentication | `http.authbasic` |
| Show SMB2 from a host | `smb2 and ip.src == 10.0.0.23` |
| Show Windows admin and file sharing ports | `tcp.port in {135 139 445 5985 5986}` |
| Broad case-insensitive string search | `frame matches "(?i)keyword"` |
| Remove common local noise | `not (arp or stp or lldp or mdns or nbns)` |

---

## 10. Final Rule

Start with the question, then build the filter.

If the question is "who is this host talking to," start with `ip.addr`.

If the question is "why is this connection slow," start with a conversation filter and TCP analysis flags.

If the question is "is this host resolving strange domains," start with DNS queries and DNS failures.

If the question is "is this traffic automated," check user agents, timing, repeated destinations, and connection patterns.

Wireshark filters are not the investigation. They are how you keep the investigation focused.
