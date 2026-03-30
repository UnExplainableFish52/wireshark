# Wireshark SOC Filter Playbook

## Objective
Use this guide to quickly filter packet captures during triage and investigations, reduce noise, and turn traffic patterns into actionable security deductions.

VThis is a practical "top 15" list of high-value filters used by SOC analysts in daily workflow and incident response.

## How To Use This Reference
For each filter below, capture four things in your notes:
1. What stands out (anomaly, volume, destination, timing).
2. What it likely means (initial deduction).
3. What is still unknown.
4. What filter to run next.

## Top 15 High-Value Wireshark Filters For SOC Work

| # | Filter Syntax | What It Helps You See | Likely Deduction | What To Narrow Down Next |
|---|---|---|---|---|
| 1 | `ip.addr == x.x.x.x` | All traffic to/from a specific host | Host-centric timeline for compromise or suspicious behavior | Pivot to `tcp.stream eq N`, `udp.stream eq N`, or isolate by protocol |
| 2 | `tcp` | All TCP traffic | Baseline of stateful client-server activity | Split by service ports, resets, retransmissions, and streams |
| 3 | `udp` | All UDP traffic | Visibility into DNS, NTP, QUIC, VoIP, and other connectionless traffic | Isolate `dns`, `quic`, unusual destination ports, and burst volume |
| 4 | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Initial TCP connection attempts (SYN only) | Possible scan behavior, broad service discovery, or normal session starts | Add `ip.src ==` or `ip.dst ==`; compare unique targets and rate |
| 5 | `tcp.flags.reset == 1` | TCP resets | Failed sessions, blocked activity, or service instability | Correlate with destination ports and failed auth patterns |
| 6 | `tcp.analysis.retransmission` | Retransmitted TCP segments | Packet loss, unstable network path, or overloaded service | Compare source/destination pairs and time windows to separate outage vs attack noise |
| 7 | `dns` | DNS queries and responses | Domain resolution behavior and potential C2 beacon clues | Use `dns.qry.name`, `dns.flags.rcode`, and host pivots |
| 8 | `dns.flags.rcode != 0` | DNS errors (NXDOMAIN, SERVFAIL, etc.) | DGA-like lookups, typos, sinkhole hits, misconfigurations | Identify repeated query names, entropy-like domains, and querying hosts |
| 9 | `http.request` | HTTP requests only | Cleartext browsing, scripted callbacks, malware staging, web abuse | Inspect `http.host`, `http.request.uri`, `http.user_agent` |
|10 | `http.response.code >= 400` | HTTP client/server errors | Failed access, broken automation, brute force side effects, blocked paths | Pair with source host, URI patterns, and auth-related endpoints |
|11 | `tls.handshake.type == 1` | TLS Client Hello packets | Outbound encrypted session starts and TLS usage footprint | Check `tls.handshake.extensions_server_name` for suspicious domains |
|12 | `icmp` | ICMP echo/unreachable/time-exceeded | Network mapping, reachability tests, tunneling suspicion, troubleshooting | Distinguish routine monitoring from unusual volume or external destinations |
|13 | `arp.duplicate-address-detected || arp.duplicate-address-frame` | Duplicate IP/MAC ARP conflicts | Potential spoofing, misconfiguration, or ARP poisoning indicators | Map MAC/IP relationships over time and verify switch logs |
|14 | `smb || smb2` | SMB file-share traffic | Lateral movement, file staging, remote admin activity | Add host filters and look for unusual share access timing |
|15 | `rdp || ssh` | Remote administration protocols | Admin activity, remote access, possible unauthorized access | Correlate source identity, login timing, destination criticality |

## Useful Companion Filters (Quick Pivots)

- `frame contains "password"`
	- Use when investigating possible cleartext credential leakage.
	- Next: confirm protocol and scope, avoid false positives from unrelated payload text.

- `tcp.port == 3389` or `tcp.port == 22`
	- Focused remote-access triage.
	- Next: identify uncommon source IPs and off-hours usage.

- `ip.dst == x.x.x.x && !(ip.src == x.x.x.x)`
	- Inbound focus to a critical host.
	- Next: identify unusual source distribution and burst attempts.

- `ip.src == x.x.x.x && tcp.flags.syn == 1 && tcp.flags.ack == 0`
	- Suspected scanning host behavior.
	- Next: count unique destination IP:port combinations.

- `dns.qry.name contains "update"` (or other keyword)
	- Threat-hunting hypothesis on themed domains.
	- Next: validate resolved IPs and process/network telemetry outside PCAP.

## Practical Deduction Workflow

1. Start broad: `ip`, `tcp`, `udp`, `dns`, `http`, `tls`.
2. Isolate suspicious host(s): `ip.addr == x.x.x.x`.
3. Identify access patterns: SYN-only, resets, retransmissions, failed responses.
4. Pivot by protocol detail: DNS names, HTTP URIs, TLS SNI, SMB paths.
5. Build timeline by stream and timestamp.
6. Separate confirmed facts from assumptions.

## Investigation Notes Template

- Filter used:
- Observation:
- Initial deduction:
- Confidence (low/medium/high):
- What remains unknown:
- Next filter or data source to validate:

## Scope Reminder
These filters are high-value starting points, not final proof. Always validate deductions with endpoint logs, authentication events, EDR telemetry, firewall logs, and asset context.

