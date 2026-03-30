# Wireshark Traffic Analysis: Questions and Answers

Practice this with the net_ctf.pcapng as provided along with the project. 

Packet capture file: net_ctf.pcapng

---

## 1) Which type of TCP packet was primarily used by host `192.168.1.111` to probe open ports on the target?

<details>
	<summary><strong>Show Answer</strong></summary>

The host primarily used **TCP SYN** packets.

Using the display filter `ip.src == 192.168.1.111`, you can isolate packets sent by that source. In the results, most TCP packets contain the SYN flag, which is the first step of a TCP connection attempt.

When many SYN packets are sent to different destination ports in a short period, it usually indicates a port scan. The goal is to discover which ports are open and what services may be available on the target host (`192.168.1.9`).

</details>

---

## 2) Multiple TCP SYN packets are sent across different ports, but the handshake is not completed. Which host is generating this traffic?

<details>
	<summary><strong>Show Answer</strong></summary>

The source host is **`192.168.1.111`**.

Apply this filter:

`tcp.flags.syn == 1 && tcp.flags.ack == 0`

This displays SYN-only packets, which are initial connection requests. In normal communication, many of these would be followed by SYN-ACK and then ACK to complete the three-way handshake.

Here, the traffic pattern is repeated SYN attempts to many ports without full session completion. That behavior strongly suggests probing/scanning activity, and the packet source shows that `192.168.1.111` is generating it.

</details>

---

## 3) An analyst observes repeated TCP handshakes with multiple external systems. In Wireshark Conversations (IPv4), which internal host communicates with the highest number of external hosts?

<details>
	<summary><strong>Show Answer</strong></summary>

The internal host is **`192.168.1.9`**.

Using `tcp.flags.syn == 0 && tcp.flags.ack == 1` helps highlight acknowledgment traffic associated with established or ongoing TCP sessions. This makes active communication patterns easier to spot.

Then, in **Statistics -> Conversations -> IPv4**, you can compare how many distinct peers each internal host talks to. `192.168.1.9` appears with the highest number of external conversation partners, so it is the internal host communicating most broadly.

</details>

---

## 4) If `192.168.1.111` appears to be the scanning source based on many connection attempts, what cyber attack lifecycle phase does this represent?

<details>
	<summary><strong>Show Answer</strong></summary>

This activity represents the **Reconnaissance** phase.

At this stage, the attacker is not necessarily exploiting a vulnerability yet. Instead, they are collecting information about the target environment, such as reachable hosts, open ports, and exposed services.

That information is typically used to plan the next phase of the attack, where specific vulnerabilities or weak configurations may be targeted.

</details>

