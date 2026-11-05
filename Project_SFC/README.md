# Service Function Chaining (SFC) over MPLS/NSH in P4

## 1. Architecture Introduction

The network architecture implements a Service Function Chaining (SFC) overlay using P4 (BMv2 `simple_switch`) devices emulated in Kathará. Traffic is steered into predefined service chains according to static policies:

* **Chain 1 (SPI 1)**: TCP traffic from H1 to H3 (destination port 5201) must traverse **SF1 → SF3 → SF2**.
* **Chain 2 (SPI 2)**: TCP traffic from H2 to H4 (destination port 5201) must traverse **SF3**.
* **Return traffic** (H3 → H1, H4 → H2) bypasses the chains and is forwarded over plain IPv4 along the shortest path.

The network logic is distributed across distinct node roles. Only three P4 programs are used (`shared/router.p4`, `shared/classifier.p4`, `shared/sff.p4`); the role of each node is determined by the table entries loaded from its `commands.txt`.

* **Access Router (`SWA`, `router.p4`)**: A standard IPv4 edge router connecting the client hosts (H1, H2) to the network. It is entirely unaware of the SFC overlay and uses longest-prefix match (LPM) routing to send traffic towards the Classifier and to route return traffic back to the hosts.
* **Classifier (`SWB`, `classifier.p4`)**: The ingress point of the SFC domain. It matches IPv4/TCP packets on (source IP, destination IP, protocol, TCP destination port). Matching packets are encapsulated with an NSH header (SPI, SI) and an MPLS label identifying the tunnel towards the first SFF. Non-matching packets (ping, return traffic, TCP on other ports) are forwarded with ordinary IPv4 LPM.
* **MPLS Transit Nodes (`SWC`, `SWF`, `SWG`, `sff.p4`)**: Label-switching routers of the overlay. They forward encapsulated packets **only on the MPLS label** (table `mpls_tbl`, action `mpls_forward`) and decrement the MPLS TTL. They never inspect or modify the NSH header. They also route return traffic with IPv4 LPM.
* **Service Function Forwarders & Proxies (`SWD`, `SWE`, `sff.p4`)**: Tail ends of the MPLS tunnels (`mpls_terminate`). The forwarding decision is taken on the NSH pair **(SPI, SI)** (table `sff_exact`). Because the SFs are not NSH-aware, the SFF acts as a proxy: it strips MPLS and NSH before delivering the plain Eth/IPv4/TCP packet to the SF, and when the SF returns the packet it restores the NSH context with the decremented Service Index and pushes the MPLS label of the tunnel towards the next overlay element.
* **Egress Node (`SWH`, `sff.p4`)**: Tail end of the last tunnel of each chain. When a packet arrives with the final Service Index (SI = 1), it reuses the proxy decapsulation action to strip MPLS and NSH and deliver plain Eth/IPv4/TCP to the destination host (H3, H4). It also routes return traffic with IPv4 LPM.
* **Service Functions (`SF1`, `SF2`, `SF3`, `router.p4`)**: Simple P4 reflectors with a single port. They only parse Ethernet/IPv4, decrement the IPv4 TTL and send the packet back to the attached SFF. They never see MPLS or NSH.

### MPLS Tunnels

Each tunnel between two overlay elements has its own label. Labels are unique per tunnel, so transit nodes forward without swapping; the label is pushed by the head end (classifier or SFF proxy) and popped by the tail end (SFF or egress node).

| Label | Tunnel | Physical path | NSH carried (SPI, SI) |
|---|---|---|---|
| 101 | Classifier B → SFF D | B – D | (1, 4) |
| 102 | SFF D → SFF E | D – F – G – E | (1, 3) |
| 103 | SFF E → SFF D | E – G – F – D | (1, 2) |
| 104 | SFF D → Egress H | D – F – H | (1, 1) |
| 201 | Classifier B → SFF E | B – C – E | (2, 2) |
| 202 | SFF E → Egress H | E – G – H | (2, 1) |

The field `spi_si` is the 32-bit service path header: `SPI << 8 | SI`. For example, the classifier writes `1 << 8 | 4 = 260` for chain 1 and `2 << 8 | 2 = 514` for chain 2. The SI starts from the number of SFs plus one and is decremented after every SF, so SI = 1 means the chain is complete.

**Header Size Assumptions:**
To correctly calculate the Maximum Segment Size (MSS) and parse packets, the following header sizes were assumed:

* **MPLS Header**: 4 bytes (one label, bottom of stack)
* **NSH Header**: 8 bytes (RFC 8300 base header + service path header, MD Type 2 with no context headers)
* **Inner Ethernet Header**: 14 bytes (the original frame is preserved, NSH next protocol = Ethernet)
* **Total Overhead**: 26 bytes.

---

## 2. P4 Header and Parser Definition

To handle the overlay, the P4 programs define a stacked header structure representing `Outer Eth -> MPLS -> NSH -> Inner Eth -> IPv4 -> TCP`. Header definitions are repeated at the top of `classifier.p4` and `sff.p4`; `router.p4` only defines Ethernet and IPv4.

### Header Definitions (`classifier.p4`, `sff.p4`)

```p4
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_MPLS = 0x8847;
const bit<8>  NSH_NEXT_ETH = 3;

header mpls_t {
    bit<20> label;
    bit<3>  tc;
    bit<1>  bos;
    bit<8>  ttl;
}

// RFC 8300 base header (4 bytes) + service path header (4 bytes) = 8 bytes
header nsh_t {
    bit<2>  ver;
    bit<1>  o;
    bit<1>  c_u;
    bit<6>  ttl;
    bit<6>  length;
    bit<4>  u_flags;
    bit<4>  md_type;
    bit<8>  next_proto;
    bit<32> spi_si;     // SPI (24 bit) << 8 | SI (8 bit)
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    mpls_t     mpls;
    nsh_t      nsh;
    ethernet_t inner_ethernet;
    ipv4_t     inner_ipv4;
    tcp_t      inner_tcp;
}
```

### Parser Implementation (`sff.p4`)

The parser transitions based on the `etherType` and the NSH `next_proto` fields, peeling back the encapsulation layers sequentially. The classifier parser is a subset of it, since the classifier only receives plain IPv4 traffic.

```p4
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MPLS: parse_mpls;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    // Plain IPv4 traffic (return traffic, traffic coming back from an SF)
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    // SFC overlay: Eth / MPLS / NSH / Eth / IPv4 / TCP
    state parse_mpls {
        packet.extract(hdr.mpls);
        packet.extract(hdr.nsh);
        transition select(hdr.nsh.next_proto) {
            NSH_NEXT_ETH: parse_inner_ethernet;
            default: accept;
        }
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            TYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            6: parse_inner_tcp;
            default: accept;
        }
    }

    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        transition accept;
    }
}
```

---

## 3. Classification and Ingress Logic

The Classifier uses a Match-Action table to map a subset of the 5-tuple (source IP, destination IP, protocol, TCP destination port) to a specific Service Path. The TCP source port is not part of the key because the iperf3 client chooses it randomly.

When a match is found, the `encap_sfc` action is triggered. It copies the original Ethernet, IPv4 and TCP headers into the inner headers, then pushes NSH and MPLS on the outside. Packets that do not match any policy are forwarded with the `ipv4_lpm` table.

### Classifier Match-Action Table

```p4
action encap_sfc(bit<24> spi, bit<8> si, bit<20> mpls_label, egressSpec_t port, macAddr_t dstMac, macAddr_t srcMac) {
    meta.is_sfc = 1;

    // 1. Preserve original packet inside inner headers
    hdr.inner_ethernet = hdr.ethernet;
    hdr.inner_ipv4 = hdr.ipv4;
    hdr.inner_tcp = hdr.tcp;

    // 2. Build Outer Ethernet for overlay transport
    hdr.ethernet.dstAddr = dstMac;
    hdr.ethernet.srcAddr = srcMac;   // MAC of the egress interface toward the tunnel
    hdr.ethernet.etherType = TYPE_MPLS;

    // 3. Push MPLS label: it identifies the tunnel classifier -> first SFF
    hdr.mpls.setValid();
    hdr.mpls.label = mpls_label;
    hdr.mpls.tc = 0;
    hdr.mpls.bos = 1;
    hdr.mpls.ttl = 64;

    // 4. Build NSH Header
    hdr.nsh.setValid();
    hdr.nsh.ver = 0;
    hdr.nsh.o = 0;
    hdr.nsh.c_u = 0;
    hdr.nsh.ttl = 63;
    hdr.nsh.length = 2;       // 8 bytes -> 2 words
    hdr.nsh.u_flags = 0;
    hdr.nsh.md_type = 2;      // MD Type 2 with no context headers (RFC 8300)
    hdr.nsh.next_proto = 3;   // Next is Ethernet (RFC 8300)
    hdr.nsh.spi_si = ((bit<32>)spi << 8) | (bit<32>)si;

    // 5. Invalidate outer IP/TCP so they aren't emitted twice
    hdr.ipv4.setInvalid();
    hdr.tcp.setInvalid();

    sm.egress_spec = port;
}

table classify {
    key = {
        hdr.ipv4.srcAddr: exact;
        hdr.ipv4.dstAddr: exact;
        hdr.ipv4.protocol: exact;
        hdr.tcp.dstPort: exact;
    }
    actions = { encap_sfc; NoAction; }
    size = 64;
    default_action = NoAction();
}

apply {
    meta.is_sfc = 0;
    if (hdr.ipv4.isValid()) {
        if (hdr.tcp.isValid()) {
            classify.apply();
        }
        if (meta.is_sfc == 0) {
            ipv4_lpm.apply();   // ping, return traffic, TCP on other ports
        }
    }
}
```

### Classifier Rules (`swb/commands.txt`)

```
table_add MyIngress.classify encap_sfc 10.0.1.1 10.0.3.1 6 5201 => 1 4 101 3 00:00:00:00:0D:00 00:00:00:00:0B:02
table_add MyIngress.classify encap_sfc 10.0.2.1 10.0.4.1 6 5201 => 2 2 201 2 00:00:00:00:0C:01 00:00:00:00:0B:01
```

Chain 1 starts with SPI 1, SI 4 (three SFs) in tunnel 101 towards SWD; chain 2 starts with SPI 2, SI 2 (one SF) in tunnel 201 towards SWE through SWC.

---

## 4. MPLS Transport, SFF and Proxy Logic

All overlay nodes run `sff.p4`. An encapsulated packet is first processed by the **MPLS layer** and, only if the tunnel terminates on the current node, by the **SFF layer**:

1. **MPLS transit (`mpls_forward`)**: The label is looked up in `mpls_tbl`. On transit nodes the packet is sent towards the next hop with new outer MAC addresses and a decremented MPLS TTL. The NSH header is left untouched.
2. **Tunnel termination (`mpls_terminate`)**: On SFFs and on the egress node the label identifies a tunnel ending here. The packet is then processed by `sff_exact`, keyed on the NSH `spi_si` field. Unknown (SPI, SI) pairs, expired MPLS/NSH TTLs and unknown labels are dropped.
3. **Proxy Decapsulation (`sff_proxy_decap`)**: The SFF promotes the inner Ethernet/IPv4/TCP headers to outer headers, removes MPLS and NSH, and sends the plain packet to the attached SF. The same action is used by `SWH` to deliver the packet to the destination host at the end of the chain.
4. **Proxy Encapsulation (`sff_proxy_encap`)**: The SF returns a plain IPv4 packet on the port it is attached to. Since the SF is not NSH-aware, the SFF reconstructs the service context from the table `sf_return`, keyed on (ingress port, source IP, destination IP). It restores NSH with the decremented SI (`SI = SI - 1`), pushes the MPLS label of the tunnel towards the next overlay element, and forwards the packet back into the overlay. This is how SWE distinguishes the two chains that both use SF3.
5. **Forward to another SFF (`sff_forward_tunnel`)**: Swaps the MPLS label and forwards the packet to another SFF without visiting a local SF. It is implemented for completeness but not used by the two chains of this project.

### Ingress Control Flow

```p4
apply {
    meta.is_sfc = 0;

    if (hdr.mpls.isValid()) {
        // Overlay packet: first the tunnel layer, then (if terminated here) the SFF layer
        if (hdr.mpls.ttl <= 1) {
            drop();
        } else {
            switch (mpls_tbl.apply().action_run) {
                mpls_terminate: {
                    if (!hdr.nsh.isValid() || hdr.nsh.ttl == 0) {
                        drop();
                    } else {
                        sff_exact.apply();
                    }
                }
            }
        }
    }
    else if (hdr.ipv4.isValid()) {
        // Either a packet returning from a local SF, or ordinary IPv4 traffic
        sf_return.apply();
        if (meta.is_sfc == 0) {
            ipv4_lpm.apply();
        }
    }
}
```

### Proxy Actions

```p4
action sff_proxy_decap(macAddr_t srcMac, macAddr_t dstMac, egressSpec_t port) {
    hdr.ethernet = hdr.inner_ethernet;
    hdr.ipv4     = hdr.inner_ipv4;
    hdr.tcp      = hdr.inner_tcp;

    hdr.ethernet.srcAddr = srcMac;
    hdr.ethernet.dstAddr = dstMac;
    sm.egress_spec = port;

    hdr.mpls.setInvalid();
    hdr.nsh.setInvalid();
    hdr.inner_ethernet.setInvalid();
    hdr.inner_ipv4.setInvalid();
    hdr.inner_tcp.setInvalid();
}

action sff_proxy_encap(bit<32> new_spi_si, bit<20> mpls_label,
                       macAddr_t srcMac, macAddr_t dstMac, egressSpec_t port) {
    meta.is_sfc = 1;

    hdr.inner_ethernet = hdr.ethernet;
    hdr.inner_ipv4     = hdr.ipv4;
    hdr.inner_tcp      = hdr.tcp;

    hdr.ethernet.srcAddr   = srcMac;
    hdr.ethernet.dstAddr   = dstMac;
    hdr.ethernet.etherType = TYPE_MPLS;

    hdr.mpls.setValid();
    hdr.mpls.label = mpls_label;
    hdr.mpls.tc = 0; hdr.mpls.bos = 1; hdr.mpls.ttl = 64;

    hdr.nsh.setValid();
    hdr.nsh.ver = 0; hdr.nsh.o = 0; hdr.nsh.c_u = 0;
    hdr.nsh.ttl = 63; hdr.nsh.length = 2; hdr.nsh.u_flags = 0;
    hdr.nsh.md_type = 2; hdr.nsh.next_proto = NSH_NEXT_ETH;
    hdr.nsh.spi_si = new_spi_si;

    hdr.ipv4.setInvalid();
    hdr.tcp.setInvalid();
    sm.egress_spec = port;
}
```

### Example: SFF D Rules (`swd/commands.txt`)

```
table_add MyIngress.mpls_tbl mpls_terminate 101 =>
table_add MyIngress.mpls_tbl mpls_terminate 103 =>

table_add MyIngress.sff_exact sff_proxy_decap 260 => 00:00:00:00:0D:02 00:00:00:00:F1:00 3
table_add MyIngress.sf_return sff_proxy_encap 3 10.0.1.1 10.0.3.1 => 259 102 00:00:00:00:0D:01 00:00:00:00:0F:01 2

table_add MyIngress.sff_exact sff_proxy_decap 258 => 00:00:00:00:0D:03 00:00:00:00:F2:00 4
table_add MyIngress.sf_return sff_proxy_encap 4 10.0.1.1 10.0.3.1 => 257 104 00:00:00:00:0D:01 00:00:00:00:0F:01 2
```

(SPI 1, SI 4) is delivered to SF1; on return it becomes (1, 3) in tunnel 102 towards SWE. (SPI 1, SI 2) is delivered to SF2; on return it becomes (1, 1) in tunnel 104 towards the egress node SWH.

---

## 5. Test Results (iperf3)

To validate the service chains, bandwidth testing was conducted using `iperf3`, and packet captures were taken with `tcpdump` on the SFF–SF links and on the overlay links.

Due to the addition of MPLS (4 bytes), NSH (8 bytes), and Inner Ethernet (14 bytes) headers, the standard MTU of 1500 bytes would cause fragmentation or packet loss within the overlay. To prevent this, the MSS (Maximum Segment Size) was explicitly lowered to **1434 bytes** in the `iperf3` client commands. This is derived from: 1500 - 4 (MPLS) - 8 (NSH) - 14 (Inner Eth) = 1474 bytes for the maximum inner IPv4 packet. Subtracting 20 bytes for IPv4 and 20 bytes for TCP yields exactly 1434 bytes.

**How the order of the SFs is verified:** every SF is a `router.p4` reflector and decrements the IPv4 TTL, while the classifier, transit nodes and SFFs never modify the inner IPv4 header (they work on MPLS and NSH). The only IPv4 routers on the forward path are SWA and the SFs, so the TTL observed on each SFF–SF link reveals the position of that SF in the chain:

```
Chain 1:  H1 sends TTL 64 -> SWA 63 -> SF1 62 -> SF3 61 -> SF2 60 -> H3
Chain 2:  H2 sends TTL 64 -> SWA 63 -> SF3 62 -> H4
```

### Chain 1: H1 -> H3 (Passes through SF1, SF3, SF2)

```bash
# Executed on H1
root@h1:/# iperf3 -c 10.0.3.1 -M 1434 -t 10
Connecting to host 10.0.3.1, port 5201
[  5] local 10.0.1.1 port 53038 connected to 10.0.3.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  3.25 MBytes  27.2 Mbits/sec   32   59.7 KBytes
[  5]   1.00-2.00   sec  3.05 MBytes  25.6 Mbits/sec    1   72.2 KBytes
[  5]   2.00-3.00   sec  3.19 MBytes  26.7 Mbits/sec   11   70.8 KBytes
[  5]   3.00-4.00   sec  2.93 MBytes  24.6 Mbits/sec    7   40.3 KBytes
[  5]   4.00-5.00   sec  3.05 MBytes  25.6 Mbits/sec    0   77.8 KBytes
[  5]   5.00-6.00   sec  3.11 MBytes  26.1 Mbits/sec    5   55.5 KBytes
[  5]   6.00-7.00   sec  3.05 MBytes  25.6 Mbits/sec    0   88.9 KBytes
[  5]   7.00-8.00   sec  3.21 MBytes  26.9 Mbits/sec   10   83.3 KBytes
[  5]   8.00-9.00   sec  3.17 MBytes  26.6 Mbits/sec    4   80.5 KBytes
[  5]   9.00-10.00  sec  3.17 MBytes  26.6 Mbits/sec    0    107 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  31.2 MBytes  26.2 Mbits/sec   70             sender
[  5]   0.00-10.04  sec  31.1 MBytes  26.0 Mbits/sec                  receiver
```

The retransmissions are caused by the limited forwarding performance of the BMv2 software switch (queue drops when TCP ramps up), not by the SFC logic: the transfer completes and sender/receiver volumes match.

**SFF–SF link captures (SYN of the data connection, IP id 39383).** All three SFs receive plain `ethertype IPv4 (0x0800)` packets, with no MPLS or NSH. The TTL entering each SF (63, 62, 61) and the timestamps confirm the order SF1 → SF3 → SF2. The SYN also shows the MSS of 1434 set by `-M`. The control connection of iperf3 (port 53030, not shown) follows the same sequence with MSS 1460, because `-M` only applies to the data connection.

```bash
# SWD eth2 (SFF D <-> SF1)
root@swd:/# grep -B1 "Flags \[S\]" /tmp/sf1.txt
18:37:19.792388 00:00:00:00:0d:02 > 00:00:00:00:f1:00, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 63, id 39383, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.1.1.53038 > 10.0.3.1.5201: Flags [S], cksum 0xcebf (correct), seq 4245702053, win 64530, options [mss 1434,sackOK,TS val 3588319534 ecr 0,nop,wscale 7], length 0
18:37:19.792678 00:00:00:00:f1:00 > 00:00:00:00:0d:02, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 62, id 39383, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.1.1.53038 > 10.0.3.1.5201: Flags [S], cksum 0xcebf (correct), seq 4245702053, win 64530, options [mss 1434,sackOK,TS val 3588319534 ecr 0,nop,wscale 7], length 0

# SWE eth2 (SFF E <-> SF3)
root@swe:/# grep -B1 "Flags \[S\]" /tmp/sf3.txt
18:37:19.793504 00:00:00:00:0e:02 > 00:00:00:00:f3:00, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 62, id 39383, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.1.1.53038 > 10.0.3.1.5201: Flags [S], cksum 0xcebf (correct), seq 4245702053, win 64530, options [mss 1434,sackOK,TS val 3588319534 ecr 0,nop,wscale 7], length 0
18:37:19.793750 00:00:00:00:f3:00 > 00:00:00:00:0e:02, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 61, id 39383, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.1.1.53038 > 10.0.3.1.5201: Flags [S], cksum 0xcebf (correct), seq 4245702053, win 64530, options [mss 1434,sackOK,TS val 3588319534 ecr 0,nop,wscale 7], length 0

# SWD eth3 (SFF D <-> SF2)
root@swd:/# grep -B1 "Flags \[S\]" /tmp/sf2.txt
18:37:19.794537 00:00:00:00:0d:03 > 00:00:00:00:f2:00, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 61, id 39383, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.1.1.53038 > 10.0.3.1.5201: Flags [S], cksum 0xcebf (correct), seq 4245702053, win 64530, options [mss 1434,sackOK,TS val 3588319534 ecr 0,nop,wscale 7], length 0
18:37:19.794784 00:00:00:00:f2:00 > 00:00:00:00:0d:03, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 60, id 39383, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.1.1.53038 > 10.0.3.1.5201: Flags [S], cksum 0xcebf (correct), seq 4245702053, win 64530, options [mss 1434,sackOK,TS val 3588319534 ecr 0,nop,wscale 7], length 0
```

The whole flow, not only the SYN, traverses the SFs: on the SF3 link the number of packets entering the SF equals the number leaving it.

```bash
root@swe:/# grep -o "ttl [0-9]*" /tmp/sf3.txt | sort | uniq -c
  23022 ttl 61
  23022 ttl 62
```

**Overlay link capture (Classifier B → SFF D, tunnel 101).** The overlay packet has the format `Eth / MPLS / NSH / Eth / IPv4 / TCP`:

```bash
root@swb:/# tcpdump -i eth2 -n -e -c 1 -xx mpls
18:37:19.762296 00:00:00:00:0b:02 > 00:00:00:00:0d:00, ethertype MPLS unicast (0x8847), length 100: MPLS (label 101, tc 0, [S], ttl 64)
0x0000:  0000 0000 0d00 0000 0000 0b02 8847 0006
0x0010:  5140 0fc2 0203 0000 0104 0000 0000 0b00
0x0020:  0000 0000 0a00 0800 4500 003c f59b 4000
0x0030:  3f06 2e1f 0a00 0101 0a00 0301 cf26 1451
0x0040:  648d 96f7 0000 0000 a002 faf0 1722 0000
0x0050:  0204 05b4 0402 080a d5e1 690d 0000 0000
0x0060:  0103 0307
```

| Bytes | Field |
|---|---|
| `0000 0000 0d00` / `0000 0000 0b02` / `8847` | Outer Ethernet: dst SWD eth0, src SWB eth2, MPLS |
| `0006 5140` | MPLS: label 101, bottom of stack, TTL 64 |
| `0fc2 0203` | NSH base header: ver 0, TTL 63, length 2, MD Type 2, next protocol 3 (Ethernet) |
| `0000 0104` | NSH service path header: SPI 1, SI 4 |
| `0000 0000 0b00` / `0000 0000 0a00` / `0800` | Inner Ethernet (original frame from SWA) |
| `4500 003c f59b 4000 3f06 ...` | Inner IPv4: id 62875, TTL 63, TCP, 10.0.1.1 → 10.0.3.1 |
| `cf26 1451 ...` | Inner TCP: port 53030 → 5201, SYN, MSS 1460 |

The frame is 100 bytes: 14 (outer Eth) + 4 (MPLS) + 8 (NSH) + 14 (inner Eth) + 60 (IPv4/TCP SYN).

### Chain 2: H2 -> H4 (Passes through SF3 only)

```bash
# Executed on H2
root@h2:/# iperf3 -c 10.0.4.1 -M 1434 -t 10

<<< PASTE THE REAL iperf3 OUTPUT OF TEST B HERE >>>
```

Verification results (test B):

* SF3 link (SWE eth2): the same number of packets enters the SF with TTL 63 and leaves it with TTL 62; packets arrive at H4 with TTL 62, i.e. after exactly one SF.
* SFF D sees no packet of the H2 → H4 flow, so SF1 and SF2 are not traversed.
* The overlay link B → C carries MPLS label 201 with NSH SPI 2, SI 2 (`0000 0202`).

```bash
<<< PASTE THE SF3 SYN CAPTURE AND THE B -> C OVERLAY DUMP OF TEST B HERE >>>
```

---

## 6. Return Traffic Analysis

According to the project specifications, traffic returning from the destination host back to the source host must not traverse the Service Function Chains and must follow the shortest IPv4 path.

The classifier policies match on the source address of H1/H2, so packets sent by H3/H4 never match and are forwarded by the `ipv4_lpm` tables of every node. The static routes were computed so that return traffic follows a shortest path (4 IPv4 hops):

```
H3 -> H1:  SWH -> SWF -> SWB -> SWA
H4 -> H2:  SWH -> SWG -> SWC -> SWA
```

**ACKs of the chain 1 iperf3 flow.** During the chain 1 test, no packet from H3 was captured on SFF D or SFF E (on any interface). The SYN-ACK and ACKs of the same connection travel as plain IPv4 on the link SWF → SWB:

```bash
root@swf:/# tcpdump -i eth0 -n -e -c 5 'src host 10.0.3.1'
18:37:19.776057 00:00:00:00:0f:03 > 00:00:00:00:0b:03, ethertype IPv4 (0x0800), length 74: 10.0.3.1.5201 > 10.0.1.1.53030: Flags [S.], seq 556860759, ack 1687000824, win 65160, options [mss 1460,sackOK,TS val 2121789510 ecr 3588319501,nop,wscale 7], length 0
18:37:19.784113 00:00:00:00:0f:03 > 00:00:00:00:0b:03, ethertype IPv4 (0x0800), length 66: 10.0.3.1.5201 > 10.0.1.1.53030: Flags [.], ack 38, win 509, options [nop,nop,TS val 2121789519 ecr 3588319519], length 0
18:37:19.784201 00:00:00:00:0f:03 > 00:00:00:00:0b:03, ethertype IPv4 (0x0800), length 67: 10.0.3.1.5201 > 10.0.1.1.53030: Flags [P.], seq 1:2, ack 38, win 509, options [nop,nop,TS val 2121789519 ecr 3588319519], length 1
18:37:19.791012 00:00:00:00:0f:03 > 00:00:00:00:0b:03, ethertype IPv4 (0x0800), length 66: 10.0.3.1.5201 > 10.0.1.1.53030: Flags [.], ack 177, win 508, options [nop,nop,TS val 2121789525 ecr 3588319527], length 0
18:37:19.791085 00:00:00:00:0f:03 > 00:00:00:00:0b:03, ethertype IPv4 (0x0800), length 67: 10.0.3.1.5201 > 10.0.1.1.53030: Flags [P.], seq 2:3, ack 177, win 508, options [nop,nop,TS val 2121789525 ecr 3588319527], length 1
```

The source MAC is `0f:03` rather than `0f:00` because `ipv4_forward` reuses the previous destination MAC (the ingress interface) as the new source MAC; this does not affect forwarding.

**Reverse-direction iperf3.** iperf3 was also run in the reverse direction (H3 → H1 and H4 → H2). No IPv4 or MPLS packet was observed on SFF D or SFF E, and all packets arrived at H1 and H2 with TTL 60 (4 IPv4 hops), i.e. along the shortest path.

```bash
# Executed on H3 (server on H1)
root@h3:/# iperf3 -c 10.0.1.1 -M 1434 -t 10

<<< PASTE THE REAL iperf3 OUTPUT OF TEST E HERE >>>

# Executed on H4 (server on H2)
root@h4:/# iperf3 -c 10.0.2.1 -M 1434 -t 10

<<< PASTE THE REAL iperf3 OUTPUT OF TEST E HERE >>>

# TTL of the packets received by H1 and H2
root@h1:/# grep -o "ttl [0-9]*" /tmp/inv.txt | sort | uniq -c
<<< PASTE OUTPUT HERE >>>
root@h2:/# grep -o "ttl [0-9]*" /tmp/inv.txt | sort | uniq -c
<<< PASTE OUTPUT HERE >>>
```