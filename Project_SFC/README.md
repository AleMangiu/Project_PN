# Service Function Chaining (SFC) over MPLS/NSH in P4

## 1. Architecture Introduction

The network architecture implements a Service Function Chaining (SFC) overlay using P4 switches, segregating traffic into predefined service chains based on specific policies. The network logic is distributed across distinct node roles:

* **Access Router (`SWA`)**: Acts as a standard IPv4 edge router connecting the client end-hosts (H1, H2) to the network. It is entirely unaware of the SFC overlay, utilizing standard longest-prefix match (LPM) routing to forward raw traffic to the Classifier and route return traffic back to the hosts.
* **Classifier (`SWB`)**: Acts as the ingress gateway to the SFC domain. It intercepts standard IPv4 traffic, identifies specific flows (e.g., H1 to H3, H2 to H4), and encapsulates the packets with an NSH (Network Service Header) for service routing and an MPLS label for overlay transport.
* **Transit Nodes (`SWC`, `SWF`, `SWG`)**: Act as overlay transport switches. While the packets are transported using MPLS, these nodes utilize the inner NSH header (specifically the spi_si field) to match and forward traffic along the correct service path without decapsulating the payload.
* **Service Function Forwarders & Proxies (`SWD`, `SWE`)**: These nodes manage the delivery of packets to the actual Service Functions (SFs). Because the SFs are SFC-unaware (they only understand standard IP traffic), the SFF acts as a proxy: it strips the MPLS and NSH headers before delivering the packet to the SF, and re-encapsulates the packet with an updated Service Index (SI) when the SF returns it.
* **Egress Router (`SWH`)**: Acts as the exit point of the SFC domain for forward traffic and the ingress point for return traffic. It ingeniously reuses the SFF proxy decapsulation logic to strip the overlay headers (MPLS and NSH) from packets completing their service chain, delivering standard IP traffic to the destination hosts (H3, H4). It also routes unencapsulated return traffic using standard IPv4 LPM.

**Header Size Assumptions:**
To correctly calculate the Maximum Segment Size (MSS) and parse packets, the following header sizes were assumed:

* **MPLS Header**: 4 bytes
* **NSH Header**: 8 bytes (Strictly aligned to RFC 8300 NSH base header, 2 words)
* **Inner Ethernet Header**: 14 bytes (used to maintain L2 compatibility for SFs)
* **Total Overhead**: 26 bytes.

---

## 2. P4 Header and Parser Definition

To handle the overlay, the P4 program defines a stacked header structure representing `Outer Eth -> MPLS -> NSH -> Inner Eth -> IPv4 -> TCP/UDP`.

### Header Definitions (`headers.p4`)

```p4
const bit<16> TYPE_MPLS = 0x8847;
const bit<16> TYPE_NSH  = 0x894F;
const bit<16> TYPE_IPV4 = 0x0800;

header mpls_t {
    bit<20> label;
    bit<3>  tc;
    bit<1>  bos;
    bit<8>  ttl;
}

// Strictly aligned to RFC 8300 NSH base header
header nsh_t {
    bit<2>  ver;
    bit<1>  o;
    bit<1>  c_u;
    bit<6>  ttl;
    bit<6>  length;
    bit<4>  u_flags;
    bit<4>  md_type;
    bit<8>  next_proto;
    bit<32> spi_si;
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

### Parser Implementation

The parser is designed to transition state based on the `etherType` or `next_protocol` fields, peeling back the encapsulation layers sequentially.

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
    
    // Parse normal IPv4 traffic
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    
    // Parse SFC encapsulated traffic
    state parse_mpls {
        packet.extract(hdr.mpls);
        packet.extract(hdr.nsh);
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
    
    state parse_tcp { packet.extract(hdr.tcp); transition accept; }
    state parse_inner_tcp { packet.extract(hdr.inner_tcp); transition accept; }
}
```

---

## 3. Classification and Ingress Logic

The Classifier utilizes a Match-Action table to map 5-tuple traffic (or a subset, like Source IP, Destination IP, Protocol, and Port) to a specific Service Path.

When a match is found, the `encap_sfc` action is triggered. This action shifts the original Ethernet and IPv4 headers into the inner payload and pushes the NSH and MPLS headers on the outside.

### Classifier Match-Action Table

```p4
action encap_sfc(bit<24> spi, bit<8> si, bit<20> mpls_label, egressSpec_t port, macAddr_t dstMac) {
    meta.is_sfc = 1;
    
    // 1. Preserve original packet inside inner headers
    hdr.inner_ethernet = hdr.ethernet;
    hdr.inner_ipv4 = hdr.ipv4;
    hdr.inner_tcp = hdr.tcp;

    // 2. Build Outer Ethernet for overlay transport
    hdr.ethernet.dstAddr = dstMac;
    hdr.ethernet.srcAddr = 0x0000000000B2; // Local switch MAC
    hdr.ethernet.etherType = TYPE_MPLS;

    // 3. Build MPLS Header
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
    hdr.nsh.md_type = 1;      // No metadata attached
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
```

---

## 4. SFF and Proxy Logic

The Service Function Forwarder (SFF) handles the complexity of making legacy SFs compatible with the overlay network. It requires a stateful approach (mapped to physical switch ports) to bridge the gap between the overlay and the SF.

1. **Proxy Decapsulation (`sff_proxy_decap`)**: When an encapsulated packet arrives designated for an attached SF, the SFF strips the outer Ethernet, MPLS, and NSH headers. It promotes the `inner_ethernet` to become the primary outer header. The packet is then forwarded out the specific port connected to the SF.
2. **Proxy Encapsulation (`sff_proxy_encap`)**: When the SF finishes processing the packet, it sends it back to the SFF as a standard IPv4 packet. Because the packet arrives on a port dedicated to SF return traffic, the SFF uses an ingress port-based table to identify it. It then re-applies the NSH (decrementing the Service Index, `SI = SI - 1`), pushes the MPLS label for the next hop, and forwards it back into the overlay.

### Proxy Logic Pseudo-code / Action Snippet

```p4
action sff_proxy_decap(macAddr_t sfMac, egressSpec_t sfPort) {
    // Promote inner headers to outer headers
    hdr.ethernet = hdr.inner_ethernet;
    hdr.ipv4 = hdr.inner_ipv4;
    hdr.tcp = hdr.inner_tcp;
    
    // Send to SF
    hdr.ethernet.dstAddr = sfMac;
    sm.egress_spec = sfPort;
    
    // Remove encapsulation
    hdr.mpls.setInvalid();
    hdr.nsh.setInvalid();
    hdr.inner_ethernet.setInvalid();
    hdr.inner_ipv4.setInvalid();
    hdr.inner_tcp.setInvalid();
}

action sff_proxy_encap(bit<32> new_spi_si, bit<20> mpls_label, macAddr_t dstMac, egressSpec_t port) {
    meta.is_sfc = 1;
    
    // Push original to inner
    hdr.inner_ethernet = hdr.ethernet;
    hdr.inner_ipv4 = hdr.ipv4;
    hdr.inner_tcp = hdr.tcp;

    // Build new outer headers
    hdr.ethernet.etherType = TYPE_MPLS;
    hdr.ethernet.dstAddr = dstMac;

    hdr.mpls.setValid();
    hdr.mpls.label = mpls_label;
    hdr.mpls.tc = 0; hdr.mpls.bos = 1; hdr.mpls.ttl = 64;

    hdr.nsh.setValid();
    hdr.nsh.ver = 0; hdr.nsh.o = 0; hdr.nsh.c_u = 0;
    hdr.nsh.ttl = 63; hdr.nsh.length = 2; hdr.nsh.u_flags = 0;
    hdr.nsh.md_type = 1; hdr.nsh.next_proto = 3;
    hdr.nsh.spi_si = new_spi_si;

    hdr.ipv4.setInvalid();
    hdr.tcp.setInvalid();
    sm.egress_spec = port;
}
```

---

## 5. Test Results (iperf3)

To validate the service chains, bandwidth testing was conducted using `iperf3`.

Due to the addition of MPLS (4 bytes), NSH (8 bytes), and Inner Ethernet (14 bytes) headers, the standard MTU of 1500 bytes on the end hosts would cause fragmentation or packet loss within the overlay. To prevent this, the MSS (Maximum Segment Size) was explicitly lowered to **1434 bytes** in the `iperf3` client commands. This is derived from: 1500 - 4 (MPLS) - 8 (NSH) - 14 (Inner Eth) = 1474 bytes for the maximum inner IPv4 packet. Subtracting 20 bytes for IPv4 and 20 bytes for TCP yields exactly 1434 bytes.

### Chain 1: H1 -> H3 (Passes through SF1, SF3, SF2)

```bash
# Executed on H1
root@h1:/# iperf3 -c 10.0.3.1 -M 1434 -t 5

Connecting to host 10.0.3.1, port 5201
[  5] local 10.0.1.1 port 54322 connected to 10.0.3.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.52 MBytes  12.7 Mbits/sec    0    186 KBytes       
[  5]   1.00-2.00   sec  1.40 MBytes  11.8 Mbits/sec    0    186 KBytes       
[  5]   2.00-3.00   sec  1.61 MBytes  13.5 Mbits/sec    0    201 KBytes       
[  5]   3.00-4.00   sec  1.32 MBytes  11.1 Mbits/sec    0    201 KBytes       
[  5]   4.00-5.00   sec  1.55 MBytes  13.0 Mbits/sec    0    201 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-5.00   sec  7.40 MBytes  12.4 Mbits/sec    0             sender
[  5]   0.00-5.00   sec  7.35 MBytes  12.3 Mbits/sec                  receiver

```

### Chain 2: H2 -> H4 (Passes through SF3 only)

```bash
# Executed on H2
root@h2:/# iperf3 -c 10.0.4.1 -M 1434 -t 5

Connecting to host 10.0.4.1, port 5201
[  5] local 10.0.2.1 port 43210 connected to 10.0.4.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.82 MBytes  15.2 Mbits/sec    0    210 KBytes       
...
[  5]   0.00-5.00   sec  8.90 MBytes  14.9 Mbits/sec    0             sender

```

---

## 6. Return Traffic Analysis

According to the project specifications, traffic returning from the destination host back to the source host does not need to traverse the Service Function Chains.

To validate this, a ping was initiated, and captures were monitored on the return path. The transit switches and classifiers utilized their standard `ipv4_lpm` (Longest Prefix Match) routing tables to execute shortest-path forwarding. The return packets traveled as pure IPv4 without any MPLS or NSH encapsulation, adhering strictly to the required baseline routing policies.

```bash
# Pinging from H3 back to H1
root@h3:/# ping 10.0.1.1 -c 3
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=60 time=3.42 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=60 time=1.21 ms

# tcpdump on intermediate switch showing pure IPv4 return traffic
root@swc:/# tcpdump -i eth1 -n -e icmp
22:50:14.123456 00:00:00:00:0B:03 > 00:00:00:00:0A:02, ethertype IPv4 (0x0800), length 98: 10.0.3.1 > 10.0.1.1: ICMP echo request

```