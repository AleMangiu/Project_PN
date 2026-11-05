#include <core.p4>
#include <v1model.p4>

/*
 * One program, three roles (selected only by the table entries in commands.txt):
 *   - MPLS transit (SWC, SWF, SWG): forwards on the MPLS label, never looks at NSH.
 *   - SFF + proxy   (SWD, SWE):     terminates the tunnel, decides on (SPI, SI),
 *                                   strips/restores NSH around non-NSH-aware SFs.
 *   - Egress        (SWH):          terminates the tunnel and, at chain end,
 *                                   delivers the plain Eth/IPv4/TCP packet.
 * All nodes also do plain IPv4 LPM forwarding for return / non-SFC traffic.
 */

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_MPLS = 0x8847;
const bit<8>  NSH_NEXT_ETH = 3;

/* ============================ HEADERS ============================ */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

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

struct metadata {
    bit<1> is_sfc;
}

/* ============================ PARSER ============================ */
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

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

/* ============================ INGRESS ============================ */
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {

    action drop() {
        mark_to_drop(sm);
    }

    /* ---------- 1. Plain IPv4 routing (return traffic, shortest path) ---------- */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        sm.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { ipv4_forward; drop; }
        size = 1024;
        default_action = drop();
    }

    /* ---------- 2. MPLS tunnel layer ---------- */

    // Transit LSR: the label identifies the tunnel, the packet keeps its label
    // (no swap needed because labels are unique per tunnel). NSH is not touched.
    action mpls_forward(macAddr_t srcMac, macAddr_t dstMac, egressSpec_t port) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = dstMac;
        hdr.mpls.ttl = hdr.mpls.ttl - 1;
        sm.egress_spec = port;
    }

    // Tail end of the tunnel: this node is the overlay element the tunnel points to.
    // The actual pop happens in the SFF action selected by (SPI, SI).
    action mpls_terminate() { }

    table mpls_tbl {
        key = { hdr.mpls.label : exact; }
        actions = { mpls_forward; mpls_terminate; drop; }
        size = 256;
        default_action = drop();
    }

    /* ---------- 3. SFF: decision on (SPI, SI) ---------- */

    // Proxy decapsulation: pop MPLS + NSH, send plain Eth/IPv4/TCP to the local SF.
    // Also used at the egress node (SWH) to deliver the packet at chain completion.
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

    // Forward to another SFF through a new MPLS tunnel (NSH kept as is).
    // Not needed by the two chains of the assignment, kept for completeness.
    action sff_forward_tunnel(bit<20> mpls_label, macAddr_t srcMac, macAddr_t dstMac, egressSpec_t port) {
        hdr.mpls.label = mpls_label;
        hdr.mpls.ttl = 64;
        hdr.nsh.ttl = hdr.nsh.ttl - 1;
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = dstMac;
        sm.egress_spec = port;
    }

    table sff_exact {
        key = { hdr.nsh.spi_si : exact; }
        actions = { sff_proxy_decap; sff_forward_tunnel; drop; }
        size = 1024;
        default_action = drop();   // invalid / unsupported (SPI, SI)
    }

    /* ---------- 4. SFF proxy: packet coming back from a local SF ---------- */

    // Restore the NSH context (SI already decremented in the table entry)
    // and push the MPLS label of the tunnel toward the next overlay element.
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
        hdr.mpls.tc  = 0;
        hdr.mpls.bos = 1;
        hdr.mpls.ttl = 64;

        hdr.nsh.setValid();
        hdr.nsh.ver = 0;
        hdr.nsh.o = 0;
        hdr.nsh.c_u = 0;
        hdr.nsh.ttl = 63;
        hdr.nsh.length = 2;
        hdr.nsh.u_flags = 0;
        hdr.nsh.md_type = 2;
        hdr.nsh.next_proto = NSH_NEXT_ETH;
        hdr.nsh.spi_si = new_spi_si;

        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        sm.egress_spec = port;
    }

    // The SF is not NSH-aware: the context is reconstructed from
    // (port the SF is attached to, flow addresses).
    table sf_return {
        key = {
            sm.ingress_port : exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = { sff_proxy_encap; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

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
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) { apply { } }

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/* ============================ DEPARSER ============================ */
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mpls);
        packet.emit(hdr.nsh);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
