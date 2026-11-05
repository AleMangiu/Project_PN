#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_MPLS = 0x8847;

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
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
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

    // 1. NORMAL IPv4 ROUTING
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        sm.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    // 2. SFF FORWARDING (Passes the encapsulated packet to next SFF)
    action sff_forward(macAddr_t srcMac, macAddr_t dstMac, egressSpec_t port) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = dstMac;
        hdr.nsh.ttl = hdr.nsh.ttl - 1;
        sm.egress_spec = port;
    }

    // 3. PROXY DECAPSULATION (Strips NSH and sends to local SF)
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

    table sff_exact {
        key = {
            hdr.nsh.spi_si : exact;
        }
        actions = {
            sff_forward;
            sff_proxy_decap;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    // 4. PROXY RE-ENCAPSULATION (Receives from SF, puts NSH back with updated SI)
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
        hdr.mpls.tc = 0;
        hdr.mpls.bos = 1;
        hdr.mpls.ttl = 64;

        hdr.nsh.setValid();
        hdr.nsh.ver = 0;
        hdr.nsh.o = 0;
        hdr.nsh.c_u = 0;
        hdr.nsh.ttl = 63;
        hdr.nsh.length = 2;
        hdr.nsh.u_flags = 0;
        hdr.nsh.md_type = 1;
        hdr.nsh.next_proto = 3;
        hdr.nsh.spi_si = new_spi_si;

        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        sm.egress_spec = port;
    }

    table sf_return {
        key = {
            sm.ingress_port: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            sff_proxy_encap;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        meta.is_sfc = 0;

        // Condition A: Packet has NSH (Arriving from Classifier or SFF)
        if (hdr.nsh.isValid()) {
            sff_exact.apply();
        }
        // Condition B: Normal IPv4 packet (Could be return traffic from SF or a simple Ping)
        else if (hdr.ipv4.isValid()) {
            // Check if it's returning from a local SF
            sf_return.apply();
            
            // If it wasn't re-encapsulated, it's normal traffic, route via LPM
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
    MyIngress(), MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;