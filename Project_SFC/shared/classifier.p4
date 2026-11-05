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

struct metadata {
    bit<1> is_sfc;
}

/* ============================ PARSER ============================ */
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
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
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

/* ============================ INGRESS ============================ */
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    
    action drop() {
        mark_to_drop(sm);
    }

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

    // Match on 4-tuple. Removed srcPort to allow iperf3 random client ports
    table classify {
        key = { 
            hdr.ipv4.srcAddr: exact; 
            hdr.ipv4.dstAddr: exact; 
            hdr.ipv4.protocol: exact; 
            hdr.tcp.dstPort: exact; 
        }
        actions = {
            encap_sfc;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    apply {
        meta.is_sfc = 0;
        
        if (hdr.ipv4.isValid()) {
            // Apply SFC rules only to TCP traffic
            if (hdr.tcp.isValid()) {
                classify.apply();
            }
            
            // Forward everything else normally (Ping, Return Traffic, etc.)
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
        // Emit in correct SFC overlay order
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mpls);
        packet.emit(hdr.nsh);
        
        // Inner headers
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        
        // Standard headers (for non-SFC traffic)
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