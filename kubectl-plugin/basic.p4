/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

header udp_t {
    bit<16>  srcPort;
    bit<16>  dstPort;
    bit<16>  length;
    bit<16>  checksum;
}

header info_t{
    bit<16>  port;
    bit<16>  replicas;
}

#define MAX_IPV4_ADDRESSES  10

header ips_t{
    bit<32>  ipAddress;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t    udp;
    info_t   info;
    ips_t[MAX_IPV4_ADDRESSES]   ips;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            17: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort){
            7777: parse_info;
            default: accept;
        }
    }

    state parse_info{
        packet.extract(hdr.info);
        verify(hdr.info.replicas <= 10);
        verify(hdr.info.replicas > 0);
        number_replicas_remaining_to_parse = hdr.info.replicas;
        transition select(hdr.info.replicas){
            1: parse_ips;
            2: parse_ips;
            3: parse_ips;
            4: parse_ips;
            5: parse_ips;
            6: parse_ips;
            7: parse_ips;
            8: parse_ips;
            9: parse_ips;
            10: parse_ips;
            default: accept;
        }
    }

    state parse_ips{
        packet.extract(hdr.ips.next);
        number_replicas_remaining_to_parse = number_replicas_remaining_to_parse - 1;
        transition select(number_replicas_remaining_to_parse){
            0: accept;
            default: parse_ips;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
register<bit<32>>(MAX_IPV4_ADDRESSES) ip_addresses;
register<bit<16>>(1) node_port;

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.info.isValid()) {
            node_port.write(0, hdr.info.port);
            if (hdr.info.replicas == 1){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
            }
            if (hdr.info.replicas == 2){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
            }
            if (hdr.info.replicas == 3){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
            }
            if (hdr.info.replicas == 4){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
                ip_addresses.write(3, hdr.ips[3].ipAddress);
            }
            if (hdr.info.replicas == 5){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
                ip_addresses.write(3, hdr.ips[3].ipAddress);
                ip_addresses.write(4, hdr.ips[4].ipAddress);
            }
            if (hdr.info.replicas == 6){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
                ip_addresses.write(3, hdr.ips[3].ipAddress);
                ip_addresses.write(4, hdr.ips[4].ipAddress);
                ip_addresses.write(5, hdr.ips[5].ipAddress);
            }
            if (hdr.info.replicas == 7){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
                ip_addresses.write(3, hdr.ips[3].ipAddress);
                ip_addresses.write(4, hdr.ips[4].ipAddress);
                ip_addresses.write(5, hdr.ips[5].ipAddress);
                ip_addresses.write(6, hdr.ips[6].ipAddress);
            }
            if (hdr.info.replicas == 8){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
                ip_addresses.write(3, hdr.ips[3].ipAddress);
                ip_addresses.write(4, hdr.ips[4].ipAddress);
                ip_addresses.write(5, hdr.ips[5].ipAddress);
                ip_addresses.write(6, hdr.ips[6].ipAddress);
                ip_addresses.write(7, hdr.ips[7].ipAddress);
            }
            if (hdr.info.replicas == 9){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
                ip_addresses.write(3, hdr.ips[3].ipAddress);
                ip_addresses.write(4, hdr.ips[4].ipAddress);
                ip_addresses.write(5, hdr.ips[5].ipAddress);
                ip_addresses.write(6, hdr.ips[6].ipAddress);
                ip_addresses.write(7, hdr.ips[7].ipAddress);
                ip_addresses.write(8, hdr.ips[8].ipAddress);
            }
            if (hdr.info.replicas == 10){
                ip_addresses.write(0, hdr.ips[0].ipAddress);
                ip_addresses.write(1, hdr.ips[1].ipAddress);
                ip_addresses.write(2, hdr.ips[2].ipAddress);
                ip_addresses.write(3, hdr.ips[3].ipAddress);
                ip_addresses.write(4, hdr.ips[4].ipAddress);
                ip_addresses.write(5, hdr.ips[5].ipAddress);
                ip_addresses.write(6, hdr.ips[6].ipAddress);
                ip_addresses.write(7, hdr.ips[7].ipAddress);
                ip_addresses.write(8, hdr.ips[8].ipAddress);
                ip_addresses.write(9, hdr.ips[9].ipAddress);
            }
        }
        else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;