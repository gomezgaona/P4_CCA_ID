/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>


Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32;

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> TYPE_REPORT = 0xFF;
const bit<16> TYPE_CUSTOM = 2001;
const bit<16> TYPE_CUSTOM2 = 4321;


typedef bit<8>  inference_result_t;
typedef bit<8> switch_ID_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<3>  ecn;
    bit<5>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header report_h {
    bit<8>  switch_ID;
    bit<48> ingress_timestamp;
    bit<48> egress_timestamp;
    bit<48> q_delay;
    bit<24> q_depth;
    bit<32> data_sent;
    bit<48> interarrival_value;
    inference_result_t cca;
    bit<8> cca_vote_bbr;
    bit<8> cca_vote_cubic;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    report_h     report;
}

struct my_ingress_metadata_t {
    bit<48> interarrival_value;
    bit<48> ingress_timestamp;
    bit<32> flow_id;
    bit<32> data_sent;
}

parser IngressParser(packet_in pkt,
    out my_ingress_headers_t hdr,
    out my_ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_REPORT: parse_report;
            default: parse_tcp;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
            TYPE_CUSTOM: parse_report;
            TYPE_CUSTOM2: parse_report;
            default: accept;
        }
    }

    state parse_report {
        pkt.extract(hdr.report);
        transition accept;
    }
}

control Ingress(
    /* User */
    inout my_ingress_headers_t hdr,
    inout my_ingress_metadata_t meta,
    /* Intrinsic */
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {

    // LAST_TIMESTAMP_REG
    Register<bit<32>, bit<32>>(65535) last_timestamp_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(last_timestamp_reg) update_last_timestamp = {
        void apply(inout bit<32> reg_data, out bit<32> result) {
            result = reg_data;
            reg_data = (bit<32>) ig_intr_md.ingress_mac_tstamp;
        }
    };

    // BYTES_TRANSMITTED
    Register<bit<32>, bit<32>>(65535) bytes_transmitted;
    RegisterAction<bit<32>, bit<32>, bit<32>>(bytes_transmitted) update_bytes_transmitted = {
        void apply(inout bit<32> reg_data, out bit<32> result) {
            result = reg_data;
            reg_data = reg_data + (bit<32>) hdr.ipv4.total_len;
        }
    };

    // SENDING_RATE_PREV_TIME
    Register<bit<32>, bit<32>>(65535) sending_rate_prev_time;
    RegisterAction<bit<32>, bit<32>, bit<32>>(sending_rate_prev_time) update_prev_time = {
        void apply(inout bit<32> reg_data, out bit<32> result) {
            result = reg_data;
            reg_data = (bit<32>) ig_intr_md.ingress_mac_tstamp;
        }
    };

    action send_using_port(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action get_interarrival_time() {
        bit<32> last_timestamp;
        bit<48> current_timestamp;

        last_timestamp = update_last_timestamp.execute(meta.flow_id);
        current_timestamp = ig_intr_md.ingress_mac_tstamp;

        if (last_timestamp != 0) {
            meta.interarrival_value = current_timestamp - (bit<48>)last_timestamp;
        } else {
            meta.interarrival_value = 0;
        }
    }

    action compute_flow_id() {
        meta.flow_id = crc32.get({hdr.ipv4.src_addr,
                                  hdr.ipv4.dst_addr,
                                  hdr.ipv4.protocol,
                                  hdr.tcp.srcPort,
                                  hdr.tcp.dstPort});
    }

    table forwarding {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            send_using_port;
            drop;
        }
        size = 1024;
        const default_action = drop();
    }

    action update_sending_rate() {
        bit<32> bytes;
        bit<32> prev_time;
        bit<32> current_time;
        bit<32> time_diff;

        bytes = update_bytes_transmitted.execute(meta.flow_id);
        prev_time = update_prev_time.execute(meta.flow_id);
        current_time = (bit<32>) ig_intr_md.ingress_mac_tstamp;
        time_diff = current_time - prev_time;

        if (time_diff > 0) {
            meta.data_sent = bytes * 8;
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            compute_flow_id();
            forwarding.apply();
            get_interarrival_time();
            meta.ingress_timestamp = ig_intr_md.ingress_mac_tstamp;
            update_sending_rate();
        }
    }
}

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t hdr,
    in my_ingress_metadata_t meta,
    /* Intrinsic */
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.report);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

struct my_egress_headers_t {
    ethernet_h ethernet;
    ipv4_h     ipv4;
    tcp_h      tcp;
    report_h   report;
}

struct my_egress_metadata_t {
    bit<48> ingress_timestamp;
    bit<48> interarrival_value;
    bit<32> data_sent;
    bit<8>  cca;
}

parser EgressParser(packet_in pkt,
    /* User */
    out my_egress_headers_t hdr,
    out my_egress_metadata_t meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_REPORT: parse_report;
            default: parse_tcp;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
            TYPE_CUSTOM: parse_report;
            TYPE_CUSTOM2: parse_report;
            default: accept;
        }
    }

    state parse_report {
        pkt.extract(hdr.report);
        transition accept;
    }
}

control Egress(
    inout my_egress_headers_t hdr,
    inout my_egress_metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    action add_sw_stats(switch_ID_t ID) {
        hdr.report.setValid();
        hdr.report.ingress_timestamp = meta.ingress_timestamp;
        hdr.report.egress_timestamp  = eg_prsr_md.global_tstamp;
        hdr.report.q_delay           = eg_prsr_md.global_tstamp - meta.ingress_timestamp;
        hdr.report.q_depth           = (bit<24>)eg_intr_md.enq_qdepth;
        hdr.report.switch_ID         = ID;
        hdr.report.interarrival_value = meta.interarrival_value;
        hdr.report.data_sent         = meta.data_sent;

        hdr.ipv4.total_len = hdr.ipv4.total_len + 22;
    }

    action set_result(inference_result_t val) {
        meta.cca = val;
    }

    table add_queue_statistics {
        key = {
            hdr.tcp.dstPort: exact;
        }
        actions = {
            add_sw_stats;
            NoAction;
        }
        size = 32;
        default_action = NoAction;
    }

    table decision_tree {
        key = {
            hdr.report.q_delay            : range;
            hdr.report.q_depth            : range;
            hdr.report.interarrival_value : range;
        }
        actions = {
            set_result;
            NoAction;
        }
        size = 8192;
        default_action = NoAction;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            add_queue_statistics.apply();
            decision_tree.apply();
            hdr.report.cca = meta.cca;
        }
    }
}

control EgressDeparser(packet_out pkt,
    inout my_egress_headers_t hdr,
    in my_egress_metadata_t meta,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.report);
    }
}

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;