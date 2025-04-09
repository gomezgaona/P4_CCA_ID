/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> TYPE_REPORT = 0xFF;
const bit<16> TYPE_CUSTOM = 2001;
const bit<16> TYPE_CUSTOM2 = 4321;


typedef bit<8>  inference_result_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
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

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    report_h     report;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<48> interarrival_value;
    bit<48> ingress_timestamp;
    bit<32> flow_id;
    bit<32> data_sent;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
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
            TYPE_TCP: parse_tcp;
            TYPE_REPORT: parse_report;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort){
            TYPE_CUSTOM: parse_report;
            TYPE_CUSTOM2: parse_report;
            default: accept;
        }
    }

    state parse_report {
        packet.extract(hdr.report);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/ 

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    // Registros de estado
    register<bit<48>>(65535) last_timestamp_reg;
    register<bit<32>>(1048576) bytes_transmitted;
    register<bit<32>>(1048576) sending_rate_prev_time;


    action send_using_port(PortId_t port){
	ig_tm_md.ucast_egress_port = port;   
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    // Acción para calcular el interarrival time
    action get_interarrival_time() {
        bit<48> last_timestamp;
        bit<48> current_timestamp;
        bit<16> flow_id;

        // Calcular el hash para el flujo
        hash(
            flow_id, 
            HashAlgorithm.crc16, 
            (bit<1>)0, 
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port
            }, 
            (bit<16>) 65535
        );

        last_timestamp_reg.read(last_timestamp, (bit<32>)flow_id);
        current_timestamp = ig_intr_md.ingress_global_timestamp;

        // Calcular el tiempo de interarrival
        if (last_timestamp != 0) {
            meta.interarrival_value = current_timestamp - last_timestamp;
        } else {
            meta.interarrival_value = 0;
        }
        last_timestamp_reg.write((bit<32>)flow_id, current_timestamp);
    }

    // Acción para calcular el ID del flujo
    action compute_flow_id() {
        hash(
            meta.flow_id, 
            HashAlgorithm.crc16, 
            (bit<1>)0, 
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                hdr.tcp.src_port,
                hdr.tcp.dst_port
            }, 
            (bit<16>) 65535
        );
    }

    // Tabla de reenvío
    table forwarding {
        key = { 
            ig_intr_md.ingress_port : exact; 
        }
        actions = {
            send_using_port; 
            drop;
        }
    }

    // Acción para actualizar la tasa de envío
    action update_sending_rate() {
        bit<32> bytes_transmitted_flow;
        bit<32> prev_time;
        bit<32> current_time;
        bit<32> time_diff;
        bit<32> data_sent;

        bytes_transmitted.read(bytes_transmitted_flow, (bit<32>)meta.flow_id);
        bytes_transmitted_flow += (bit<32>)hdr.ipv4.total_len;
        bytes_transmitted.write((bit<32>)meta.flow_id, bytes_transmitted_flow);

        sending_rate_prev_time.read(prev_time, (bit<32>)meta.flow_id);
        current_time = (bit<32>)ig_intr_md.ingress_global_timestamp;
        time_diff = current_time - prev_time;

        if (time_diff > 0) {
            data_sent = bytes_transmitted_flow * 8;
            meta.data_sent = data_sent;
        }

        sending_rate_prev_time.write((bit<32>)meta.flow_id, current_time);
    }

    apply {
        // Procesar si el paquete tiene cabecera IPv4
        if (hdr.ipv4.isValid()) {
            compute_flow_id();
            forwarding.apply();
            get_interarrival_time();
            meta.ingress_timestamp = ig_intr_md.ingress_global_timestamp;
            update_sending_rate();
        }
    }
}
    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        if (hdr.ipv4.isValid()) {
            pkt.emit(hdr.ipv4);
        }
        if (hdr.tcp.isValid()) {
            pkt.emit(hdr.tcp);
        }
        if (hdr.report.isValid()) {
            pkt.emit(hdr.report);
        }
    }
}



/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h ethernet;
    ipv4_h     ipv4;
    tcp_h      tcp;
    report_h   report;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<48> ingress_timestamp;
    bit<48> interarrival_value;
    bit<32> data_sent;
    bit<8>  cca;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    action add_sw_stats(switch_ID_t ID) {
        hdr.report.setValid();
        hdr.report.ingress_timestamp    = meta.ingress_timestamp;
        hdr.report.egress_timestamp     = eg_intr_md.global_tstamp;
        hdr.report.q_delay              = eg_intr_md.global_tstamp - meta.ingress_timestamp;
        hdr.report.q_depth              = (bit<24>)eg_intr_md.enq_qdepth;
        hdr.report.switch_ID            = ID;
        hdr.report.interarrival_value   = meta.interarrival_value;
        hdr.report.data_sent            = meta.data_sent;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 22;
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
        size = NB_ENTRIES;
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

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.report);
    }
}



/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;