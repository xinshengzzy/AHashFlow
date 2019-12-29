#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/pktgen_headers.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/wred_blackbox.p4>

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/macro.p4"


field_list flow {
    ipv4.srcip;
    ipv4.dstip;
    ipv4.proto;
    export_promotion_meta.srcport;
    export_promotion_meta.dstport;
}

// hash function for main_table_1 and fingerprint generation
field_list_calculation hash_1 {
    input {
        flow;
    }
//    algorithm: crc32;
    algorithm: crc_32c;
    output_width: MAIN_TABLE_IDX_WIDTH;
}

// hash function for main_table_2
field_list_calculation hash_2 {
    input {
        flow;
    }
//    algorithm: crc32_msb;
    algorithm: crc_32d;
    output_width: MAIN_TABLE_IDX_WIDTH;
}

// hash function for main_table_3
field_list_calculation hash_3 {
    input {
        flow;
    }
//    algorithm: crc_32_bzip2;
    algorithm: crc_32q;
    output_width: MAIN_TABLE_IDX_WIDTH;
}

// 1 hash function for ancillary table
field_list_calculation hash_4 {
    input {
        flow;
    }
    algorithm: crc32_msb;
    output_width: A_TABLE_IDX_WIDTH;
}

field_list_calculation digest_hash {
    input {
        flow;
    }
    algorithm: identity;
    output_width: DIGEST_WIDTH;
}

field_list_calculation fingerprint_hash {
    input {
        flow;
    }
    algorithm: crc32;
    output_width: FINGERPRINT_WIDTH;
}

// metadata for measurement program
header_type measurement_meta_t {
    fields {
        digest: 8; // digest for differentiating in ancillary table;
        a_cnt: 8; // temp storage for flow count of ancillary table;
        b_cnt: 8; // temp storage for flow count of B Table;
        flag_min: 32; // subtract flag used for judging negative or not
        flag_max: 32; // subtract flag used for judging negative or not
        flag_active: 8; // subtract flag used for judging negative or not
        fingerprint: 32; // fingerprint for 5-tuple;
        cnt_max: 8; // maximum flow count of all 3 sub tables of main table;
		idx_max: 32; // the index of the bucket corresponding to cnt_max
		m_table_id_max: 4; // which m table the cnt_max is located.
        cnt_min: 32; // minimum flow count of all 3 sub tables of main table;
		idx_min: 32; // the index of the bucket corresponding to cnt_min
		m_table_id_min: 4; // which m table the cnt_min is located
        temp_flow_count: 32; // temp storage for flow count of the current sub table;
        m_table_1_predicate: 4; // output predicate in main sub table 1;
        m_table_2_predicate: 4; // output predicate in main sub table 2;
        m_table_3_predicate: 4; // output predicate in main sub table 3;
		m_table_1_cnt: 32; // when collision occurs, the count of the bucket in table 1 
					   //corresponding to current packet
		m_table_2_cnt: 32; // when collision occurs, the count of the bucket in table 2 
					   //corresponding to current packet
		m_table_3_cnt: 32; // when collision occurs, the count of the bucket in table 3 
					   //corresponding to current packet
		m_table_1_idx: 32; // the index of the bucket corresponding to the current packet 
					   //in m table 1
		m_table_2_idx: 32; // the index of the bucket corresponding to the current packet 
					   //in m table 2
		m_table_3_idx: 32; // the index of the bucket corresponding to the current packet 
					   //in m table 3
		diff1: 32; // m_table_1_cnt - m_table_2_cnt
		diff2: 32; // m_table_1_cnt - m_table_3_cnt
		diff3: 32; // m_table_2_cnt - m_table_3_cnt
    }
}

metadata measurement_meta_t measurement_meta;

field_list resubmit_fields {
	export_promotion_meta.promotion_flag;
}

header_type export_promotion_meta_t {
	fields{
		srcip: 32;
		dstip: 32;
		proto: 8;
		srcport: 16;
		dstport: 16;
		ipv4_totalLen: 16;
		promotion_flag: 1;
		export_flag: 1;
		resubmit_flag: 1;
		m_table_1: 1;
		m_table_2: 1;
		m_table_3: 1;
	}
}
metadata export_promotion_meta_t export_promotion_meta;

action add_promote_header() {
	add_header(promote_header);
	add(ipv4.totalLen, ipv4.totalLen, PROMOTE_HEADER_LEN);
	add(export_promotion_meta.ipv4_totalLen, 
			export_promotion_meta.ipv4_totalLen, PROMOTE_HEADER_LEN);
	modify_field(ipv4.proto, IPV4_PROMOTION);
	modify_field(promote_header.next_header, export_promotion_meta.proto);
}

table add_promote_header_t {
	actions {
		add_promote_header;
	}
	default_action: add_promote_header;
}

action remove_promote_header() {
	remove_header(promote_header);
	add(ipv4.totalLen, ipv4.totalLen, -PROMOTE_HEADER_LEN);
	add(export_promotion_meta.ipv4_totalLen, 
			export_promotion_meta.ipv4_totalLen, -PROMOTE_HEADER_LEN);
	modify_field(ipv4.proto, promote_header.next_header);
}

action rmv_promote_header_config_export_header() {
	remove_promote_header();
	config_export_header(promote_header.srcip, promote_header.dstip,
			promote_header.proto, promote_header.srcport, promote_header.dstport, 
			promote_header.fingerprint);
	modify_field(export_header.m_table_1_idx, 0);
	modify_field(export_header.m_table_2_idx, 0);
	modify_field(export_header.m_table_3_idx, 0);
	modify_field(export_promotion_meta.export_flag, 1);
}

@pragma stage 5
table rmv_promote_header_config_export_header_t {
	actions {
		rmv_promote_header_config_export_header;
	}
	default_action: rmv_promote_header_config_export_header;
}

action export_set_flag_config_header() {
	config_export_header(export_promotion_meta.srcip, export_promotion_meta.dstip,
			export_promotion_meta.proto, export_promotion_meta.srcport,
			export_promotion_meta.dstport, measurement_meta.fingerprint);
	modify_field(export_header.padding, 0x00);
	modify_field(export_header.record_fingerprint, 0x00000000);
	modify_field(export_header.record_cnt, 0x00000000);
	modify_field(export_header.m_table_1_idx, measurement_meta.m_table_1_idx);
	modify_field(export_header.m_table_2_idx, measurement_meta.m_table_2_idx);
	modify_field(export_header.m_table_3_idx, measurement_meta.m_table_3_idx);
	modify_field(export_promotion_meta.export_flag, 1);
}

@pragma stage 5
table export_set_flag_config_header_t {
	actions {
		export_set_flag_config_header;
	}
	default_action: export_set_flag_config_header;
}

////////// for the useage of testing //////////
register cntr1 {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu update_cntr1 {
	reg: cntr1;
	update_lo_1_value: register_lo + 1;
}

action update_cntr1_action() {
	update_cntr1.execute_stateful_alu(0);
}


table update_cntr1_t {
	actions {
		update_cntr1_action;
	}
	default_action: update_cntr1_action;
}

register cntr2 {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu update_cntr2 {
	reg: cntr2;
	update_lo_1_value: register_lo + 1;
}

action update_cntr2_action() {
	update_cntr2.execute_stateful_alu(0);
}

table update_cntr2_t {
	actions {
		update_cntr2_action;
	}
	default_action: update_cntr2_action;
}
register cntr3 {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu update_cntr3 {
	reg: cntr3;
	update_lo_1_value: register_lo + 1;
}

action update_cntr3_action() {
	update_cntr3.execute_stateful_alu(0);
}

table update_cntr3_t {
	actions {
		update_cntr3_action;
	}
	default_action: update_cntr3_action;
}
////////// end the test //////////

action initialize() {
	modify_field(export_promotion_meta.promotion_flag, 0);
	modify_field(export_promotion_meta.export_flag, 0);
	modify_field(export_promotion_meta.resubmit_flag, 0);
	modify_field(export_promotion_meta.m_table_1, 0);
	modify_field(export_promotion_meta.m_table_2, 0);
	modify_field(export_promotion_meta.m_table_3, 0);
}

table initialize_t {
	actions {
		initialize;
	}
	default_action: initialize;
}

action set_egr(egress_spec) {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action nop() {}

@pragma stage 0
table forward {
	reads {
		ig_intr_md.ingress_port: exact;
	}
	actions {
		set_egr; 
		nop;
	}
}

// action for transforming 5-tuple into 32-bit fingerprint;
action generate_fingerprint_action()
{
    modify_field_with_hash_based_offset(measurement_meta.fingerprint, 0, fingerprint_hash, 4294967296);
}

// table for transforming 5-tuple into 32-bit fingerprint;
@pragma stage 0
table generate_fingerprint_t
{
    actions {
        generate_fingerprint_action;
    }
    default_action: generate_fingerprint_action;
}

// action for generating digest which is used for comparing in anciliary table
action calc_digest_action()
{
    modify_field_with_hash_based_offset(measurement_meta.digest, 0,
        digest_hash, 256);
}

// table for generating digest which is used for comparing in anciliary table
@pragma stage 0
table calc_digest_t
{
    actions {
        calc_digest_action;
    }
    default_action: calc_digest_action;
}

action calc_m_table_1_idx()
{
    modify_field_with_hash_based_offset(measurement_meta.m_table_1_idx, 0,
        hash_1, M_TABLE_1_SIZE);
}

@pragma stage 0
table calc_m_table_1_idx_t
{
    actions {
        calc_m_table_1_idx;
    }
    default_action: calc_m_table_1_idx;
}

action calc_m_table_2_idx()
{
    modify_field_with_hash_based_offset(measurement_meta.m_table_2_idx, 0,
        hash_2, M_TABLE_2_SIZE);
}

@pragma stage 0
table calc_m_table_2_idx_t
{
    actions {
        calc_m_table_2_idx;
    }
    default_action: calc_m_table_2_idx;
}

action calc_m_table_3_idx()
{
    modify_field_with_hash_based_offset(measurement_meta.m_table_3_idx, 0,
        hash_3, M_TABLE_3_SIZE);
}

@pragma stage 0
table calc_m_table_3_idx_t
{
    actions {
        calc_m_table_3_idx;
    }
    default_action: calc_m_table_3_idx;
}

// register for storing key of the first main sub table 1
register m_table_1_key
{
    width: 32;
    instance_count: M_TABLE_1_SIZE;
}

blackbox stateful_alu update_m_table_1_key
{
    reg: m_table_1_key;
    condition_lo: register_lo == 0;
    condition_hi: register_lo == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: measurement_meta.fingerprint;

    output_value: predicate;
    output_dst: measurement_meta.m_table_1_predicate;
}

action update_m_table_1_key_action()
{
    update_m_table_1_key.execute_stateful_alu_from_hash(hash_1);
}

@pragma stage 1
table update_m_table_1_key_t
{
    actions {
        update_m_table_1_key_action;
    }
    default_action: update_m_table_1_key_action;
    max_size: 1;
}

blackbox stateful_alu promote_m_table_1_key
{
    reg: m_table_1_key;
    update_lo_1_value: promote_header.fingerprint;
	output_value: register_lo;
	output_dst: export_header.record_fingerprint;	  
}

action promote_m_table_1_key_action()
{
    promote_m_table_1_key.execute_stateful_alu(promote_header.idx);
	modify_field(export_promotion_meta.m_table_1, 1);
}

@pragma stage 1
table promote_m_table_1_key_t
{
	reads {
		promote_header.m_table_id: exact;
	}
    actions {
        promote_m_table_1_key_action;
		nop;
    }
    default_action: nop;
    max_size: 2;
}

register m_table_2_key
{
    width: 32;
    instance_count: M_TABLE_2_SIZE;
}

blackbox stateful_alu update_m_table_2_key
{
    reg: m_table_2_key;
    condition_lo: register_lo == 0;
    condition_hi: register_lo == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: measurement_meta.fingerprint;

    output_value: predicate;
    output_dst: measurement_meta.m_table_2_predicate;
}

action update_m_table_2_key_action()
{
    update_m_table_2_key.execute_stateful_alu_from_hash(hash_2);
}

@pragma stage 2
table update_m_table_2_key_t
{
    reads {
        measurement_meta.m_table_1_predicate: exact;
    }
    actions {
        update_m_table_2_key_action;
        nop;
    }
    default_action: nop;
    max_size: 2;
}

blackbox stateful_alu promote_m_table_2_key
{
    reg: m_table_2_key;
    update_lo_1_value: promote_header.fingerprint;
	output_value: register_lo;
	output_dst: export_header.record_fingerprint;	  
}

action promote_m_table_2_key_action()
{
    promote_m_table_2_key.execute_stateful_alu(promote_header.idx);
	modify_field(export_promotion_meta.m_table_2, 1);
}

@pragma stage 2
table promote_m_table_2_key_t
{
	reads {
		promote_header.m_table_id: exact;
	}
    actions {
        promote_m_table_2_key_action;
		nop;
    }
    default_action: nop;
    max_size: 2;
}

register m_table_3_key
{
    width: 32;
    instance_count: M_TABLE_3_SIZE;
}

blackbox stateful_alu update_m_table_3_key
{
    reg: m_table_3_key;
    condition_lo: register_lo == 0;
    condition_hi: register_lo == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: measurement_meta.fingerprint;

    output_value: predicate;
    output_dst: measurement_meta.m_table_3_predicate;
}

action update_m_table_3_key_action()
{
    update_m_table_3_key.execute_stateful_alu_from_hash(hash_3);
}

@pragma stage 3
table update_m_table_3_key_t
{
    reads {
        measurement_meta.m_table_1_predicate: exact;
        measurement_meta.m_table_2_predicate: exact;
    }
    actions {
        update_m_table_3_key_action;
        nop;
    }
    default_action: nop;
    max_size: 2;
}

blackbox stateful_alu promote_m_table_3_key
{
    reg: m_table_3_key;
    update_lo_1_value: promote_header.fingerprint;
	output_value: register_lo;
	output_dst: export_header.record_fingerprint;	  
}

action promote_m_table_3_key_action()
{
    promote_m_table_3_key.execute_stateful_alu(promote_header.idx);
	modify_field(export_promotion_meta.m_table_3, 1);
}

@pragma stage 3
table promote_m_table_3_key_t
{
	reads {
		promote_header.m_table_id: exact;
	}
    actions {
        promote_m_table_3_key_action;
		nop;
    }
    default_action: nop;
    max_size: 2;
}

// action copy_pkt_to_cpu_action()
// {
//     modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
//     // modify_field(intrinsic_metadata.cos_for_copy_to_cpu, ...);
// }

// table copy_pkt_to_cpu_t_1
// {
//     reads {
//         measurement_meta.main_table_1_predicate: exact;//0010
//     }
//     actions {
//         copy_pkt_to_cpu_action;
//         nop;
//     }
//     default_action: nop;
//     max_size: 1;
// }

// table copy_pkt_to_cpu_t_2
// {
//     actions {
//         copy_pkt_to_cpu_action;
//     }
//     default_action: copy_pkt_to_cpu_action;
// }

register m_table_1_value
{
    width: 32;
    instance_count: M_TABLE_1_SIZE;
}

blackbox stateful_alu update_m_table_1_value
{
    reg: m_table_1_value;
    update_lo_1_value: register_lo + 1;
}

action update_m_table_1_value_action()
{
    update_m_table_1_value.execute_stateful_alu_from_hash(hash_1);
}

blackbox stateful_alu read_m_table_1_value
{
    reg: m_table_1_value;
    output_value: register_lo;
    output_dst: measurement_meta.m_table_1_cnt;
}

action read_m_table_1_value_action()
{
    read_m_table_1_value.execute_stateful_alu_from_hash(hash_1);
}

blackbox stateful_alu init_m_table_1_value
{
    reg: m_table_1_value;
    update_lo_1_value: 1;
}

action init_m_table_1_value_action()
{
    init_m_table_1_value.execute_stateful_alu_from_hash(hash_1);
}

@pragma stage 2
table update_m_table_1_value_t
{
    reads {
        measurement_meta.m_table_1_predicate: exact;
    }
    actions {
        update_m_table_1_value_action;
        read_m_table_1_value_action;
        init_m_table_1_value_action;
    }
    max_size: 3;
}


blackbox stateful_alu promote_m_table_1_value
{
    reg: m_table_1_value;
    update_lo_1_value: promote_header.cnt;
	output_value: register_lo;
	output_dst: export_header.record_cnt;	  
}

action promote_m_table_1_value_action()
{
    promote_m_table_1_value.execute_stateful_alu(promote_header.idx);
}

@pragma stage 2
table promote_m_table_1_value_t
{
	reads {
		export_promotion_meta.m_table_1: exact;
	}
    actions {
        promote_m_table_1_value_action;
		nop;
    }
    default_action: nop;
    max_size: 2;
}

//register m_table_2_key
//{
//    width: 32;
//    instance_count: M_TABLE_2_SIZE;
//}
// table copy_pkt_to_cpu_t_3
// {
//     reads {
//         measurement_meta.main_table_2_predicate: exact;//0010
//     }
//     actions {
//         copy_pkt_to_cpu_action;
//     }
//     max_size: 1;
// }

// table copy_pkt_to_cpu_t_4
// {
//     actions {
//         copy_pkt_to_cpu_action;
//     }
//     default_action: copy_pkt_to_cpu_action;
// }

register m_table_2_value
{
    width: 32;
    instance_count: M_TABLE_2_SIZE;
}

blackbox stateful_alu update_m_table_2_value
{
    reg: m_table_2_value;
    update_lo_1_value: register_lo + 1;
}

action update_m_table_2_value_action()
{
    update_m_table_2_value.execute_stateful_alu_from_hash(hash_2);
}

blackbox stateful_alu read_m_table_2_value
{
    reg: m_table_2_value;
    output_value: register_lo;
    output_dst: measurement_meta.m_table_2_cnt;
}

action read_m_table_2_value_action()
{
    read_m_table_2_value.execute_stateful_alu_from_hash(hash_2);
}

blackbox stateful_alu init_m_table_2_value
{
    reg: m_table_2_value;
    update_lo_1_value: 1;
}

action init_m_table_2_value_action()
{
    init_m_table_2_value.execute_stateful_alu_from_hash(hash_2);
	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
}

@pragma stage 3
table update_m_table_2_value_t
{
    reads {
        measurement_meta.m_table_2_predicate: exact;
    }
    actions {
        update_m_table_2_value_action;
        read_m_table_2_value_action;
        init_m_table_2_value_action;
		nop;
    }
	default_action: nop;
    max_size: 4;
}

blackbox stateful_alu promote_m_table_2_value
{
    reg: m_table_2_value;
    update_lo_1_value: promote_header.cnt;
	output_value: register_lo;
	output_dst: export_header.record_cnt;	  
}

action promote_m_table_2_value_action()
{
    promote_m_table_2_value.execute_stateful_alu(promote_header.idx);
}

@pragma stage 3
table promote_m_table_2_value_t
{
	reads {
		export_promotion_meta.m_table_2: exact;
	}
    actions {
        promote_m_table_2_value_action;
		nop;
    }
    default_action: nop;
    max_size: 2;
}

// table copy_pkt_to_cpu_t_5
// {
//     reads {
//         measurement_meta.main_table_3_predicate: exact;//0010
//     }
//     actions {
//         copy_pkt_to_cpu_action;
//         nop;
//     }
//     default_action: nop;
//     max_size: 1;
// }

// table copy_pkt_to_cpu_t_6
// {
//     actions {
//         copy_pkt_to_cpu_action;
//     }
//     default_action: copy_pkt_to_cpu_action;
// }

register m_table_3_value
{
    width: 32;
    instance_count: M_TABLE_3_SIZE;
}

blackbox stateful_alu update_m_table_3_value
{
    reg: m_table_3_value;
    update_lo_1_value: register_lo + 1;
}

action update_m_table_3_value_action()
{
    update_m_table_3_value.execute_stateful_alu_from_hash(hash_3);
}

blackbox stateful_alu read_m_table_3_value
{
    reg: m_table_3_value;
    output_value: register_lo;
    output_dst: measurement_meta.m_table_3_cnt;
}

action read_m_table_3_value_action()
{
    read_m_table_3_value.execute_stateful_alu_from_hash(hash_3);
}

blackbox stateful_alu init_m_table_3_value
{
    reg: m_table_3_value;
    update_lo_1_value: 1;
}

action init_m_table_3_value_action()
{
    init_m_table_3_value.execute_stateful_alu_from_hash(hash_3);
	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
}

@pragma stage 4
table update_m_table_3_value_t
{
    reads {
        measurement_meta.m_table_3_predicate: exact;
    }
    actions {
        update_m_table_3_value_action;
        read_m_table_3_value_action;
        init_m_table_3_value_action;
    }
    max_size: 3;
}

blackbox stateful_alu promote_m_table_3_value
{
    reg: m_table_3_value;
    update_lo_1_value: promote_header.cnt;
	output_value: register_lo;
	output_dst: export_header.record_cnt;	  
}

action promote_m_table_3_value_action()
{
    promote_m_table_3_value.execute_stateful_alu(promote_header.idx);
}

@pragma stage 4
table promote_m_table_3_value_t
{
	reads {
		export_promotion_meta.m_table_3: exact;
	}
    actions {
        promote_m_table_3_value_action;
		nop;
    }
    default_action: nop;
    max_size: 2;
}

action subtract_action() {
	subtract(measurement_meta.diff1, measurement_meta.m_table_1_cnt, measurement_meta.m_table_2_cnt);
	subtract(measurement_meta.diff2, measurement_meta.m_table_1_cnt, measurement_meta.m_table_3_cnt);
	subtract(measurement_meta.diff3, measurement_meta.m_table_2_cnt, measurement_meta.m_table_3_cnt);
}

@pragma stage 5
table subtract_t {
	actions {
		subtract_action;
	}
	default_action: subtract_action;
}


action update_min_max (cnt_min, idx_min, m_table_id_min, cnt_max, idx_max, m_table_id_max) {
	modify_field(measurement_meta.cnt_min, cnt_min);
	modify_field(measurement_meta.idx_min, idx_min);
	modify_field(measurement_meta.m_table_id_min, m_table_id_min);
	modify_field(measurement_meta.cnt_max, cnt_max, 0x000000ff);
	modify_field(measurement_meta.idx_max, idx_max);
	modify_field(measurement_meta.m_table_id_max, m_table_id_max);
}

action update_min_1_max_2 () {
	update_min_max(measurement_meta.m_table_1_cnt, measurement_meta.m_table_1_idx, 1, 
			measurement_meta.m_table_2_cnt, measurement_meta.m_table_2_idx, 2);
}

action update_min_1_max_3 () {
	update_min_max(measurement_meta.m_table_1_cnt, measurement_meta.m_table_1_idx, 1, 
			measurement_meta.m_table_3_cnt, measurement_meta.m_table_3_idx, 3);
}

action update_min_2_max_1 () {
	update_min_max(measurement_meta.m_table_2_cnt, measurement_meta.m_table_2_idx, 2, 
			measurement_meta.m_table_1_cnt, measurement_meta.m_table_1_idx, 1);
}

action update_min_2_max_3 () {
	update_min_max(measurement_meta.m_table_2_cnt, measurement_meta.m_table_2_idx, 2, 
			measurement_meta.m_table_3_cnt, measurement_meta.m_table_3_idx, 3);
}

action update_min_3_max_1 () {
	update_min_max(measurement_meta.m_table_3_cnt, measurement_meta.m_table_3_idx, 3, 
			measurement_meta.m_table_1_cnt, measurement_meta.m_table_1_idx, 1);
}

action update_min_3_max_2 () {
	update_min_max(measurement_meta.m_table_3_cnt, measurement_meta.m_table_3_idx, 3, 
			measurement_meta.m_table_2_cnt, measurement_meta.m_table_2_idx, 2);
}

@pragma stage 6
table update_min_max_t {
	reads {
		measurement_meta.diff1 mask 0x80000000: exact;
		measurement_meta.diff2 mask 0x80000000: exact;
		measurement_meta.diff3 mask 0x80000000: exact;
		/*diff1	diff2	diff3	min	max
		 *0		0		0		3	1
		 *0		0		1		2	1
		 *0		1		0		NO	NO
		 *0		1		1		2	3
		 *1		0		0		3	2
		 *1		0		1		NO	NO
		 *1		1		0		1	2
		 *1		1		1		1	3
		 * */
	}
	actions {
		update_min_1_max_2;
		update_min_1_max_3;
		update_min_2_max_1;
		update_min_2_max_3;
		update_min_3_max_1;
		update_min_3_max_2;
	}
    max_size: 6;
}

register a_table
{
    width: 16;
    instance_count: A_TABLE_SIZE;
}

blackbox stateful_alu update_a_table
{
    reg: a_table;
    condition_lo: register_lo == 0;
    condition_hi: register_hi == measurement_meta.digest;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: 1;

    update_hi_1_value: measurement_meta.digest;

    output_value: alu_lo;
    output_dst: measurement_meta.a_cnt;
}

action update_a_table_action()
{
    update_a_table.execute_stateful_alu_from_hash(hash_4);
}

@pragma stage 6
table update_a_table_t
{
    actions {
        update_a_table_action;
    }
    default_action: update_a_table_action;
    max_size: 1;
}

action compare_action()
{
    subtract(measurement_meta.flag_min, measurement_meta.cnt_min, measurement_meta.a_cnt);
    subtract(measurement_meta.flag_max, GAMMA, measurement_meta.a_cnt);
	subtract(measurement_meta.flag_active, measurement_meta.cnt_max, measurement_meta.b_cnt);
}

@pragma stage 8
table compare_t
{
    actions {
        compare_action;
    }
    default_action: compare_action;
}


// register array for the B table
register b_table
{
    width: 8;
    instance_count: A_TABLE_SIZE;
}

blackbox stateful_alu update_b_table
{
    reg: b_table;
    condition_lo: measurement_meta.a_cnt == 1;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: measurement_meta.cnt_max;

    output_value: alu_lo;
    output_dst: measurement_meta.b_cnt;
}

action update_b_action()
{
    update_b_table.execute_stateful_alu_from_hash(hash_4);
}

@pragma stage 7
table update_b_t
{
    actions {
        update_b_action;
    }
    default_action: update_b_action;
    max_size: 1;
}

action do_promotion(cnt, m_table_id, idx){
	modify_field(promote_header.cnt, cnt);
	modify_field(promote_header.m_table_id, m_table_id);
	modify_field(promote_header.idx, idx);
	config_export_header(export_promotion_meta.srcip, export_promotion_meta.dstip,
			export_promotion_meta.proto, export_promotion_meta.srcport,
			export_promotion_meta.dstport, measurement_meta.fingerprint);
	add_promote_header();
	modify_field(export_promotion_meta.promotion_flag, 1);
	modify_field(export_promotion_meta.resubmit_flag, 1);
	resubmit(resubmit_fields);
}

action do_promotion_min() {
	do_promotion(measurement_meta.cnt_min, measurement_meta.m_table_id_min, 
			measurement_meta.idx_min);
//	update_cntr1_action();
}

action do_promotion_max() {
	do_promotion(measurement_meta.cnt_max, measurement_meta.m_table_id_max, 
			measurement_meta.idx_max);
//	update_cntr2_action();
}

@pragma stage 9
table promote_t {
	reads {
		measurement_meta.flag_min: ternary;
		measurement_meta.flag_max: ternary;
		measurement_meta.flag_active: ternary;
		/*flag_min	flag_max	flag_active	action
		 *0			0			0			nop
		 *0			0			!=0			nop
		 *0			1			0			do_promotion_max
		 *0			1			!=0			nop
		 *1			0			0			do_promotion_min
		 *1			0			!=0			do_promotion_min
		 *1			1			0			do_promotion_min
		 *1			1			!=0			do_promotion_min
		 * */
	}
	actions {
		do_promotion_min;
		do_promotion_max;
		nop;
	}
	default_action: nop;
}

action rmv_tcp_add_udp() {
	remove_header(tcp);
	add_header(udp);
	add(ipv4.totalLen, export_promotion_meta.ipv4_totalLen, -12);
	modify_field(ipv4.proto, IPV4_UDP);
	add(udp.totalLen, export_promotion_meta.ipv4_totalLen, -32);
//	modify_field(udp.srcport, UDP_EXPORT);
//	modify_field(udp.dstport, 8082);
//	modify_field(udp.checksum, 0);
}

@pragma stage 10
table rmv_tcp_add_udp_t {
	actions {
		rmv_tcp_add_udp;
	}
	default_action: rmv_tcp_add_udp;
}

action do_drop()
{
	drop();
}

action config_export_header(srcip, dstip, proto, srcport, dstport, fingerprint) {
	modify_field(export_header.srcip, srcip);
	modify_field(export_header.dstip, dstip);
	modify_field(export_header.proto, proto);
	modify_field(export_header.srcport, srcport);
	modify_field(export_header.dstport, dstport);
	modify_field(export_header.fingerprint, fingerprint);
}

action export() {
	add_header(export_header);
	add(ipv4.totalLen, ipv4.totalLen, EXPORT_HEADER_LEN);
	add(udp.totalLen, udp.totalLen, EXPORT_HEADER_LEN);
	modify_field(ipv4.srcip, CTRL_SRC_IP);
	modify_field(ipv4.dstip, CTRL_IP);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.dstport, CTRL_PORT);
	modify_field(udp.checksum, 0);
}

@pragma stage 11
table export_t {
	reads {
		export_promotion_meta.export_flag: exact;
	}
	actions {
		do_drop;
		export;
	}	
	default_action: do_drop;
}

control AHashFlow
{
	if(0 == export_promotion_meta.promotion_flag) {
		// stage 0
		apply(generate_fingerprint_t);
		apply(calc_digest_t);
		apply(calc_m_table_1_idx_t);
		apply(calc_m_table_2_idx_t);
		apply(calc_m_table_3_idx_t);
		// stage 1
		apply(update_m_table_1_key_t);
		// stage 2
		apply(update_m_table_1_value_t); 
		apply(update_m_table_2_key_t); 
		// stage 3
		apply(update_m_table_2_value_t); 
		apply(update_m_table_3_key_t);
		// stage 4
		apply(update_m_table_3_value_t);
		if (PRED_COL == measurement_meta.m_table_1_predicate and 
			PRED_COL == measurement_meta.m_table_2_predicate and 
			PRED_COL == measurement_meta.m_table_3_predicate) {// collision occurs in every m table
			// stage 5
			apply(subtract_t);
			// stage 6
			apply(update_min_max_t);
			apply(update_a_table_t);
			// stage 7
			apply(update_b_t);
			// stage 8
			apply(compare_t)
			{
				compare_action {
					// stage 9
					apply(promote_t);
				}
			}
		}
		else if(PRED_EMP == measurement_meta.m_table_1_predicate or 
			PRED_EMP == measurement_meta.m_table_2_predicate or 
			PRED_EMP == measurement_meta.m_table_3_predicate) {// there is a empty bucket
			// stage 5
			apply(export_set_flag_config_header_t);		
		}
	}
	else{
		apply(update_cntr1_t);
		if(valid(promote_header)) {
			apply(update_cntr2_t);
		}
		// stage 1
		apply(promote_m_table_1_key_t);	
		// stage 2
		apply(promote_m_table_1_value_t);	
		apply(promote_m_table_2_key_t);	
		// stage 3
		apply(promote_m_table_2_value_t);	
		apply(promote_m_table_3_key_t);	
		// stage 4
		apply(promote_m_table_3_value_t);	
		// stage 5
		apply(rmv_promote_header_config_export_header_t);
	}
	//	apply(set_export_flag_t);		
	if(0 == export_promotion_meta.resubmit_flag) {
		if(valid(tcp)) {
			// stage 10
			apply(rmv_tcp_add_udp_t);
		}
		// stage 11
		apply(export_t);
	}
}

control ingress {
	apply(forward);
	if(valid(udp) or valid(tcp)) {
		AHashFlow();
	}
}
control egress
{

}
