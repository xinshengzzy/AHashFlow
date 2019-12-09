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
    tcp.srcport;
    tcp.dstport;
}

// hash function for main_table_1 and fingerprint generation
field_list_calculation hash_1 {
    input {
        flow;
    }
    algorithm: crc32;
    output_width: MAIN_TABLE_IDX_WIDTH;
}

// hash function for main_table_2
field_list_calculation hash_2 {
    input {
        flow;
    }
    algorithm: crc32_extend;
    output_width: MAIN_TABLE_IDX_WIDTH;
}

// hash function for main_table_3
field_list_calculation hash_3 {
    input {
        flow;
    }
    algorithm: crc32_lsb;
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
        promotion: 1; // indicating variable for recirculate;
        stage: 4; // indicating variable for stage of back inserting;
        stage2: 4; // indicating variable for stage of reporting;
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
        ancillary_table_predicate: 4; // output predicate in main sub table 1
		export_fingerprint: 32; // the fingerprint evicted from the M table
		export_cnt: 32; // the counter evicted from the M table
    }
}

metadata measurement_meta_t measurement_meta;


////////// for the useage of testing //////////
register cntr1 {
	width: 16;
	instance_count: 10;
}

blackbox stateful_alu update_cntr1 {
	reg: cntr1;
	update_lo_1_value: register_lo + 1;
}

action update_cntr1_action() {
	update_cntr1.execute_stateful_alu(0);
}

@pragma stage 0
table update_cntr1_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		update_cntr1_action;
		nop;
	}
	default_action: nop;
	size: 10;
}
////////// end the test //////////


action nop()
{
    // no operation conducted
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

action do_recirc() {
	recirculate(68);
}

table recirc_tbl {
	reads {
		measurement_meta.promotion: exact;	
	}
	actions {
		do_recirc;
		nop;
	}
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
	output_dst: measurement_meta.export_fingerprint;	  
}

action promote_m_table_1_key_action()
{
    promote_m_table_1_key.execute_stateful_alu(promote_header.idx);
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
        measurement_meta.m_table_1_predicate: ternary;
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
	output_dst: measurement_meta.export_fingerprint;	  
}

action promote_m_table_2_key_action()
{
    promote_m_table_2_key.execute_stateful_alu(promote_header.idx);
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

//blackbox stateful_alu rewrite_m_table_3_key
//{
//    reg: m_table_3_key;
//    update_lo_1_value: measurement_meta.fingerprint;
//}

//action rewrite_m_table_3_key_action()
//{
//    rewrite_m_table_3_key.execute_stateful_alu_from_hash(hash_3);
//}

@pragma stage 3
table update_m_table_3_key_t
{
    reads {
        measurement_meta.m_table_2_predicate: ternary;
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
	output_dst: measurement_meta.export_fingerprint;	  
}

action promote_m_table_3_key_action()
{
    promote_m_table_3_key.execute_stateful_alu(promote_header.idx);
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
	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
}

@pragma stage 4
table update_m_table_1_value_t
{
    reads {
        measurement_meta.m_table_1_predicate: exact;
        measurement_meta.m_table_2_predicate: exact;
        measurement_meta.m_table_3_predicate: exact;
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
	output_dst: measurement_meta.export_cnt;	  
}

action promote_m_table_1_value_action()
{
    promote_m_table_1_value.execute_stateful_alu(promote_header.idx);
}

@pragma stage 4
table promote_m_table_1_value_t
{
	reads {
		promote_header.m_table_id: exact;
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

@pragma stage 5
table update_m_table_2_value_t
{
    reads {
        measurement_meta.m_table_1_predicate: exact;
        measurement_meta.m_table_2_predicate: exact;
        measurement_meta.m_table_3_predicate: exact;
    }
    actions {
        update_m_table_2_value_action;
        read_m_table_2_value_action;
        init_m_table_2_value_action;
    }
    max_size: 3;
}

blackbox stateful_alu promote_m_table_2_value
{
    reg: m_table_2_value;
    update_lo_1_value: promote_header.cnt;
	output_value: register_lo;
	output_dst: measurement_meta.export_cnt;	  
}

action promote_m_table_2_value_action()
{
    promote_m_table_2_value.execute_stateful_alu(promote_header.idx);
}

@pragma stage 5
table promote_m_table_2_value_t
{
	reads {
		promote_header.m_table_id: exact;
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

@pragma stage 6
table update_m_table_3_value_t
{
    reads {
        measurement_meta.m_table_1_predicate: exact;
        measurement_meta.m_table_2_predicate: exact;
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
	output_dst: measurement_meta.export_cnt;	  
}

action promote_m_table_3_value_action()
{
    promote_m_table_3_value.execute_stateful_alu(promote_header.idx);
}

@pragma stage 6
table promote_m_table_3_value_t
{
	reads {
		promote_header.m_table_id: exact;
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

@pragma stage 7
table subtract_t {
	actions {
		subtract_action;
	}
	default_action: subtract_action;
}

action export_flow_record_action() {
	add_header(record_export_header);
	remove_header(promote_header);
	// assume that all the packets are from the TCP flows
	modify_field(tcp.srcport, TCP_RECORD_EXPORT);
	modify_field(record_export_header.fingerprint, measurement_meta.export_fingerprint);
	modify_field(record_export_header.cnt, measurement_meta.export_cnt);
	modify_field(record_export_header.exportType, promote_header.promoteType);
	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
}

@pragma stage 7
table export_flow_record_t {
	actions {
		export_flow_record_action;
	}	
	default_action: export_flow_record_action;
}

action update_min_max_1 () {
	modify_field(measurement_meta.cnt_max, measurement_meta.m_table_1_cnt, 0x000000ff);
	modify_field(measurement_meta.idx_max, measurement_meta.m_table_1_idx);
	modify_field(measurement_meta.m_table_id_max, 1);
	modify_field(measurement_meta.cnt_min, measurement_meta.m_table_3_cnt);
	modify_field(measurement_meta.idx_min, measurement_meta.m_table_3_idx);
	modify_field(measurement_meta.m_table_id_min, 3);
}

action update_min_max_2 () {
	modify_field(measurement_meta.cnt_max, measurement_meta.m_table_1_cnt, 0x000000ff);
	modify_field(measurement_meta.idx_max, measurement_meta.m_table_1_idx);
	modify_field(measurement_meta.m_table_id_max, 1);
	modify_field(measurement_meta.cnt_min, measurement_meta.m_table_2_cnt);
	modify_field(measurement_meta.idx_min, measurement_meta.m_table_2_idx);
	modify_field(measurement_meta.m_table_id_min, 2);
}

action update_min_max_3 () {
	modify_field(measurement_meta.cnt_max, measurement_meta.m_table_2_cnt, 0x000000ff);
	modify_field(measurement_meta.idx_max, measurement_meta.m_table_2_idx);
	modify_field(measurement_meta.m_table_id_max, 2);
	modify_field(measurement_meta.cnt_min, measurement_meta.m_table_3_cnt);
	modify_field(measurement_meta.idx_min, measurement_meta.m_table_3_idx);
	modify_field(measurement_meta.m_table_id_min, 3);
}

action update_min_max_4 () {
	modify_field(measurement_meta.cnt_max, measurement_meta.m_table_2_cnt, 0x000000ff);
	modify_field(measurement_meta.idx_max, measurement_meta.m_table_2_idx);
	modify_field(measurement_meta.m_table_id_max, 2);
	modify_field(measurement_meta.cnt_min, measurement_meta.m_table_1_cnt);
	modify_field(measurement_meta.idx_min, measurement_meta.m_table_1_idx);
	modify_field(measurement_meta.m_table_id_min, 1);
}

action update_min_max_5 () {
	modify_field(measurement_meta.cnt_max, measurement_meta.m_table_3_cnt, 0x000000ff);
	modify_field(measurement_meta.idx_max, measurement_meta.m_table_3_idx);
	modify_field(measurement_meta.m_table_id_max, 3);
	modify_field(measurement_meta.cnt_min, measurement_meta.m_table_2_cnt);
	modify_field(measurement_meta.idx_min, measurement_meta.m_table_2_idx);
	modify_field(measurement_meta.m_table_id_min, 2);
}

action update_min_max_6 () {
	modify_field(measurement_meta.cnt_max, measurement_meta.m_table_3_cnt, 0x000000ff);
	modify_field(measurement_meta.idx_max, measurement_meta.m_table_3_idx);
	modify_field(measurement_meta.m_table_id_max, 3);
	modify_field(measurement_meta.cnt_min, measurement_meta.m_table_1_cnt);
	modify_field(measurement_meta.idx_min, measurement_meta.m_table_1_idx);
	modify_field(measurement_meta.m_table_id_min, 1);
}

@pragma stage 8
table update_min_max_t {
	reads {
		measurement_meta.diff1 mask 0x80000000: exact;
		measurement_meta.diff2 mask 0x80000000: exact;
		measurement_meta.diff3 mask 0x80000000: exact;
	}
	actions {
		update_min_max_1;
		update_min_max_2;
		update_min_max_3;
		update_min_max_4;
		update_min_max_5;
		update_min_max_6;
	}
    max_size: 6;
}








//action copy_pkt_to_cpu_action()
//{
//    modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
    // modify_field(intrinsic_metadata.cos_for_copy_to_cpu, ...);
//}

//table copy_to_cpu_t
//{
//    reads {
//        measurement_meta.promotion: exact;
//        measurement_meta.m_table_1_predicate: ternary;
//        measurement_meta.m_table_2_predicate: ternary;
//        measurement_meta.m_table_3_predicate: ternary;
//    }
//    actions {
//        copy_pkt_to_cpu_action;
//        nop;
//    }
//    default_action: nop;
//    max_size: 4;
//}

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

@pragma stage 8
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

@pragma stage 10
table compare_t
{
    reads {
        measurement_meta.a_cnt: exact;
    }
    actions {
        compare_action;
        nop;
    }
    default_action: compare_action;
    max_size: 2;
}


// register array for the B table
register b_table
{
    width: 8;
    instance_count: A_TABLE_SIZE;
}

@pragma stage 7
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

@pragma stage 9
table update_b_t
{
    actions {
        update_b_action;
    }
    default_action: update_b_action;
    max_size: 1;
}

action promote_max_action() {
	add_header(promote_header);	
	modify_field(promote_header.fingerprint, measurement_meta.fingerprint);
	modify_field(promote_header.m_table_id, measurement_meta.m_table_id_max);
	modify_field(promote_header.idx, measurement_meta.idx_max);
	modify_field(promote_header.cnt, measurement_meta.cnt_max);
	// we assume that all the packets are from TCP flows
	modify_field(promote_header.promoteType, tcp.srcport);
	modify_field(tcp.srcport, TCP_PROMOTE);
	recirculate(68);
}

action promote_min_action() {
	add_header(promote_header);	
	modify_field(promote_header.fingerprint, measurement_meta.fingerprint);
	modify_field(promote_header.m_table_id, measurement_meta.m_table_id_min);
	modify_field(promote_header.idx, measurement_meta.idx_min);
	modify_field(promote_header.cnt, measurement_meta.cnt_min);
	// we assume that all the packets are from TCP flows
	modify_field(promote_header.promoteType, tcp.srcport);
	modify_field(tcp.srcport, TCP_PROMOTE);
	recirculate(68);
}

@pragma stage 11
table promote_t {
	reads {
		measurement_meta.flag_min: ternary;
		measurement_meta.flag_max: ternary;
		measurement_meta.flag_active: exact;
	}	
	actions {
		promote_max_action;
		promote_min_action;
		nop;
	}
	default_action: nop;
}

//field_list recirculate_fields
//{
//    measurement_meta.promotion; //1-bit
//    measurement_meta.stage; //4-bit
//    measurement_meta.ac_flow_count; //32-bit
//}

//action cancel_recirc_action()
//{
//	// drop();
//	mark_for_drop();
//}

control ingress
{
	// stage 0
	apply(update_cntr1_t);
    apply(generate_fingerprint_t);
    apply(calc_digest_t);
	apply(calc_m_table_1_idx_t);
	apply(calc_m_table_2_idx_t);
	apply(calc_m_table_3_idx_t);
	if(valid(promote_header)) {
		// stage 1
		apply(promote_m_table_1_key_t);	
		// stage 2
		apply(promote_m_table_2_key_t);	
		// stage 3
		apply(promote_m_table_3_key_t);	
		// stage 4
		apply(promote_m_table_1_value_t);	
		// stage 5
		apply(promote_m_table_2_value_t);	
		// stage 6
		apply(promote_m_table_3_value_t);	
		// stage 7
		apply(export_flow_record_t);	
	} 
	else{
		// stage 1
		apply(update_m_table_1_key_t);
			// stage 2
			apply(update_m_table_2_key_t) {
				update_m_table_2_key_action {
					// stage 3
					apply(update_m_table_3_key_t);
				}
			}
		// stage 4
		apply(update_m_table_1_value_t); 
		// stage 5
		apply(update_m_table_2_value_t); 
		// stage 6
		apply(update_m_table_3_value_t);
		if (measurement_meta.m_table_1_predicate == PRED and measurement_meta.m_table_2_predicate == PRED and measurement_meta.m_table_3_predicate == PRED)	{
			// stage 7
			apply(subtract_t);
			// stage 8
			apply(update_min_max_t);
			apply(update_a_table_t);
			// stage 9
			apply(update_b_t);
			// stage 10
			apply(compare_t)
			{
				compare_action {
					// stage 11
					apply(promote_t);
				}
			}
		}
	}
}

control egress
{
//    apply(copy_to_cpu_t);
    // apply(update_ancillary_table_key_t);
    // apply(update_ancillary_table_value_t) {
    //     update_ancillary_table_value_action {
    //         apply(min_value_subtract_pktcnt_a_t);
    //         apply(handle_recirculate_t);
    //     }
    // }
}
