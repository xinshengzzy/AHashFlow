#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/pktgen_headers.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/wred_blackbox.p4>

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/macro.p4"

#define PKT_INSTANCE_TYPE_NORMAL 0

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
    output_width: ANCILLARY_TABLE_IDX_WIDTH;
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
        ac_flow_count: 8; // temp storage for flow count of ancillary table;
        flag: 32; // subtract flag used for judging negative or not
        flag2: 32; // subtract flag used for judging negative or not
        fingerprint: 32; // fingerprint for 5-tuple;
        min_flow_count: 32; // minimum flow count of all 3 sub tables of main table;
        max_flow_count: 32; // maximum flow count of all 3 sub tables of main table;
        temp_flow_count: 32; // temp storage for flow count of the current sub table;
        main_table_1_predicate: 4; // output predicate in main sub table 1;
        main_table_2_predicate: 4; // output predicate in main sub table 2;
        main_table_3_predicate: 4; // output predicate in main sub table 3;
        ancillary_table_predicate: 4; // output predicate in main sub table 1
    }
}

metadata measurement_meta_t measurement_meta;


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
table calc_digest_t
{
    actions {
        calc_digest_action;
    }
    default_action: calc_digest_action;
}

// register for storing key of the first main sub table 1
register main_table_1_key
{
    width: 32;
    instance_count: SUB_TABLE_A_SIZE;
}

blackbox stateful_alu update_main_table_1_key
{
    reg: main_table_1_key;
    condition_lo: register_lo == 0;
    condition_hi: register_lo == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: measurement_meta.fingerprint;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: register_lo;

    output_value: predicate;
    output_dst: measurement_meta.main_table_1_predicate;
}

action update_main_table_1_key_action()
{
    update_main_table_1_key.execute_stateful_alu_from_hash(hash_1);
}

blackbox stateful_alu rewrite_main_table_1_key
{
    reg: main_table_1_key;
    update_lo_1_value: measurement_meta.fingerprint;
}

action rewrite_main_table_1_key_action()
{
    rewrite_main_table_1_key.execute_stateful_alu_from_hash(hash_1);
}

table update_main_table_1_key_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: ternary;
    }
    actions {
        update_main_table_1_key_action;
        rewrite_main_table_1_key_action;
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

register main_table_1_value
{
    width: 32;
    instance_count: SUB_TABLE_A_SIZE;
}

blackbox stateful_alu update_main_table_1_value
{
    reg: main_table_1_value;
    update_lo_1_value: register_lo + 1;
}

action update_main_table_1_value_action()
{
    update_main_table_1_value.execute_stateful_alu_from_hash(hash_1);
}

blackbox stateful_alu read_main_table_1_value
{
    reg: main_table_1_value;
    output_value: register_lo;
    output_dst: measurement_meta.temp_flow_count;
}

action read_main_table_1_value_action()
{
    read_main_table_1_value.execute_stateful_alu_from_hash(hash_1);
    // modify_field(measurement_meta.stage, 1);
    // modify_field(measurement_meta.stage2, 1);
    // modify_field(measurement_meta.max_flow_count, measurement_meta.min_flow_count);
}

blackbox stateful_alu rewrite_main_table_1_value
{
    reg: main_table_1_value;
    update_lo_1_value: measurement_meta.ac_flow_count + 1;
}

action rewrite_main_table_1_value_action()
{
    rewrite_main_table_1_value.execute_stateful_alu_from_hash(hash_1);
}

table update_main_table_1_value_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: ternary;
        measurement_meta.main_table_1_predicate: ternary;
    }
    actions {
        update_main_table_1_value_action;
        read_main_table_1_value_action;
        rewrite_main_table_1_value_action;
        nop;
    }
    default_action: nop;
    max_size: 3;
}

action update_min_max_1_action()
{
    modify_field(measurement_meta.stage, 1);
    modify_field(measurement_meta.stage2, 1);
    modify_field(measurement_meta.min_flow_count, measurement_meta.temp_flow_count);
    modify_field(measurement_meta.max_flow_count, measurement_meta.temp_flow_count);
}

table update_min_max_1_t
{
    actions {
        update_min_max_1_action;
    }
    default_action: update_min_max_1_action;
}

register main_table_2_key
{
    width: 32;
    instance_count: SUB_TABLE_B_SIZE;
}

blackbox stateful_alu update_main_table_2_key
{
    reg: main_table_2_key;
    condition_lo: register_lo == 0;
    condition_hi: register_lo == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: measurement_meta.fingerprint;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: register_lo;

    output_value: predicate;
    output_dst: measurement_meta.main_table_2_predicate;
}

action update_main_table_2_key_action()
{
    update_main_table_2_key.execute_stateful_alu_from_hash(hash_2);
}

blackbox stateful_alu rewrite_main_table_2_key
{
    reg: main_table_2_key;
    update_lo_1_value: measurement_meta.fingerprint;
}

action rewrite_main_table_2_key_action()
{
    rewrite_main_table_2_key.execute_stateful_alu_from_hash(hash_2);
}

table update_main_table_2_key_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: ternary;
        measurement_meta.main_table_1_predicate: ternary;
    }
    actions {
        update_main_table_2_key_action;
        rewrite_main_table_2_key_action;
        nop;
    }
    default_action: nop;
    max_size: 2;
}

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

register main_table_2_value
{
    width: 32;
    instance_count: SUB_TABLE_B_SIZE;
}

blackbox stateful_alu update_main_table_2_value
{
    reg: main_table_2_value;
    update_lo_1_value: register_lo + 1;
}

action update_main_table_2_value_action()
{
    update_main_table_2_value.execute_stateful_alu_from_hash(hash_2);
}

blackbox stateful_alu read_main_table_2_value
{
    reg: main_table_2_value;
    output_value: register_lo;
    output_dst: measurement_meta.temp_flow_count;
}

action read_main_table_2_value_action()
{
    read_main_table_2_value.execute_stateful_alu_from_hash(hash_2);
}

blackbox stateful_alu rewrite_main_table_2_value
{
    reg: main_table_2_value;
    update_lo_1_value: measurement_meta.ac_flow_count + 1;
}

action rewrite_main_table_2_value_action()
{
    rewrite_main_table_2_value.execute_stateful_alu_from_hash(hash_2);
}

table update_main_table_2_value_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: ternary;
        measurement_meta.main_table_1_predicate: ternary;
        measurement_meta.main_table_2_predicate: ternary;
    }
    actions {
        update_main_table_2_value_action;
        read_main_table_2_value_action;
        rewrite_main_table_2_value_action;
        nop;
    }
    default_action: nop;
    max_size: 3;
}

action min_max_value_subtract_pktcnt_2_action()
{
    subtract(measurement_meta.flag, measurement_meta.min_flow_count, measurement_meta.temp_flow_count);
    subtract(measurement_meta.flag2, measurement_meta.max_flow_count, measurement_meta.temp_flow_count);
}

table min_max_value_subtract_pktcnt_2_t
{
    actions {
        min_max_value_subtract_pktcnt_2_action;
    }
    default_action: min_max_value_subtract_pktcnt_2_action;
}

action update_min_2_action()
{
    modify_field(measurement_meta.min_flow_count, measurement_meta.temp_flow_count);
    modify_field(measurement_meta.stage, 2);
}

table update_min_2_t
{
    reads {
        measurement_meta.flag: ternary;
    }
    actions {
        update_min_2_action;// execute when the highest bit of flag is 0
        nop;
    }
    default_action: nop;
    max_size: 1;
}

action update_max_2_action()
{
    modify_field(measurement_meta.max_flow_count, measurement_meta.temp_flow_count);
    modify_field(measurement_meta.stage2, 2);
}

table update_max_2_t
{
    reads {
        measurement_meta.flag2: ternary;
    }
    actions {
        update_max_2_action;
        nop;
    }
    default_action: nop;
    max_size: 1;
}

register main_table_3_key
{
    width: 32;
    instance_count: SUB_TABLE_C_SIZE;
}

blackbox stateful_alu update_main_table_3_key
{
    reg: main_table_3_key;
    condition_lo: register_lo == 0;
    condition_hi: register_lo == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: measurement_meta.fingerprint;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: register_lo;

    output_value: predicate;
    output_dst: measurement_meta.main_table_3_predicate;
}

action update_main_table_3_key_action()
{
    update_main_table_3_key.execute_stateful_alu_from_hash(hash_3);
}

blackbox stateful_alu rewrite_main_table_3_key
{
    reg: main_table_3_key;
    update_lo_1_value: measurement_meta.fingerprint;
}

action rewrite_main_table_3_key_action()
{
    rewrite_main_table_3_key.execute_stateful_alu_from_hash(hash_3);
}

table update_main_table_3_key_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: ternary;
        measurement_meta.main_table_1_predicate: ternary;
        measurement_meta.main_table_2_predicate: ternary;
    }
    actions {
        update_main_table_3_key_action;
        rewrite_main_table_3_key_action;
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

register main_table_3_value
{
    width: 32;
    instance_count: SUB_TABLE_C_SIZE;
}

blackbox stateful_alu update_main_table_3_value
{
    reg: main_table_3_value;
    update_lo_1_value: register_lo + 1;
}

action update_main_table_3_value_action()
{
    update_main_table_3_value.execute_stateful_alu_from_hash(hash_3);
}

blackbox stateful_alu read_main_table_3_value
{
    reg: main_table_3_value;
    output_value: register_lo;
    output_dst: measurement_meta.temp_flow_count;
}

action read_main_table_3_value_action()
{
    read_main_table_3_value.execute_stateful_alu_from_hash(hash_3);
}

blackbox stateful_alu rewrite_main_table_3_value
{
    reg: main_table_3_value;
    update_lo_1_value: measurement_meta.ac_flow_count + 1;
}

action rewrite_main_table_3_value_action()
{
    rewrite_main_table_3_value.execute_stateful_alu_from_hash(hash_3);
}

table update_main_table_3_value_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: ternary;
        measurement_meta.main_table_1_predicate: ternary;
        measurement_meta.main_table_2_predicate: ternary;
        measurement_meta.main_table_3_predicate: ternary;
    }
    actions {
        update_main_table_3_value_action;
        read_main_table_3_value_action;
        rewrite_main_table_3_value_action;
        nop;
    }
    default_action: nop;
    max_size: 3;
}

action min_max_value_subtract_pktcnt_3_action()
{
    subtract(measurement_meta.flag, measurement_meta.min_flow_count, measurement_meta.temp_flow_count);
    subtract(measurement_meta.flag2, measurement_meta.max_flow_count, measurement_meta.temp_flow_count);
}

table min_max_value_subtract_pktcnt_3_t
{
    actions {
        min_max_value_subtract_pktcnt_3_action;
    }
    default_action: min_max_value_subtract_pktcnt_3_action;
}

action update_min_3_action()
{
    modify_field(measurement_meta.min_flow_count, measurement_meta.temp_flow_count);
    modify_field(measurement_meta.stage, 3);
}

table update_min_3_t
{
    reads {
        measurement_meta.flag: ternary;
    }
    actions {
        update_min_3_action;
        nop;
    }
    default_action: nop;
    max_size: 1;
}

action update_max_3_action()
{
    modify_field(measurement_meta.max_flow_count, measurement_meta.temp_flow_count);
    modify_field(measurement_meta.stage2, 3);
}

table update_max_3_t
{
    reads {
        measurement_meta.flag2: ternary;
    }
    actions {
        update_max_3_action;
        nop;
    }
    default_action: nop;
    max_size: 1;
}

action copy_pkt_to_cpu_action()
{
    modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
    // modify_field(intrinsic_metadata.cos_for_copy_to_cpu, ...);
}

table copy_to_cpu_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.main_table_1_predicate: ternary;
        measurement_meta.main_table_2_predicate: ternary;
        measurement_meta.main_table_3_predicate: ternary;
    }
    actions {
        copy_pkt_to_cpu_action;
        nop;
    }
    default_action: nop;
    max_size: 4;
}

register ancillary_table
{
    width: 16;
    instance_count: ANCILLARY_TABLE_SIZE;
}

blackbox stateful_alu update_ancillary_table
{
    reg: ancillary_table;
    condition_lo: register_hi == 0;
    condition_hi: register_hi == measurement_meta.digest;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: 1;

    update_hi_1_value: measurement_meta.digest;

    output_predicate: condition_hi;
    output_value: register_lo;
    output_dst: measurement_meta.ac_flow_count;
}

action update_ancillary_table_action()
{
    update_ancillary_table.execute_stateful_alu_from_hash(hash_4);
}

table update_ancillary_table_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.main_table_1_predicate: exact;
        measurement_meta.main_table_2_predicate: exact;
        measurement_meta.main_table_3_predicate: exact;
    }
    actions {
        update_ancillary_table_action;
        nop;
    }
    default_action: nop;
    max_size: 1;
}

action min_value_subtract_pktcnt_a_action()
{
    subtract(measurement_meta.flag, measurement_meta.min_flow_count, measurement_meta.ac_flow_count);
}

table min_value_subtract_pktcnt_a_t
{
    reads {
        measurement_meta.ac_flow_count: exact;
    }
    actions {
        min_value_subtract_pktcnt_a_action;
        nop;
    }
    default_action: min_value_subtract_pktcnt_a_action;
    max_size: 1;
}

field_list recirculate_fields
{
    measurement_meta.promotion; //1-bit
    measurement_meta.stage; //4-bit
    measurement_meta.ac_flow_count; //32-bit
}

action cancel_recirc_action()
{
//    modify_field(measurement_meta.promotion, 1);
//    recirculate(recirculate_fields);
//	recirculate(68);
//	clone_egress_pkt_to_ingress(0, recirculate_fields);
	modify_field(standard_metadata.instance_type, PKT_INSTANCE_TYPE_NORMAL);
//	modify_field(standard_metadata.instance_type, 0);
}

table cancel_recirc_t
{
    reads {
        measurement_meta.ac_flow_count: range;
        measurement_meta.flag: ternary;
    }
    actions {
        cancel_recirc_action;//highest bit is 1;
        nop;
    }
    default_action: nop;
    max_size: 1;
}

control ingress
{
    apply(generate_fingerprint_t);
    apply(calc_digest_t);
	apply(recirc_tbl);
    apply(update_main_table_1_key_t);
//     {
//         update_main_table_1_key_action {
//             apply(copy_pkt_to_cpu_t_1);
//         }
//         rewrite_main_table_1_key_action {
//             apply(copy_pkt_to_cpu_t_2);
//         }
//     }
    apply(update_main_table_1_value_t)
    {
        read_main_table_1_value_action {
            apply(update_min_max_1_t);
        }
    }
    apply(update_main_table_2_key_t);
    // {
        // update_main_table_2_key_action {
        //     apply(copy_pkt_to_cpu_t_3);
        // }
        // rewrite_main_table_2_key_action {
        //     apply(copy_pkt_to_cpu_t_4);
        // }
    // }
    apply(update_main_table_2_value_t) 
	{
        read_main_table_2_value_action {
            apply(min_max_value_subtract_pktcnt_2_t);
            apply(update_min_2_t);
			apply(update_max_2_t);
        }
    }
    apply(update_main_table_3_key_t);
    // {
        // update_main_table_3_key_action {
        //     apply(copy_pkt_to_cpu_t_5);
        // }
        // rewrite_main_table_3_key_action {
        //     apply(copy_pkt_to_cpu_t_6);
        // }
    // }
    apply(update_main_table_3_value_t) {
        read_main_table_3_value_action {
            apply(min_max_value_subtract_pktcnt_3_t);
            apply(update_min_3_t);
            apply(update_max_3_t);
        }
    }
}

control egress
{
//    apply(copy_to_cpu_t);
    apply(update_ancillary_table_t)
	{
        update_ancillary_table_action {
            apply(min_value_subtract_pktcnt_a_t);
            apply(cancel_recirc_t);
        }
    }
    // apply(update_ancillary_table_key_t);
    // apply(update_ancillary_table_value_t) {
    //     update_ancillary_table_value_action {
    //         apply(min_value_subtract_pktcnt_a_t);
    //         apply(handle_recirculate_t);
    //     }
    // }
}
