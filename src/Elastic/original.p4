#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/pktgen_headers.p4"
#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>

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
        promotion: 1; // indicating variable for resubmit;
        stage: 4; // indicating variable for stage of back inserting;
        digest: 8; // digest for differentiating in ancillary table;
        ac_flow_count: 8; // temp storage for flow count of ancillary table;
        flag: 32;
        fingerprint: 32; // fingerprint for 5-tuple;
        min_flow_count: 32; // minimum flow count of all 3 sub tables of main table;
        temp_flow_count: 32; // temp storage for flow count of the current sub table;
        temp_flow_count_2: 32; // temp storage for flow count of the current sub table;
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

action calc_digest_action()
{
    modify_field_with_hash_based_offset(measurement_meta.digest, 0,
        digest_hash, 256);
}

table calc_digest_t
{
    actions {
        calc_digest_action;
    }
    default_action: calc_digest_action;
}

// register for storing key and value of sub table 1, hi: fingerprint, lo: count;
register main_table_1
{
    width: 64;
    instance_count: SUB_TABLE_A_SIZE;
}

blackbox stateful_alu update_main_table_1_entry
{
    reg: main_table_1;
    condition_lo: register_hi == 0;
    condition_hi: register_hi == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: register_lo;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: measurement_meta.fingerprint;
    update_hi_2_predicate: not condition_lo and not condition_hi;
    update_hi_2_value: register_hi;

    output_predicate: not condition_lo and not condition_hi;
    output_value: register_lo;
    output_dst: measurement_meta.min_flow_count;
}

action update_main_table_1_entry_action()
{
    update_main_table_1_entry.execute_stateful_alu_from_hash(hash_1);
}

blackbox stateful_alu rewrite_main_table_1_entry
{
    reg: main_table_1;
    update_lo_1_value: measurement_meta.ac_flow_count + 1;
    update_hi_1_value: measurement_meta.fingerprint;
}

action rewrite_main_table_1_entry_action()
{
    rewrite_main_table_1_entry.execute_stateful_alu_from_hash(hash_1);
}

table update_main_table_1_entry_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: exact;
    }
    actions {
        update_main_table_1_entry_action;
        rewrite_main_table_1_entry_action;
        nop;
    }
}

action update_min_1_action()
{
    modify_field(measurement_meta.stage, 1);
}

// if mismatch happen in sub table 1, considering that min_flow_count has been recorded,
// we update the stage into 1 in this table for future resubmit;
table update_min_1_t
{
    reads {
        measurement_meta.min_flow_count: exact;
    }
    actions {
        update_min_1_action;
        nop;
    }
}

register main_table_2
{
    width: 64;
    instance_count: SUB_TABLE_B_SIZE;
}

blackbox stateful_alu update_main_table_2_entry
{
    reg: main_table_2;
    condition_lo: register_hi == 0;
    condition_hi: register_hi == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: register_lo;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: measurement_meta.fingerprint;
    update_hi_2_predicate: not condition_lo and not condition_hi;
    update_hi_2_value: register_hi;

    output_predicate: not condition_lo and not condition_hi;
    output_value: register_lo;
    output_dst: measurement_meta.temp_flow_count;
}

action update_main_table_2_entry_action()
{
    update_main_table_2_entry.execute_stateful_alu_from_hash(hash_2);
}

blackbox stateful_alu rewrite_main_table_2_entry
{
    reg: main_table_2;
    update_lo_1_value: measurement_meta.ac_flow_count + 1;
    update_hi_1_value: measurement_meta.fingerprint;
}

action rewrite_main_table_2_entry_action()
{
    rewrite_main_table_2_entry.execute_stateful_alu_from_hash(hash_2);
}

table update_main_table_2_entry_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: exact;
        measurement_meta.min_flow_count: exact;
    }
    actions {
        update_main_table_2_entry_action;
        rewrite_main_table_2_entry_action;
        nop;
    }
}

action min_value_subtract_pktcnt_2_action()
{
    subtract(measurement_meta.flag, measurement_meta.min_flow_count, measurement_meta.temp_flow_count);
}

// when mismatch happen in sub table 2, we need to compare two flow count form sub table 1 and sub table 2
table min_value_subtract_pktcnt_2_t
{
    reads {
        measurement_meta.temp_flow_count: exact;
    }
    actions {
        min_value_subtract_pktcnt_2_action;
        nop;
    }
}

action update_min_2_action()
{
    modify_field(measurement_meta.min_flow_count, measurement_meta.temp_flow_count);
    modify_field(measurement_meta.stage, 2);
}

// update the min flow count according to compare result
table update_min_2_t
{
    reads {
        measurement_meta.temp_flow_count: exact;
        measurement_meta.flag: ternary;
    }
    actions {
        update_min_2_action;
        nop;
    }
}

register main_table_3
{
    width: 64;
    instance_count: SUB_TABLE_C_SIZE;
}

blackbox stateful_alu update_main_table_3_entry
{
    reg: main_table_3;
    condition_lo: register_hi == 0;
    condition_hi: register_hi == measurement_meta.fingerprint;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate: not condition_lo and not condition_hi;
    update_lo_2_value: register_lo;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: measurement_meta.fingerprint;
    update_hi_2_predicate: not condition_lo and not condition_hi;
    update_hi_2_value: register_hi;

    output_predicate: not condition_lo and not condition_hi;
    output_value: register_lo;
    output_dst: measurement_meta.temp_flow_count_2;
}

action update_main_table_3_entry_action()
{
    update_main_table_3_entry.execute_stateful_alu_from_hash(hash_3);
}

blackbox stateful_alu rewrite_main_table_3_entry
{
    reg: main_table_3;
    update_lo_1_value: measurement_meta.ac_flow_count + 1;
    update_hi_1_value: measurement_meta.fingerprint;
}

action rewrite_main_table_3_entry_action()
{
    rewrite_main_table_3_entry.execute_stateful_alu_from_hash(hash_3);
}

table update_main_table_3_entry_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.stage: exact;
        measurement_meta.temp_flow_count: exact;
    }
    actions {
        update_main_table_3_entry_action;
        rewrite_main_table_3_entry_action;
        nop;
    }
}

action min_value_subtract_pktcnt_3_action()
{
    subtract(measurement_meta.flag, measurement_meta.min_flow_count, measurement_meta.temp_flow_count_2);
}

table min_value_subtract_pktcnt_3_t
{
    reads {
        measurement_meta.temp_flow_count_2: exact;
    }
    actions {
        min_value_subtract_pktcnt_3_action;
        nop;
    }
}

action update_min_3_action()
{
    modify_field(measurement_meta.min_flow_count, measurement_meta.temp_flow_count_2);
    modify_field(measurement_meta.stage, 3);
}

table update_min_3_t
{
    reads {
        measurement_meta.temp_flow_count_2: exact;
        measurement_meta.flag: ternary;
    }
    actions {
        update_min_3_action;
        nop;
    }
}

register ancillary_table
{
    width: 16;
    instance_count: ANCILLARY_TABLE_SIZE;
}

blackbox stateful_alu update_ancillary_table_entry
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

action update_ancillary_table_entry_action()
{
    update_ancillary_table_entry.execute_stateful_alu_from_hash(hash_4);
}

table update_ancillary_table_entry_t
{
    reads {
        measurement_meta.promotion: exact;
        measurement_meta.temp_flow_count_2: exact;
    }
    actions {
        update_ancillary_table_entry_action;
        nop;
    }
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
}

field_list resubmit_fields
{
    measurement_meta.promotion; //1-bit
    measurement_meta.stage; //4-bit
    measurement_meta.ac_flow_count; //32-bit
}

action resubmit_action()
{
    modify_field(measurement_meta.promotion, 1);
    resubmit(resubmit_fields);
}

table handle_resubmit_t
{
    reads {
        measurement_meta.ac_flow_count: exact;
        measurement_meta.flag: ternary;
    }
    actions {
        resubmit_action;
        nop;
    }
}


// <=========================================  MAIN LOOP ====================================================> //

control ingress
{
    apply(generate_fingerprint_t);
    apply(calc_digest_t);
    apply(update_main_table_1_entry_t) {
        update_main_table_1_entry_action {
            apply(update_min_1_t);
        }
    }
    apply(update_main_table_2_entry_t) {
        update_main_table_2_entry_action {
            apply(min_value_subtract_pktcnt_2_t);
            apply(update_min_2_t);
        }
    }
    apply(update_main_table_3_entry_t) {
        update_main_table_3_entry_action {
            apply(min_value_subtract_pktcnt_3_t);
            apply(update_min_3_t);
        }
    }
    apply(update_ancillary_table_entry_t) {
        update_ancillary_table_entry_action {
            apply(min_value_subtract_pktcnt_a_t);
            apply(handle_resubmit_t);
        }
    }
}

control egress
{
    // no table applied
}

