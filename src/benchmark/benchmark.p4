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
    export_meta.srcport;
    export_meta.dstport;
}

// hash function for main_table_1 and fingerprint generation
field_list_calculation hash_1 {
    input {
        flow;
    }
    algorithm: crc32;
    output_width: HASH_TABLE_IDX_WIDTH;
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
        fingerprint: 32; // fingerprint for 5-tuple;
		evicted_fingerprint: 32;
		evicted_count: 32;
		minus_ef: 32; // minus_ef = 0 - evicted_fingerprint
		minus_ec: 32; // minus_ec = 0 - evicted_count
		diff: 32; // diff = evicted_count - THRESH
		ipv4_totalLen: 16;
		ipv4_proto: 8;
    }
}

metadata measurement_meta_t measurement_meta;


header_type export_meta_t {
	fields{
		srcport: 16;
		dstport: 16;
	}
}
metadata export_meta_t export_meta;

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

// register for storing key of the first main sub table 1
register hash_table_key
{
    width: 32;
    instance_count: HASH_TABLE_SIZE;
}

blackbox stateful_alu update_ht_key
{
    reg: hash_table_key;
    condition_lo: register_lo == 0;
    condition_hi: register_lo == measurement_meta.fingerprint;

    update_lo_1_value: measurement_meta.fingerprint;
	
	output_predicate: not condition_lo and not condition_hi;
    output_value: register_lo;
    output_dst: measurement_meta.evicted_fingerprint;
}

action update_ht_key_action()
{
    update_ht_key.execute_stateful_alu_from_hash(hash_1);
}

@pragma stage 1
table update_ht_key_t
{
    actions {
        update_ht_key_action;
    }
    default_action: update_ht_key_action;
}

register hash_table_value
{
    width: 32;
    instance_count: HASH_TABLE_SIZE;
}

blackbox stateful_alu update_ht_value
{
    reg: hash_table_value;
	condition_lo: 0 == measurement_meta.evicted_fingerprint;
	update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo + 1;
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value: 1;
	output_value: register_lo;
	output_dst: measurement_meta.evicted_count;
}

action update_ht_value_action()
{
    update_ht_value.execute_stateful_alu_from_hash(hash_1);
}

@pragma stage 2
table update_ht_value_t
{
    actions {
        update_ht_value_action;
    }
	default_action: update_ht_value_action;
}

action subtract_action() {
	subtract(measurement_meta.diff, measurement_meta.evicted_count, THRESH);
	subtract(measurement_meta.minus_ef, 0, measurement_meta.evicted_fingerprint);
	subtract(measurement_meta.minus_ec, 0, measurement_meta.evicted_count);
}

@pragma stage 3
table subtract_t {
	actions {
		subtract_action;
	}
	default_action: subtract_action;
}

action rmv_tcp_add_udp() {
	remove_header(tcp);
	add_header(udp);
	add(ipv4.totalLen, measurement_meta.ipv4_totalLen, -12);
	modify_field(ipv4.proto, IPV4_UDP);
	add(udp.totalLen, measurement_meta.ipv4_totalLen, -32);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.dstport, CTRL_PORT);
	modify_field(udp.checksum, 0);
}

@pragma stage 4
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

action config_flow_id() {
	modify_field(export_header.srcip, ipv4.srcip);
	modify_field(export_header.dstip, ipv4.dstip);
	modify_field(export_header.proto, ipv4.proto);
	modify_field(export_header.srcport, export_meta.srcport);
	modify_field(export_header.dstport, export_meta.dstport);
}

action config_flow_record() {
	modify_field(export_header.fingerprint, measurement_meta.evicted_fingerprint);	
	modify_field(export_header.cnt, measurement_meta.evicted_count);
}

action add_export_header() {
	add_header(export_header);
	add(ipv4.totalLen, ipv4.totalLen, EXPORT_HEADER_LEN);
	add(udp.totalLen, udp.totalLen, EXPORT_HEADER_LEN);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.dstport, CTRL_PORT);
	modify_field(udp.checksum, 0);
}

action export_flow_id() {
	config_flow_id();
	add_export_header();
}

action export_flow_id_record() {
	config_flow_id();
	config_flow_record();
	add_export_header();
}

@pragma stage 5
table export_t {
	reads {
		measurement_meta.minus_ef mask 0x80000000: exact;
		measurement_meta.minus_ec mask 0x80000000: exact;
		measurement_meta.diff mask 0x80000000: exact;
		/*minus_ef		minus_ec	diff		action
		 *0x00000000	0x00000000	0x00000000	NONE
		 *0x00000000	0x00000000	0x80000000	export_flow_id
		 *0x00000000	0x80000000	0x00000000	do_drop
		 *0x00000000	0x80000000	0x80000000	do_drop
		 *0x80000000	0x00000000	0x00000000	NONE
		 *0x80000000	0x00000000	0x80000000	NONE
		 *0x80000000	0x80000000	0x00000000	export_flow_id_record
		 *0x80000000	0x80000000	0x80000000	do_drop
		 * */
	}
	actions {
		do_drop;
		export_flow_id;
		export_flow_id_record;
	}	
	default_action: do_drop;
}

control TurboFlow
{
	// stage 0
	apply(generate_fingerprint_t);
	// stage 1
	apply(update_ht_key_t);
	// stage 2
	apply(update_ht_value_t);
	// stage 3
	apply(subtract_t);
	if(valid(tcp)) {
		// stage 4
		apply(rmv_tcp_add_udp_t);
	}
	// stage 5
	apply(export_t);
}

control ingress {
	apply(forward);
	if(valid(udp) or valid(tcp)) {
		TurboFlow();
	}
}
control egress
{

}
