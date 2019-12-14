/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This is P4 sample source for basic_switching

#include "includes/headers.p4"
#include "includes/parser.p4"
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include "tofino/stateful_alu_blackbox.p4"

header_type measurement_meta_t {
	fields {
		index: 32;
		export_flag: 1;
		l3_len: 16;
		l4_len: 16;
		zero: 8;
		checksum: 16;
		proto: 16;
	}
}

metadata measurement_meta_t measurement_meta;


action calc_checksum_action()
{
    modify_field_with_hash_based_offset(measurement_meta.checksum, 0,
        udp_checksum2, 65536);
}

@pragma stage 1
table calc_checksum_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		calc_checksum_action;
		nop;
	}
	default_action: nop;
}

register checksum1 {
	width: 16;
	instance_count: 10;
}

blackbox stateful_alu update_checksum1 {
	reg: checksum1;
	update_lo_1_value: measurement_meta.checksum;
}

action update_checksum1_action() {
	update_checksum1.execute_stateful_alu(0);
//	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
}

@pragma stage 2
table update_checksum1_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		update_checksum1_action;
		nop;
	}
	default_action: nop;
}

register checksum2 {
	width: 16;
	instance_count: 10;
}

blackbox stateful_alu update_checksum2 {
	reg: checksum2;
	update_lo_1_value: udp.checksum;
}

action update_checksum2_action() {
	update_checksum2.execute_stateful_alu(0);
//	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
}

@pragma stage 2
table update_checksum2_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		update_checksum2_action;
		nop;
	}
	default_action: nop;
}

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
//	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
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

register cntr2 {
	width: 16;
	instance_count: 10;
}

blackbox stateful_alu update_cntr2 {
	reg: cntr2;
	update_lo_1_value: measurement_meta.l3_len;
//	output_dst: measurement_meta.index;
//	output_value: register_lo;
}

action update_cntr2_action() {
	update_cntr2.execute_stateful_alu(0);
}

@pragma stage 1
table update_cntr2_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
//		ethernet.etherType: exact;
	}
	actions {
		update_cntr2_action;
		nop;
	}
	default_action: nop;
	size: 10;
}

register cntr3 {
	width: 16;
	instance_count: 1000;
}

blackbox stateful_alu update_cntr3 {
	reg: cntr3;
	update_lo_1_value: measurement_meta.l4_len;
//	update_lo_1_value: 5000;
//	update_hi_1_value: 200;
}

action update_cntr3_action() {
	update_cntr3.execute_stateful_alu(0);
}

@pragma stage 1
table update_cntr3_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
//		ethernet.etherType: exact;
	}
	actions {
		update_cntr3_action;
		nop;
	}
	default_action: nop;
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action nop() {
}

action _drop() {
    drop();
}

table forward {
    reads {
		ig_intr_md.ingress_port: exact;
    }
    actions {
        set_egr; nop;
    }
}

table acl {
    reads {
        ethernet.dstAddr : ternary;
        ethernet.srcAddr : ternary;
    }
    actions {
        nop;
        _drop;
    }
}

register cntr4 {
	width: 16;
	instance_count: 10;
}

blackbox stateful_alu update_cntr4 {
	reg: cntr4;
	update_lo_1_value: register_lo + 1;
}

action export() {
	update_cntr4.execute_stateful_alu(0);
//	modify_field(ipv4.dstip, 167772171);
//	modify_field(ipv4.proto, 0x0011);
//	add_header(udp);
//	modify_field(udp.srcport, 0x0017);
	modify_field(udp.dstport, 8081);
//	add(measurement_meta.l4_len, ipv4.totalLen, -20);
	modify_field(measurement_meta.l3_len, ipv4.totalLen);
	modify_field(measurement_meta.zero, 0);
	modify_field(measurement_meta.proto, ipv4.proto);
	modify_field(measurement_meta.l4_len, udp.hdr_length);
//	modify_field(measurement_meta.export_flag, 1);
//	add_header(export_header);
//	modify_field(export_header.fingerprint, 100);	
//	modify_field(export_header.cnt, 101);
//	modify_field(export_header.srcip, 102);
//	modify_field(export_header.dstip, 103);
//	modify_field(export_header.srcport, 104);
//	modify_field(export_header.dstport, 105);
//	modify_field(export_header.proto, 106);
}

@pragma stage 0
table export_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
//		udp: valid;
	}
	actions {
		export;
		nop;
	}
	default_action: nop;
	size: 10;
}

control ingress {
	if(valid(udp)){
		apply(export_t);
		apply(update_cntr1_t);
		apply(update_cntr2_t);
		apply(update_cntr3_t);
//		apply(calc_checksum_t);
//		apply(update_checksum1_t);
//		apply(update_checksum2_t);
	}
//	apply(update_cntr1_t);
//	apply(update_cntr2_t);
    apply(forward);
}

control egress {
    apply(acl);
}

