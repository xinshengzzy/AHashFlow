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
		update_udp_flag: 1;
		l4_len: 16;
		clone_a: 16;
		clone_b: 16;
		clone_c: 16;
		ipv4_totalLen: 16;
	}
}

metadata measurement_meta_t measurement_meta;


field_list clone_fields {
	measurement_meta.clone_a;
	measurement_meta.clone_b;
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

action remove() {
	remove_header(tcp);
	add_header(udp);
	add(ipv4.totalLen, measurement_meta.ipv4_totalLen, -12);
	modify_field(ipv4.proto, IPV4_UDP);
	add(udp.totalLen, measurement_meta.ipv4_totalLen, -12);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.dstport, 8082);
	modify_field(udp.checksum, 0);
//	add(udp.totalLen, measurement_meta.ipv4_totalLen, -32);
}

table remove_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		remove;
		nop;
	}
	default_action: nop;
}

action set_udp_length() {
	add_header(udp);
	modify_field(ipv4.proto, IPV4_UDP);
	add(udp.totalLen, ipv4.totalLen, -20);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.dstport, 8082);
	modify_field(udp.checksum, 0);
}

table set_udp_length_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		set_udp_length;
		nop;
	}
	default_action: nop;
}

action add_hdr() {
	add_header(udp);
	add(ipv4.totalLen, ipv4.totalLen, 8);
	modify_field(ipv4.proto, IPV4_UDP);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.dstport, 8082);
}

table add_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		add_hdr;
		nop;
	}
	default_action: nop;
}

action update_headers_1() {
//	clone_ingress_pkt_to_egress(udp_checksum_list);
	add_header(export_header);
	add(ipv4.totalLen, ipv4.totalLen, EXPORT_HEADER_LEN);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.checksum, 0);
}

table update_headers_1_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		update_headers_1;
		nop;
	}
	default_action: nop;
}

action update_headers_2 () {
	add(udp.totalLen, ipv4.totalLen, -20);
	modify_field(measurement_meta.update_udp_flag, 0);
	modify_field(export_header.fingerprint, 0x67686970);	
	modify_field(export_header.cnt, 0x67686970);
	modify_field(export_header.srcip, 0x67686970);
	modify_field(export_header.dstip, 0x67686970);
	modify_field(export_header.srcport, 0x6768);
	modify_field(export_header.dstport, 0x6768);
	modify_field(export_header.proto, 0x67);
	modify_field(export_header.padding, 0x67);
	modify_field(measurement_meta.l4_len, 0);
}

table update_headers_2_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		update_headers_2;
		nop;
	}
	default_action: nop;
}

register cntr1 {
	width: 32;
	instance_count: 10;	   
}

blackbox stateful_alu update_cntr1_bb {
	reg: cntr1;
	update_lo_1_value: register_lo + 1;
}

action update_cntr1() {
	update_cntr1_bb.execute_stateful_alu(0);
}

table update_cntr1_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		update_cntr1;
		nop;
	}
	default_action: nop;
}

action do_resubmit() {
	resubmit();
}

table resubmit_t {
	actions {
		do_resubmit;
	}
	default_action: do_resubmit;
}

action clone() {
	clone_ingress_pkt_to_egress(measurement_meta.clone_c, clone_fields);
}

table clone_t {
	actions {
		clone;
	}
	default_action: clone;
}

control ingress {
	apply(forward);
//	apply(clone_t);
	if(valid(tcp)) {
		apply(remove_t);
//		apply(set_udp_length_t);
//		apply(add_t);
		apply(update_headers_1_t);
		apply(update_headers_2_t);
		apply(update_cntr1_t);
	}
	if(0 == ig_intr_md.resubmit_flag) {
		apply(resubmit_t);
	}
}

control egress {
    apply(acl);
}

