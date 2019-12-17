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
//		l3_len: 16;
		l4_len: 16;
		checksum: 16;
	}
}

metadata measurement_meta_t measurement_meta;

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

action update_headers_1() {
	add_header(udp);
	modify_field(ipv4.proto, IPV4_UDP);
	add(ipv4.totalLen, ipv4.totalLen, 8);
}

@pragma immediate 1
@pragma stage 3
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
	modify_field(udp.srcport, 79);
	modify_field(udp.dstport, 8082);
	modify_field(udp.checksum, 0);
	add(udp.hdr_length, ipv4.totalLen, -20);
}

@pragma immediate 1
@pragma stage 0
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

control ingress {
	if(valid(udp)){
		apply(update_headers_1_t);
	}
    apply(forward);
}

control egress {
	if(valid(udp)) {
		apply(update_headers_2_t);
	}
    apply(acl);
}

