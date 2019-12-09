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
	}
}

metadata measurement_meta_t measurement_meta;

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
	modify_field(ig_intr_md_for_tm.copy_to_cpu, 1);
}

table update_cntr1_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
//		ethernet.etherType: exact;
	}
	actions {
		update_cntr1_action;
		nop;
	}
	default_action: nop;
	size: 10;
}

register cntr2 {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu update_cntr2 {
	reg: cntr2;
	update_lo_1_value: register_lo + 1;

	output_dst: measurement_meta.index;
	output_value: register_lo;
}

action update_cntr2_action() {
	update_cntr2.execute_stateful_alu();
}

table update_cntr2_t {
	actions {
		update_cntr2_action;
	}
	default_action: update_cntr2_action;
	size: 10;
}

register cntr3 {
	width: 32;
	instance_count: 1000;
}

blackbox stateful_alu update_cntr3 {
	reg: cntr3;
	update_lo_1_value: ethernet.etherType;
}

action update_cntr3_action() {
	update_cntr3.execute_stateful_alu(measurement_meta.index);
}

table update_cntr3_t {
	actions {
		update_cntr3_action;
	}
	default_action: update_cntr3_action;
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

control ingress {
	apply(update_cntr1_t);
	apply(update_cntr2_t);
	apply(update_cntr3_t);
    apply(forward);
}

control egress {
    apply(acl);
}

