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

register cntr {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu update_cntr {
	reg: cntr;
	update_lo_1_value: register_lo + 1;
}

action update_cntr_action() {
	update_cntr.execute_stateful_alu(0);
}

table update_cntr_t {
	actions {
		update_cntr_action;
	}
	default_action: update_cntr_action;
	size: 1;
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
        ethernet.dstAddr : exact;
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
	apply(update_cntr_t);
    apply(forward);
}

control egress {
    apply(acl);
}

