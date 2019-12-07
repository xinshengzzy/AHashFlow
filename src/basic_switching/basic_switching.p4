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
		cntr3: 16;
		cntr4: 16;
		predicate: 8;
    }
}

metadata measurement_meta_t measurement_meta;

header_type my_header_t {
    fields {
        cnt: 16;
        idx: 16;
        etherType : 16;
    }
}

header my_header_t my_header;

register cntr3 {
	width: 16;
	instance_count: 10;
}

blackbox stateful_alu update_cntr3 {
	reg: cntr3;
	condition_lo: register_lo == 0;
	condition_hi: register_hi == 0;
	update_lo_1_value: 0;
	
	output_value: predicate;
	output_dst: measurement_meta.predicate;
}

action update_cntr3_action() {
	update_cntr3.execute_stateful_alu(0);
}

//@pragma stage 2
table update_cntr3_t {
	actions {
		update_cntr3_action;
	}
	default_action: update_cntr3_action;
	size: 4;
}

register cntr4 {
	width: 8;
	instance_count: 10;
}

blackbox stateful_alu update_cntr4 {
	reg: cntr4;
	update_lo_1_value: measurement_meta.predicate;
}

action update_cntr4_action() {
	update_cntr4.execute_stateful_alu(0);
}

@pragma stage 3
table update_cntr4_t {
	actions {
		update_cntr4_action;
	}
	default_action: update_cntr4_action;
	size: 4;
}
control ingress {
	apply(update_cntr3_t);
	apply(update_cntr4_t);
}

control egress {
}

