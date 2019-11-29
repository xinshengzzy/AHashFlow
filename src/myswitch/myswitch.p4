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
#include "tofino/pktgen_headers.p4"

header_type measurement_metadata_t {
    fields {
        flag : 1;
        ptr : 8;
        former_ancillary_table_entry_key: 32;
        former_ancillary_table_entry_value: 32;
        match_in_ancillary_table: 1;
        match_in_main_table: 4;
        replace_in_main_table: 4;
        ptr_for_back_writing: 8;
		temp: 16;
    }
}

metadata measurement_metadata_t measurement_meta;



action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action nop() {
}

register pktcnt1 {
	width: 32;
	instance_count: 10;
}

register pktcnt2 {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu incre_pktcnt_alu {
	reg: pktcnt1;
	update_lo_1_value: register_lo + 1;	
	update_hi_1_value: 5;
}

blackbox stateful_alu read_alu_1 {
	reg: pktcnt1;
	output_value: register_lo;
	output_dst: measurement_meta.temp;
}

blackbox stateful_alu read_alu_2 {
	reg: pktcnt2;
	output_value: register_lo;
	output_dst: measurement_meta.temp;
}

action action1() {
	read_alu_1.execute_stateful_alu(0);	
}

action action2() {
	read_alu_2.execute_stateful_alu(2);	
}

table table1 {
	actions {action1;}
}

table table2 {
	actions {action2;}
}

action m_action() {
	incre_pktcnt_alu.execute_stateful_alu(0);
}
table m_table {
	actions {m_action;}
}

table forward {
    reads {
        ig_intr_md.ingress_port: exact;
    }
    actions {
        set_egr; nop;
    }
}

control ingress {
//	apply(table1);
//    apply(forward);
//	apply(table2);
	if (0 == measurement_meta.flag) {
		apply(table1);
		apply(table2);
	}
	else {
		apply(table2);
		apply(table1);
	}
}

control egress {
}

