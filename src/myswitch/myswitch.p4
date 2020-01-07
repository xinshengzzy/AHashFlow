// myswitch.p4
#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/pktgen_headers.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/wred_blackbox.p4>

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/macro.p4"




header_type export_promotion_meta_t {
	fields{
		srcip: 32;
		dstip: 32;
		proto: 8;
		srcport: 16;
		dstport: 16;
		ipv4_totalLen: 16;
		promotion_flag: 1;
		export_flag: 1;
		resubmit_flag: 1;
		temp: 32;
	}
}
metadata export_promotion_meta_t export_promotion_meta;

action add_export_header_ac() {
	config_export_header(export_promotion_meta.srcip, export_promotion_meta.dstip,
			export_promotion_meta.proto, export_promotion_meta.srcport,
			export_promotion_meta.dstport, 0x00000000);
	modify_field(export_header.m_table_1_idx, 0);
	modify_field(export_header.m_table_2_idx, 0);
	modify_field(export_header.m_table_3_idx, 0);
	add_header(export_header);
	add(ipv4.totalLen, ipv4.totalLen, EXPORT_HEADER_LEN);
	add(udp.totalLen, udp.totalLen, EXPORT_HEADER_LEN);
	modify_field(udp.srcport, UDP_EXPORT);
	recirculate(68);
}

table add_export_header_t {
	actions {
		add_export_header_ac;
	}
	default_action: add_export_header_ac;
}

////////// for the useage of testing //////////
register cntr1 {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu update_cntr1 {
	reg: cntr1;
	update_lo_1_value: register_lo + 1;
}

action update_cntr1_action() {
	update_cntr1.execute_stateful_alu(0);
}


table update_cntr1_t {
	actions {
		update_cntr1_action;
	}
	default_action: update_cntr1_action;
}

register cntr2 {
	width: 32;
	instance_count: 10;
}

blackbox stateful_alu update_cntr2 {
	reg: cntr2;
	update_lo_1_value: register_lo + 1;
}

action update_cntr2_action() {
	update_cntr2.execute_stateful_alu(0);
}

table update_cntr2_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		update_cntr2_action;
		nop;
	}
	default_action: nop;
}
////////// end the test //////////

action set_egr(egress_spec) {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
	modify_field_rng_uniform(export_promotion_meta.temp, 0, 5);
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

action config_export_header(srcip, dstip, proto, srcport, dstport, fingerprint) {
	modify_field(export_header.srcip, srcip);
	modify_field(export_header.dstip, dstip);
	modify_field(export_header.proto, proto);
	modify_field(export_header.srcport, srcport);
	modify_field(export_header.dstport, dstport);
	modify_field(export_header.fingerprint, fingerprint);
}

action export() {
	modify_field(ipv4.srcip, CTRL_SRC_IP);
	modify_field(ipv4.dstip, CTRL_IP);
	modify_field(udp.dstport, CTRL_PORT);
	modify_field(udp.checksum, 0);
	modify_field(export_header.fingerprint, ig_intr_md.ingress_port);
	update_cntr1_action();
}

table export_t {
	reads {
		ipv4.srcip: exact;
		ipv4.dstip: exact;
	}
	actions {
		nop;
		export;
	}	
	default_action: nop;
}

control myswitch
{
	if(valid(export_header)) {
		apply(export_t);
	}
	else {
		apply(add_export_header_t);
	}
	apply(update_cntr2_t);
}

control ingress {
	apply(forward);
//	if(valid(udp) or valid(tcp)) {
//		myswitch();
//	}
}
control egress
{

}
