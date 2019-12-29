// myswitch.p4
#include "includes/headers.p4"
#include "includes/parser.p4"
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include "tofino/stateful_alu_blackbox.p4"


action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action nop() {
}

table forward {
    reads {
		ig_intr_md.ingress_port: exact;
    }
    actions {
        set_egr; nop;
    }
}


action export() {
	//////////
//	modify_field(export_header.fingerprint, 0x01);
//	modify_field(export_header.cnt, 0x00);
	modify_field(export_header.srcip, 0x11);
	modify_field(export_header.dstip, 0x21);
	modify_field(export_header.srcport, 0x41);
	modify_field(export_header.dstport, 0x51);
	modify_field(export_header.proto, 0x31);
//	modify_field(export_header.padding, 0);
	/////////
	add_header(export_header);
	add(ipv4.totalLen, ipv4.totalLen, EXPORT_HEADER_LEN);
	add(udp.totalLen, udp.totalLen, EXPORT_HEADER_LEN);
	modify_field(ipv4.srcip, CTRL_SRC_IP);
	modify_field(ipv4.dstip, CTRL_IP);
	modify_field(udp.srcport, UDP_EXPORT);
	modify_field(udp.dstport, CTRL_PORT);
	modify_field(udp.checksum, 0);
}

table export_t {
//	reads {
//		ipv4.srcip: exact;
//		ipv4.dstip: exact;
//	}
	actions {
//		nop;
		export;
	}	
	default_action: export;
}
control ingress {
	apply(forward);
	if(valid(udp)) {
		apply(export_t);
	}
}

control egress {
}

