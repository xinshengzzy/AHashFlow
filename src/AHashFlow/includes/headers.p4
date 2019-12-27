header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

header_type vlan_tag_t {
	fields {
		pcp : 3;
		cfi : 1;
		vid : 12;
		etherType : 16;
	}
}

header vlan_tag_t vlan;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        proto : 8;
        hdrChecksum : 16;
        srcip : 32;
        dstip: 32;
    }
}

//@pragma pa_fragment ingress ipv4.hdrChecksum
//@pragma pa_fragment egress ipv4.hdrChecksum
header ipv4_t ipv4;

field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.proto;
    ipv4.srcip;
    ipv4.dstip;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

header_type tcp_t {
    fields {
        srcport : 16;
        dstport : 16;
        seqNo: 32;
        ackNo: 32;
        dataOffset: 4;
        res: 4;
        flags: 8;
        window: 16;
        checksum: 16;
        urgentPtr: 16;
    }
}
header tcp_t tcp;

header_type udp_t {
    fields {
        srcport : 16;
        dstport : 16;
        totalLen : 16;
        checksum : 16;
    }
}

//@pragma pa_fragment egress udp.checksum
header udp_t udp;

/*
field_list udp_checksum_list {
    ipv4.srcip;
    ipv4.dstip;
    8'0;
    ipv4.proto;
    measurement_meta.l4_len;
    udp.srcport;
    udp.dstport;
    udp.totalLen;
    payload;
}

field_list_calculation udp_checksum {
    input {
        udp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field udp.checksum {
    update udp_checksum if (measurement_meta.update_udp_flag == 1);
}*/

header_type promote_header_t {
    fields {
		fingerprint: 32;
//		fingerprint: 16;
		cnt: 32;
//		cnt: 16;
		idx: 32;
//		idx: 16;
		srcip: 32;
//		srcip: 16;
		dstip: 32;
		srcport: 16;
		dstport: 16;
		next_header: 8;
		proto: 8;
		m_table_id: 4;
		padding: 12;
    }
}
header promote_header_t promote_header;


header_type export_header_t {
	fields {
		fingerprint: 32;
		cnt: 32;
		srcip: 32;
		dstip: 32;
		srcport: 16;
		dstport: 16;
		proto: 8;
		padding: 8;
	}
}

header export_header_t export_header;
