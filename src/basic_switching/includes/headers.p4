header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

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
header ipv4_t ipv4;

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
        sPort : 16;
        dPort : 16;
        hdr_length : 16;
        checksum : 16;
    }
}
header udp_t udp;

header_type promote_header_t {
    fields {
		fingerprint: 32;
		idx: 32;
		cnt: 32;
		promoteType: 8;
		m_table_id: 8;
    }
}
header promote_header_t promote_header;


header_type record_export_header_t {
    fields {
		fingerprint: 32;
		cnt: 32;
		exportType: 8;
    }
}
header record_export_header_t record_export_header;

header_type id_export_header_t {
    fields {
		srcip: 32;
		dstip: 32;
		srcport: 16;
		dstport: 16;
		proto: 8;
		exportType: 8;
    }
}
header id_export_header_t id_export_header;

header_type vlan_tag_t {
	fields {
		pcp : 3;
		cfi : 1;
		vid : 12;
		etherType : 16;
	}
}

header vlan_tag_t vlan;
