#define ETHERTYPE_IPV4 0x0800
#define IPV4_TCP 0x0006
#define IPV4_UDP 0x0011
#define IPV4_ID_EXPORT 0x0012
#define IPV4_RECORD_EXPORT 0x0013
#define IPV4_PROMOTE 0x0014
#define ID_RECORD_EXPORT 0x0015
#define ID_EXPORT_UDP 0x0016
#define RECORD_EXPORT_UDP 0x0017
#define PROMOTE_UDP 0x0018
#define ID_EXPORT_TCP 0x0019
#define RECORD_EXPORT_TCP 0x0020
#define PROMOTE_TCP 0x0021

parser start {
    return parse_ethernet;
}


parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
//  return parse_ipv4;
}

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

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.proto){
        IPV4_TCP: parse_tcp;
		IPV4_UDP: parse_udp;
		IPV4_ID_EXPORT: parse_id_export;
		IPV4_RECORD_EXPORT: parse_record_export;
		IPV4_PROMOTE: parse_promote;	
        default: ingress;
    }
}

parser parse_id_export {
	extract(id_export_header);
	return select(latest.exportType) {
		ID_RECORD_EXPORT: parse_record_export;
		ID_EXPORT_UDP: parse_udp;
		ID_EXPORT_TCP: parse_tcp;
		default: ingress;
	}
}

parser parse_record_export {
	extract(record_export_header);
	return select(latest.exportType) {
		RECORD_EXPORT_UDP: parse_udp;
		RECORD_EXPORT_TCP: parse_tcp;
		default: ingress;
	}
}

parser parse_promote {
	extract(promote_header);
	return select(latest.promoteType) {
		PROMOTE_UDP: parse_udp;
		PROMOTE_TCP: parse_tcp;
		default: ingress;
	}
}


parser parse_tcp {
    extract(tcp);
    return ingress;
}
