#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define IPV4_TCP 0x0006
#define IPV4_UDP 0x0011
#define UDP_RECORD_EXPORT 0x0017
#define UDP_PROMOTE 0x0018
#define TCP_RECORD_EXPORT 0x0020
#define TCP_PROMOTE 0x0021

parser start {
    return parse_ethernet;
}


parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
		ETHERTYPE_VLAN: parse_vlan;
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

parser parse_vlan {
	extract(vlan);
	return select(latest.etherType) {
//		ETHERTYPE_VLAN : parse_vlan;
		ETHERTYPE_IPV4 : parse_ipv4;
		default: ingress;
	}
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.proto){
        IPV4_TCP: parse_tcp;
		IPV4_UDP: parse_udp;
        default: ingress;
    }
}
parser parse_tcp {
    extract(tcp);
	return select(latest.srcport) {
		TCP_RECORD_EXPORT: parse_record_export;
		TCP_PROMOTE: parse_promote;
		default: ingress;
	}
}

parser parse_udp {
    extract(udp);
	return select(latest.sPort) {
		UDP_RECORD_EXPORT: parse_record_export;
		UDP_PROMOTE: parse_promote;
		default: ingress;
	}
}

parser parse_record_export {
	extract(record_export_header);
	return ingress;
}

parser parse_promote {
	extract(promote_header);
	return ingress;
}
