#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define IPV4_TCP 0x0006
#define IPV4_UDP 0x0011
#define UDP_EXPORT 0x0017
#define UDP_PROMOTE 0x0018
#define TCP_PROMOTE 0x0021
#define EXPORT_HEADER_LEN 22

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
}

parser parse_vlan {
	extract(vlan);
	return select(latest.etherType) {
		ETHERTYPE_IPV4 : parse_ipv4;
		default: ingress;
	}
}

parser parse_ipv4 {
    extract(ipv4);
	set_metadata(measurement_meta.ipv4_totalLen, ipv4.totalLen);
    return select(latest.proto){
        IPV4_TCP: parse_tcp;
		IPV4_UDP: parse_udp;
        default: ingress;
    }
}
parser parse_tcp {
    extract(tcp);
	return ingress;
}

parser parse_udp {
    extract(udp);
	return select(latest.srcport) {
		UDP_EXPORT: parse_export_header;
		default: ingress;
	}
}

parser parse_export_header {
	extract(export_header);
	return ingress;
}
