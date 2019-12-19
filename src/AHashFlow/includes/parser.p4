#include "macro.p4"

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

