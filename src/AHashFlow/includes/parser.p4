// parser.p4
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

@pragma pack 4
parser parse_ipv4 {
    extract(ipv4);
	set_metadata(export_promotion_meta.ipv4_totalLen, ipv4.totalLen);
	set_metadata(export_promotion_meta.proto, ipv4.proto);
	set_metadata(export_promotion_meta.srcip, ipv4.srcip);
	set_metadata(export_promotion_meta.dstip, ipv4.dstip);
    return select(latest.proto){
		IPV4_PROMOTION: parse_promote_header;
        IPV4_TCP: parse_tcp;
		IPV4_UDP: parse_udp;
        default: ingress;
    }
}

parser parse_promote_header {
	extract(promote_header);
	return select(latest.next_header){
        PROMOTE_TCP: parse_tcp;
		PROMOTE_UDP: parse_udp;
        default: ingress;
	}
}

parser parse_tcp {
    extract(tcp);
	set_metadata(export_promotion_meta.srcport, tcp.srcport);
	set_metadata(export_promotion_meta.dstport, tcp.dstport);
	return ingress;
}

parser parse_udp {
    extract(udp);
	set_metadata(export_promotion_meta.srcport, udp.srcport);
	set_metadata(export_promotion_meta.dstport, udp.dstport);
	return select(latest.srcport) {
		UDP_EXPORT: parse_export_header;
		default: ingress;
	}
}

parser parse_export_header {
	extract(export_header);
	return ingress;
}

