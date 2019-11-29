parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800
#define IPV4_TCP 0x0006
#define IPV4_UDP 0x0011

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
//  return parse_ipv4;
}

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

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.proto){
        IPV4_TCP : parse_tcp;
        default: ingress;
    }
//  return parse_tcp;
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return ingress;
}