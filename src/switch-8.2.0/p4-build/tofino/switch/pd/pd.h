#ifndef _PD_SWITCH_PD_H
#define _PD_SWITCH_PD_H

#include <stdint.h>

#include <tofino/pdfixed/pd_common.h>
#include <pipe_mgr/pipe_mgr_intf.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN_
#define LITTLE_ENDIAN_CALLER 1
#endif


/* MATCH STRUCTS */

/* switch_config_params has no match fields */

typedef struct p4_pd_dc_validate_outer_ethernet_match_spec {
  uint8_t ethernet_srcAddr[6];
  uint8_t ethernet_srcAddr_mask[6];
  uint8_t ethernet_dstAddr[6];
  uint8_t ethernet_dstAddr_mask[6];
  uint8_t vlan_tag__0__valid;
  uint8_t vlan_tag__0__valid_mask;
} p4_pd_dc_validate_outer_ethernet_match_spec_t;

typedef struct p4_pd_dc_ingress_port_mapping_match_spec {
  uint16_t ig_intr_md_ingress_port;
} p4_pd_dc_ingress_port_mapping_match_spec_t;

typedef struct p4_pd_dc_ingress_port_properties_match_spec {
  uint16_t ig_intr_md_ingress_port;
} p4_pd_dc_ingress_port_properties_match_spec_t;

typedef struct p4_pd_dc_port_vlan_to_bd_mapping_match_spec {
  uint16_t ingress_metadata_port_lag_index;
  uint8_t vlan_tag__0__valid;
  uint16_t vlan_tag__0__vid;
} p4_pd_dc_port_vlan_to_bd_mapping_match_spec_t;

typedef struct p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec {
  uint16_t ingress_metadata_port_lag_index;
  uint8_t vlan_tag__0__valid;
  uint16_t vlan_tag__0__vid;
} p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t;

typedef struct p4_pd_dc_cpu_packet_transform_match_spec {
  uint16_t fabric_header_cpu_ingressBd;
} p4_pd_dc_cpu_packet_transform_match_spec_t;

/* ingress_bd_stats has no match fields */

typedef struct p4_pd_dc_lag_group_match_spec {
  uint16_t ingress_metadata_egress_port_lag_index;
} p4_pd_dc_lag_group_match_spec_t;

typedef struct p4_pd_dc_egress_port_mapping_match_spec {
  uint16_t eg_intr_md_egress_port;
} p4_pd_dc_egress_port_mapping_match_spec_t;

typedef struct p4_pd_dc_egress_vlan_xlate_match_spec {
  uint16_t ingress_metadata_egress_ifindex;
  uint16_t egress_metadata_outer_bd;
} p4_pd_dc_egress_vlan_xlate_match_spec_t;

/* capture_tstamp has no match fields */

typedef struct p4_pd_dc_spanning_tree_match_spec {
  uint16_t ingress_metadata_ifindex;
  uint16_t l2_metadata_stp_group;
} p4_pd_dc_spanning_tree_match_spec_t;

typedef struct p4_pd_dc_smac_match_spec {
  uint16_t ingress_metadata_bd;
  uint8_t l2_metadata_lkp_mac_sa[6];
} p4_pd_dc_smac_match_spec_t;

typedef struct p4_pd_dc_dmac_match_spec {
  uint16_t ingress_metadata_bd;
  uint8_t l2_metadata_lkp_mac_da[6];
} p4_pd_dc_dmac_match_spec_t;

typedef struct p4_pd_dc_learn_notify_match_spec {
  uint8_t l2_metadata_l2_src_miss;
  uint8_t l2_metadata_l2_src_miss_mask;
  uint16_t l2_metadata_l2_src_move;
  uint16_t l2_metadata_l2_src_move_mask;
  uint8_t l2_metadata_stp_state;
  uint8_t l2_metadata_stp_state_mask;
} p4_pd_dc_learn_notify_match_spec_t;

typedef struct p4_pd_dc_validate_packet_match_spec {
  uint8_t l2_metadata_lkp_mac_sa[6];
  uint8_t l2_metadata_lkp_mac_sa_mask[6];
  uint8_t l2_metadata_lkp_mac_da[6];
  uint8_t l2_metadata_lkp_mac_da_mask[6];
  uint8_t l3_metadata_lkp_ip_type;
  uint8_t l3_metadata_lkp_ip_type_mask;
  uint8_t l3_metadata_lkp_ip_ttl;
  uint8_t l3_metadata_lkp_ip_ttl_mask;
  uint8_t l3_metadata_lkp_ip_version;
  uint8_t l3_metadata_lkp_ip_version_mask;
  uint8_t tunnel_metadata_tunnel_terminate;
  uint8_t tunnel_metadata_tunnel_terminate_mask;
  uint8_t inner_ipv4_ihl;
  uint8_t inner_ipv4_ihl_mask;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
  uint32_t ipv4_metadata_lkp_ipv4_sa_mask;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
  uint8_t ipv6_metadata_lkp_ipv6_sa_mask[16];
} p4_pd_dc_validate_packet_match_spec_t;

typedef struct p4_pd_dc_egress_bd_stats_match_spec {
  uint16_t egress_metadata_bd;
  uint8_t l2_metadata_lkp_pkt_type;
} p4_pd_dc_egress_bd_stats_match_spec_t;

typedef struct p4_pd_dc_egress_bd_map_match_spec {
  uint16_t egress_metadata_bd;
} p4_pd_dc_egress_bd_map_match_spec_t;

typedef struct p4_pd_dc_egress_outer_bd_map_match_spec {
  uint16_t egress_metadata_outer_bd;
} p4_pd_dc_egress_outer_bd_map_match_spec_t;

typedef struct p4_pd_dc_vlan_decap_match_spec {
  uint8_t vlan_tag__0__valid;
} p4_pd_dc_vlan_decap_match_spec_t;

typedef struct p4_pd_dc_rmac_match_spec {
  uint16_t l3_metadata_rmac_group;
  uint8_t l2_metadata_lkp_mac_da[6];
} p4_pd_dc_rmac_match_spec_t;

typedef struct p4_pd_dc_urpf_bd_match_spec {
  uint16_t l3_metadata_urpf_bd_group;
  uint16_t ingress_metadata_bd;
} p4_pd_dc_urpf_bd_match_spec_t;

typedef struct p4_pd_dc_smac_rewrite_match_spec {
  uint16_t egress_metadata_smac_idx;
} p4_pd_dc_smac_rewrite_match_spec_t;

typedef struct p4_pd_dc_l3_rewrite_match_spec {
  uint8_t ipv4_valid;
  uint8_t ipv6_valid;
  uint8_t mpls_0__valid;
  uint32_t ipv4_dstAddr;
  uint32_t ipv4_dstAddr_mask;
  uint8_t ipv6_dstAddr[16];
  uint8_t ipv6_dstAddr_mask[16];
} p4_pd_dc_l3_rewrite_match_spec_t;

typedef struct p4_pd_dc_mtu_match_spec {
  uint8_t l3_metadata_mtu_index;
  uint8_t ipv4_valid;
  uint8_t ipv6_valid;
} p4_pd_dc_mtu_match_spec_t;

typedef struct p4_pd_dc_validate_outer_ipv4_packet_match_spec {
  uint16_t ig_intr_md_from_parser_aux_ingress_parser_err;
  uint16_t ig_intr_md_from_parser_aux_ingress_parser_err_mask;
  uint8_t ipv4_version;
  uint8_t ipv4_version_mask;
  uint8_t ipv4_ihl;
  uint8_t ipv4_ihl_mask;
  uint8_t ipv4_ttl;
  uint8_t ipv4_ttl_mask;
  uint32_t ipv4_srcAddr;
  uint32_t ipv4_srcAddr_mask;
  uint32_t ipv4_dstAddr;
  uint32_t ipv4_dstAddr_mask;
} p4_pd_dc_validate_outer_ipv4_packet_match_spec_t;

typedef struct p4_pd_dc_ipv4_fib_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_metadata_lkp_ipv4_da;
} p4_pd_dc_ipv4_fib_match_spec_t;

typedef struct p4_pd_dc_ipv4_fib_lpm_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_metadata_lkp_ipv4_da;
  uint16_t ipv4_metadata_lkp_ipv4_da_prefix_length;
} p4_pd_dc_ipv4_fib_lpm_match_spec_t;

typedef struct p4_pd_dc_ipv4_urpf_lpm_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
  uint16_t ipv4_metadata_lkp_ipv4_sa_prefix_length;
} p4_pd_dc_ipv4_urpf_lpm_match_spec_t;

typedef struct p4_pd_dc_ipv4_urpf_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
} p4_pd_dc_ipv4_urpf_match_spec_t;

typedef struct p4_pd_dc_validate_outer_ipv6_packet_match_spec {
  uint8_t ipv6_version;
  uint8_t ipv6_version_mask;
  uint8_t ipv6_hopLimit;
  uint8_t ipv6_hopLimit_mask;
  uint8_t ipv6_srcAddr[16];
  uint8_t ipv6_srcAddr_mask[16];
  uint8_t ipv6_dstAddr[16];
  uint8_t ipv6_dstAddr_mask[16];
} p4_pd_dc_validate_outer_ipv6_packet_match_spec_t;

typedef struct p4_pd_dc_ipv6_fib_lpm_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
  uint16_t ipv6_metadata_lkp_ipv6_da_prefix_length;
} p4_pd_dc_ipv6_fib_lpm_match_spec_t;

typedef struct p4_pd_dc_ipv6_fib_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
} p4_pd_dc_ipv6_fib_match_spec_t;

typedef struct p4_pd_dc_ipv6_urpf_lpm_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
  uint16_t ipv6_metadata_lkp_ipv6_sa_prefix_length;
} p4_pd_dc_ipv6_urpf_lpm_match_spec_t;

typedef struct p4_pd_dc_ipv6_urpf_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
} p4_pd_dc_ipv6_urpf_match_spec_t;

typedef struct p4_pd_dc_outer_rmac_match_spec {
  uint16_t l3_metadata_rmac_group;
  uint8_t ethernet_dstAddr[6];
} p4_pd_dc_outer_rmac_match_spec_t;

typedef struct p4_pd_dc_ipv4_dest_vtep_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_dstAddr;
  uint8_t tunnel_metadata_ingress_tunnel_type;
} p4_pd_dc_ipv4_dest_vtep_match_spec_t;

typedef struct p4_pd_dc_ipv4_src_vtep_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_srcAddr;
  uint8_t tunnel_metadata_ingress_tunnel_type;
} p4_pd_dc_ipv4_src_vtep_match_spec_t;

typedef struct p4_pd_dc_ipv6_dest_vtep_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_dstAddr[16];
  uint8_t tunnel_metadata_ingress_tunnel_type;
} p4_pd_dc_ipv6_dest_vtep_match_spec_t;

typedef struct p4_pd_dc_ipv6_src_vtep_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_srcAddr[16];
  uint8_t tunnel_metadata_ingress_tunnel_type;
} p4_pd_dc_ipv6_src_vtep_match_spec_t;

typedef struct p4_pd_dc_tunnel_match_spec {
  uint32_t tunnel_metadata_tunnel_vni;
  uint8_t mpls_0__valid;
  uint8_t inner_ipv4_valid;
  uint8_t inner_ipv6_valid;
} p4_pd_dc_tunnel_match_spec_t;

typedef struct p4_pd_dc_adjust_lkp_fields_match_spec {
  uint8_t ipv4_valid;
  uint8_t ipv6_valid;
} p4_pd_dc_adjust_lkp_fields_match_spec_t;

typedef struct p4_pd_dc_tunnel_lookup_miss_match_spec {
  uint8_t ipv4_valid;
  uint8_t ipv6_valid;
} p4_pd_dc_tunnel_lookup_miss_match_spec_t;

typedef struct p4_pd_dc_tunnel_check_match_spec {
  uint8_t tunnel_metadata_ingress_tunnel_type;
  uint8_t tunnel_metadata_ingress_tunnel_type_mask;
  uint8_t tunnel_metadata_tunnel_lookup;
  uint8_t tunnel_metadata_tunnel_lookup_mask;
  uint8_t tunnel_metadata_src_vtep_hit;
  uint8_t tunnel_metadata_src_vtep_hit_mask;
  uint8_t tunnel_metadata_tunnel_term_type;
  uint8_t tunnel_metadata_tunnel_term_type_mask;
} p4_pd_dc_tunnel_check_match_spec_t;

typedef struct p4_pd_dc_validate_mpls_packet_match_spec {
  uint8_t mpls_0__valid;
} p4_pd_dc_validate_mpls_packet_match_spec_t;

typedef struct p4_pd_dc_tunnel_decap_process_outer_match_spec {
  uint8_t tunnel_metadata_ingress_tunnel_type;
  uint8_t inner_ipv4_valid;
  uint8_t inner_ipv6_valid;
} p4_pd_dc_tunnel_decap_process_outer_match_spec_t;

typedef struct p4_pd_dc_tunnel_decap_process_inner_match_spec {
  uint8_t inner_tcp_valid;
  uint8_t inner_udp_valid;
  uint8_t inner_icmp_valid;
} p4_pd_dc_tunnel_decap_process_inner_match_spec_t;

typedef struct p4_pd_dc_egress_vni_match_spec {
  uint16_t egress_metadata_bd;
} p4_pd_dc_egress_vni_match_spec_t;

typedef struct p4_pd_dc_tunnel_encap_process_inner_match_spec {
  uint8_t ipv4_valid;
  uint8_t ipv6_valid;
  uint8_t tcp_valid;
  uint8_t udp_valid;
  uint8_t icmp_valid;
} p4_pd_dc_tunnel_encap_process_inner_match_spec_t;

typedef struct p4_pd_dc_tunnel_encap_process_outer_match_spec {
  uint8_t tunnel_metadata_egress_tunnel_type;
  uint8_t tunnel_metadata_egress_header_count;
  uint8_t multicast_metadata_replica;
} p4_pd_dc_tunnel_encap_process_outer_match_spec_t;

typedef struct p4_pd_dc_tunnel_rewrite_match_spec {
  uint16_t tunnel_metadata_tunnel_index;
} p4_pd_dc_tunnel_rewrite_match_spec_t;

typedef struct p4_pd_dc_tunnel_dst_rewrite_match_spec {
  uint16_t tunnel_metadata_tunnel_dst_index;
} p4_pd_dc_tunnel_dst_rewrite_match_spec_t;

typedef struct p4_pd_dc_tunnel_smac_rewrite_match_spec {
  uint8_t tunnel_metadata_tunnel_smac_index;
} p4_pd_dc_tunnel_smac_rewrite_match_spec_t;

typedef struct p4_pd_dc_tunnel_dmac_rewrite_match_spec {
  uint16_t tunnel_metadata_tunnel_dmac_index;
} p4_pd_dc_tunnel_dmac_rewrite_match_spec_t;

typedef struct p4_pd_dc_tunnel_to_mgid_mapping_match_spec {
  uint16_t tunnel_metadata_tunnel_dst_index;
} p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t;

typedef struct p4_pd_dc_ingress_l4_src_port_match_spec {
  uint16_t l3_metadata_lkp_l4_sport_start;
  uint16_t l3_metadata_lkp_l4_sport_end;
} p4_pd_dc_ingress_l4_src_port_match_spec_t;

typedef struct p4_pd_dc_ingress_l4_dst_port_match_spec {
  uint16_t l3_metadata_lkp_l4_dport_start;
  uint16_t l3_metadata_lkp_l4_dport_end;
} p4_pd_dc_ingress_l4_dst_port_match_spec_t;

typedef struct p4_pd_dc_mac_acl_match_spec {
  uint16_t acl_metadata_port_lag_label;
  uint16_t acl_metadata_port_lag_label_mask;
  uint16_t acl_metadata_bd_label;
  uint16_t acl_metadata_bd_label_mask;
  uint8_t l2_metadata_lkp_mac_sa[6];
  uint8_t l2_metadata_lkp_mac_sa_mask[6];
  uint8_t l2_metadata_lkp_mac_da[6];
  uint8_t l2_metadata_lkp_mac_da_mask[6];
  uint16_t l2_metadata_lkp_mac_type;
  uint16_t l2_metadata_lkp_mac_type_mask;
} p4_pd_dc_mac_acl_match_spec_t;

typedef struct p4_pd_dc_ip_acl_match_spec {
  uint16_t acl_metadata_port_lag_label;
  uint16_t acl_metadata_port_lag_label_mask;
  uint16_t acl_metadata_bd_label;
  uint16_t acl_metadata_bd_label_mask;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
  uint32_t ipv4_metadata_lkp_ipv4_sa_mask;
  uint32_t ipv4_metadata_lkp_ipv4_da;
  uint32_t ipv4_metadata_lkp_ipv4_da_mask;
  uint8_t l3_metadata_lkp_ip_proto;
  uint8_t l3_metadata_lkp_ip_proto_mask;
  uint8_t l3_metadata_lkp_ip_ttl;
  uint8_t l3_metadata_lkp_ip_ttl_mask;
  uint8_t l3_metadata_lkp_tcp_flags;
  uint8_t l3_metadata_lkp_tcp_flags_mask;
  uint8_t acl_metadata_ingress_src_port_range_id;
  uint8_t acl_metadata_ingress_src_port_range_id_mask;
  uint8_t acl_metadata_ingress_dst_port_range_id;
  uint8_t acl_metadata_ingress_dst_port_range_id_mask;
  uint8_t l3_metadata_rmac_hit;
  uint8_t l3_metadata_rmac_hit_mask;
} p4_pd_dc_ip_acl_match_spec_t;

typedef struct p4_pd_dc_ipv6_acl_match_spec {
  uint16_t acl_metadata_port_lag_label;
  uint16_t acl_metadata_port_lag_label_mask;
  uint16_t acl_metadata_bd_label;
  uint16_t acl_metadata_bd_label_mask;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
  uint8_t ipv6_metadata_lkp_ipv6_sa_mask[16];
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
  uint8_t ipv6_metadata_lkp_ipv6_da_mask[16];
  uint8_t l3_metadata_lkp_ip_proto;
  uint8_t l3_metadata_lkp_ip_proto_mask;
  uint8_t l3_metadata_lkp_ip_ttl;
  uint8_t l3_metadata_lkp_ip_ttl_mask;
  uint8_t l3_metadata_lkp_tcp_flags;
  uint8_t l3_metadata_lkp_tcp_flags_mask;
  uint8_t acl_metadata_ingress_src_port_range_id;
  uint8_t acl_metadata_ingress_src_port_range_id_mask;
  uint8_t acl_metadata_ingress_dst_port_range_id;
  uint8_t acl_metadata_ingress_dst_port_range_id_mask;
  uint8_t l3_metadata_rmac_hit;
  uint8_t l3_metadata_rmac_hit_mask;
} p4_pd_dc_ipv6_acl_match_spec_t;

typedef struct p4_pd_dc_ipv4_racl_match_spec {
  uint16_t acl_metadata_port_lag_label;
  uint16_t acl_metadata_port_lag_label_mask;
  uint16_t acl_metadata_bd_label;
  uint16_t acl_metadata_bd_label_mask;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
  uint32_t ipv4_metadata_lkp_ipv4_sa_mask;
  uint32_t ipv4_metadata_lkp_ipv4_da;
  uint32_t ipv4_metadata_lkp_ipv4_da_mask;
  uint8_t l3_metadata_lkp_ip_proto;
  uint8_t l3_metadata_lkp_ip_proto_mask;
  uint8_t l3_metadata_lkp_ip_ttl;
  uint8_t l3_metadata_lkp_ip_ttl_mask;
  uint8_t l3_metadata_lkp_tcp_flags;
  uint8_t l3_metadata_lkp_tcp_flags_mask;
  uint8_t acl_metadata_ingress_src_port_range_id;
  uint8_t acl_metadata_ingress_src_port_range_id_mask;
  uint8_t acl_metadata_ingress_dst_port_range_id;
  uint8_t acl_metadata_ingress_dst_port_range_id_mask;
  uint8_t l3_metadata_rmac_hit;
  uint8_t l3_metadata_rmac_hit_mask;
} p4_pd_dc_ipv4_racl_match_spec_t;

typedef struct p4_pd_dc_ipv6_racl_match_spec {
  uint16_t acl_metadata_port_lag_label;
  uint16_t acl_metadata_port_lag_label_mask;
  uint16_t acl_metadata_bd_label;
  uint16_t acl_metadata_bd_label_mask;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
  uint8_t ipv6_metadata_lkp_ipv6_sa_mask[16];
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
  uint8_t ipv6_metadata_lkp_ipv6_da_mask[16];
  uint8_t l3_metadata_lkp_ip_proto;
  uint8_t l3_metadata_lkp_ip_proto_mask;
  uint8_t l3_metadata_lkp_ip_ttl;
  uint8_t l3_metadata_lkp_ip_ttl_mask;
  uint8_t l3_metadata_lkp_tcp_flags;
  uint8_t l3_metadata_lkp_tcp_flags_mask;
  uint8_t acl_metadata_ingress_src_port_range_id;
  uint8_t acl_metadata_ingress_src_port_range_id_mask;
  uint8_t acl_metadata_ingress_dst_port_range_id;
  uint8_t acl_metadata_ingress_dst_port_range_id_mask;
  uint8_t l3_metadata_rmac_hit;
  uint8_t l3_metadata_rmac_hit_mask;
} p4_pd_dc_ipv6_racl_match_spec_t;

/* acl_stats has no match fields */

/* racl_stats has no match fields */

typedef struct p4_pd_dc_system_acl_match_spec {
  uint16_t acl_metadata_port_lag_label;
  uint16_t acl_metadata_port_lag_label_mask;
  uint16_t acl_metadata_bd_label;
  uint16_t acl_metadata_bd_label_mask;
  uint16_t ingress_metadata_ifindex;
  uint16_t ingress_metadata_ifindex_mask;
  uint16_t l2_metadata_lkp_mac_type;
  uint16_t l2_metadata_lkp_mac_type_mask;
  uint8_t l2_metadata_port_vlan_mapping_miss;
  uint8_t l2_metadata_port_vlan_mapping_miss_mask;
  uint8_t acl_metadata_acl_deny;
  uint8_t acl_metadata_acl_deny_mask;
  uint8_t acl_metadata_racl_deny;
  uint8_t acl_metadata_racl_deny_mask;
  uint8_t l3_metadata_urpf_check_fail;
  uint8_t l3_metadata_urpf_check_fail_mask;
  uint8_t meter_metadata_storm_control_color;
  uint8_t meter_metadata_storm_control_color_mask;
  uint8_t ingress_metadata_drop_flag;
  uint8_t ingress_metadata_drop_flag_mask;
  uint8_t l3_metadata_l3_copy;
  uint8_t l3_metadata_l3_copy_mask;
  uint8_t l3_metadata_rmac_hit;
  uint8_t l3_metadata_rmac_hit_mask;
  uint8_t l3_metadata_fib_hit_myip;
  uint8_t l3_metadata_fib_hit_myip_mask;
  uint8_t nexthop_metadata_nexthop_glean;
  uint8_t nexthop_metadata_nexthop_glean_mask;
  uint8_t multicast_metadata_mcast_route_hit;
  uint8_t multicast_metadata_mcast_route_hit_mask;
  uint8_t multicast_metadata_mcast_route_s_g_hit;
  uint8_t multicast_metadata_mcast_route_s_g_hit_mask;
  uint8_t multicast_metadata_mcast_copy_to_cpu;
  uint8_t multicast_metadata_mcast_copy_to_cpu_mask;
  uint8_t multicast_metadata_mcast_rpf_fail;
  uint8_t multicast_metadata_mcast_rpf_fail_mask;
  uint8_t l3_metadata_routed;
  uint8_t l3_metadata_routed_mask;
  uint8_t ipv6_metadata_ipv6_src_is_link_local;
  uint8_t ipv6_metadata_ipv6_src_is_link_local_mask;
  uint16_t l2_metadata_same_if_check;
  uint16_t l2_metadata_same_if_check_mask;
  uint8_t tunnel_metadata_tunnel_if_check;
  uint8_t tunnel_metadata_tunnel_if_check_mask;
  uint16_t l3_metadata_same_bd_check;
  uint16_t l3_metadata_same_bd_check_mask;
  uint8_t l3_metadata_lkp_ip_ttl;
  uint8_t l3_metadata_lkp_ip_ttl_mask;
  uint8_t l2_metadata_stp_state;
  uint8_t l2_metadata_stp_state_mask;
  uint8_t l2_metadata_l2_src_miss;
  uint8_t l2_metadata_l2_src_miss_mask;
  uint16_t l2_metadata_l2_src_move;
  uint16_t l2_metadata_l2_src_move_mask;
  uint8_t ipv4_metadata_ipv4_unicast_enabled;
  uint8_t ipv4_metadata_ipv4_unicast_enabled_mask;
  uint8_t ipv6_metadata_ipv6_unicast_enabled;
  uint8_t ipv6_metadata_ipv6_unicast_enabled_mask;
  uint8_t l2_metadata_l2_dst_miss;
  uint8_t l2_metadata_l2_dst_miss_mask;
  uint8_t l2_metadata_lkp_pkt_type;
  uint8_t l2_metadata_lkp_pkt_type_mask;
  uint8_t l2_metadata_arp_opcode;
  uint8_t l2_metadata_arp_opcode_mask;
  uint16_t ingress_metadata_egress_ifindex;
  uint16_t ingress_metadata_egress_ifindex_mask;
  uint16_t fabric_metadata_reason_code;
  uint16_t fabric_metadata_reason_code_mask;
} p4_pd_dc_system_acl_match_spec_t;

/* drop_stats has no match fields */

typedef struct p4_pd_dc_egress_system_acl_match_spec {
  uint16_t fabric_metadata_reason_code;
  uint16_t fabric_metadata_reason_code_mask;
  uint8_t ig_intr_md_for_tm_packet_color;
  uint8_t ig_intr_md_for_tm_packet_color_mask;
  uint16_t eg_intr_md_egress_port;
  uint16_t eg_intr_md_egress_port_mask;
  uint8_t eg_intr_md_deflection_flag;
  uint8_t eg_intr_md_deflection_flag_mask;
  uint16_t l3_metadata_l3_mtu_check;
  uint16_t l3_metadata_l3_mtu_check_mask;
} p4_pd_dc_egress_system_acl_match_spec_t;

typedef struct p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec {
  uint16_t ingress_metadata_bd;
  uint32_t ipv4_metadata_lkp_ipv4_da;
} p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t;

typedef struct p4_pd_dc_ipv4_multicast_bridge_match_spec {
  uint16_t ingress_metadata_bd;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
  uint32_t ipv4_metadata_lkp_ipv4_da;
} p4_pd_dc_ipv4_multicast_bridge_match_spec_t;

typedef struct p4_pd_dc_ipv4_multicast_route_star_g_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_metadata_lkp_ipv4_da;
} p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t;

typedef struct p4_pd_dc_ipv4_multicast_route_match_spec {
  uint16_t l3_metadata_vrf;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
  uint32_t ipv4_metadata_lkp_ipv4_da;
} p4_pd_dc_ipv4_multicast_route_match_spec_t;

typedef struct p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec {
  uint16_t ingress_metadata_bd;
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
} p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t;

typedef struct p4_pd_dc_ipv6_multicast_bridge_match_spec {
  uint16_t ingress_metadata_bd;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
} p4_pd_dc_ipv6_multicast_bridge_match_spec_t;

typedef struct p4_pd_dc_ipv6_multicast_route_star_g_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
} p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t;

typedef struct p4_pd_dc_ipv6_multicast_route_match_spec {
  uint16_t l3_metadata_vrf;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
} p4_pd_dc_ipv6_multicast_route_match_spec_t;

typedef struct p4_pd_dc_bd_flood_match_spec {
  uint16_t ingress_metadata_bd;
  uint8_t l2_metadata_lkp_pkt_type;
  uint8_t multicast_metadata_flood_to_mrouters;
} p4_pd_dc_bd_flood_match_spec_t;

typedef struct p4_pd_dc_rid_match_spec {
  uint16_t eg_intr_md_egress_rid;
} p4_pd_dc_rid_match_spec_t;

typedef struct p4_pd_dc_mcast_egress_ifindex_match_spec {
  uint16_t eg_intr_md_egress_rid;
} p4_pd_dc_mcast_egress_ifindex_match_spec_t;

typedef struct p4_pd_dc_replica_type_match_spec {
  uint8_t multicast_metadata_replica;
  uint16_t egress_metadata_same_bd_check;
  uint16_t egress_metadata_same_bd_check_mask;
} p4_pd_dc_replica_type_match_spec_t;

typedef struct p4_pd_dc_fwd_result_match_spec {
  uint8_t l2_metadata_l2_redirect;
  uint8_t l2_metadata_l2_redirect_mask;
  uint8_t acl_metadata_acl_redirect;
  uint8_t acl_metadata_acl_redirect_mask;
  uint8_t acl_metadata_racl_redirect;
  uint8_t acl_metadata_racl_redirect_mask;
  uint8_t l3_metadata_rmac_hit;
  uint8_t l3_metadata_rmac_hit_mask;
  uint8_t l3_metadata_fib_hit;
  uint8_t l3_metadata_fib_hit_mask;
  uint8_t l2_metadata_lkp_pkt_type;
  uint8_t l2_metadata_lkp_pkt_type_mask;
  uint8_t l3_metadata_lkp_ip_type;
  uint8_t l3_metadata_lkp_ip_type_mask;
  uint8_t multicast_metadata_igmp_snooping_enabled;
  uint8_t multicast_metadata_igmp_snooping_enabled_mask;
  uint8_t multicast_metadata_mld_snooping_enabled;
  uint8_t multicast_metadata_mld_snooping_enabled_mask;
  uint8_t multicast_metadata_mcast_route_hit;
  uint8_t multicast_metadata_mcast_route_hit_mask;
  uint8_t multicast_metadata_mcast_bridge_hit;
  uint8_t multicast_metadata_mcast_bridge_hit_mask;
  uint16_t multicast_metadata_mcast_rpf_group;
  uint16_t multicast_metadata_mcast_rpf_group_mask;
  uint8_t multicast_metadata_mcast_mode;
  uint8_t multicast_metadata_mcast_mode_mask;
  uint8_t nexthop_metadata_nexthop_type;
  uint8_t nexthop_metadata_nexthop_type_mask;
  uint8_t l3_metadata_lkp_ip_llmc;
  uint8_t l3_metadata_lkp_ip_llmc_mask;
  uint8_t l3_metadata_lkp_ip_mc;
  uint8_t l3_metadata_lkp_ip_mc_mask;
} p4_pd_dc_fwd_result_match_spec_t;

typedef struct p4_pd_dc_ecmp_group_match_spec {
  uint16_t l3_metadata_nexthop_index;
} p4_pd_dc_ecmp_group_match_spec_t;

typedef struct p4_pd_dc_nexthop_match_spec {
  uint16_t l3_metadata_nexthop_index;
} p4_pd_dc_nexthop_match_spec_t;

typedef struct p4_pd_dc_rewrite_match_spec {
  uint16_t l3_metadata_nexthop_index;
} p4_pd_dc_rewrite_match_spec_t;

typedef struct p4_pd_dc_storm_control_stats_match_spec {
  uint8_t meter_metadata_storm_control_color;
  uint8_t l2_metadata_lkp_pkt_type;
  uint8_t l2_metadata_lkp_pkt_type_mask;
  uint16_t ig_intr_md_ingress_port;
} p4_pd_dc_storm_control_stats_match_spec_t;

typedef struct p4_pd_dc_storm_control_match_spec {
  uint16_t ig_intr_md_ingress_port;
  uint8_t l2_metadata_lkp_pkt_type;
  uint8_t l2_metadata_lkp_pkt_type_mask;
} p4_pd_dc_storm_control_match_spec_t;

typedef struct p4_pd_dc_fabric_ingress_dst_lkp_match_spec {
  uint8_t fabric_header_dstDevice;
} p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t;

typedef struct p4_pd_dc_mirror_match_spec {
  uint16_t i2e_metadata_mirror_session_id;
} p4_pd_dc_mirror_match_spec_t;

typedef struct p4_pd_dc_compute_ipv4_hashes_match_spec {
  uint8_t ethernet_valid;
} p4_pd_dc_compute_ipv4_hashes_match_spec_t;

typedef struct p4_pd_dc_compute_ipv6_hashes_match_spec {
  uint8_t ethernet_valid;
} p4_pd_dc_compute_ipv6_hashes_match_spec_t;

typedef struct p4_pd_dc_compute_non_ip_hashes_match_spec {
  uint8_t ethernet_valid;
} p4_pd_dc_compute_non_ip_hashes_match_spec_t;

typedef struct p4_pd_dc_compute_other_hashes_match_spec {
  uint8_t ethernet_valid;
} p4_pd_dc_compute_other_hashes_match_spec_t;



/* Dynamic Exm Table Key Mask */

/* switch_config_params has no match fields */

/* validate_outer_ethernet has no dynamic key masks */

/* ingress_port_mapping has no dynamic key masks */

/* ingress_port_properties has no dynamic key masks */

/* port_vlan_to_bd_mapping has no dynamic key masks */

/* port_vlan_to_ifindex_mapping has no dynamic key masks */

/* cpu_packet_transform has no dynamic key masks */

/* ingress_bd_stats has no match fields */

/* lag_group has no dynamic key masks */

/* egress_port_mapping has no dynamic key masks */

/* egress_vlan_xlate has no dynamic key masks */

/* capture_tstamp has no match fields */

/* spanning_tree has no dynamic key masks */

/* smac has no dynamic key masks */

/* dmac has no dynamic key masks */

/* learn_notify has no dynamic key masks */

/* validate_packet has no dynamic key masks */

/* egress_bd_stats has no dynamic key masks */

/* egress_bd_map has no dynamic key masks */

/* egress_outer_bd_map has no dynamic key masks */

/* vlan_decap has no dynamic key masks */

/* rmac has no dynamic key masks */

/* urpf_bd has no dynamic key masks */

/* smac_rewrite has no dynamic key masks */

/* l3_rewrite has no dynamic key masks */

/* mtu has no dynamic key masks */

/* validate_outer_ipv4_packet has no dynamic key masks */

/* ipv4_fib has no dynamic key masks */

/* ipv4_fib_lpm has no dynamic key masks */

/* ipv4_urpf_lpm has no dynamic key masks */

/* ipv4_urpf has no dynamic key masks */

/* validate_outer_ipv6_packet has no dynamic key masks */

/* ipv6_fib_lpm has no dynamic key masks */

/* ipv6_fib has no dynamic key masks */

/* ipv6_urpf_lpm has no dynamic key masks */

/* ipv6_urpf has no dynamic key masks */

/* outer_rmac has no dynamic key masks */

/* ipv4_dest_vtep has no dynamic key masks */

/* ipv4_src_vtep has no dynamic key masks */

/* ipv6_dest_vtep has no dynamic key masks */

/* ipv6_src_vtep has no dynamic key masks */

/* tunnel has no dynamic key masks */

/* adjust_lkp_fields has no dynamic key masks */

/* tunnel_lookup_miss has no dynamic key masks */

/* tunnel_check has no dynamic key masks */

/* validate_mpls_packet has no dynamic key masks */

/* tunnel_decap_process_outer has no dynamic key masks */

/* tunnel_decap_process_inner has no dynamic key masks */

/* egress_vni has no dynamic key masks */

/* tunnel_encap_process_inner has no dynamic key masks */

/* tunnel_encap_process_outer has no dynamic key masks */

/* tunnel_rewrite has no dynamic key masks */

/* tunnel_dst_rewrite has no dynamic key masks */

/* tunnel_smac_rewrite has no dynamic key masks */

/* tunnel_dmac_rewrite has no dynamic key masks */

/* tunnel_to_mgid_mapping has no dynamic key masks */

/* ingress_l4_src_port has no dynamic key masks */

/* ingress_l4_dst_port has no dynamic key masks */

/* mac_acl has no dynamic key masks */

/* ip_acl has no dynamic key masks */

/* ipv6_acl has no dynamic key masks */

/* ipv4_racl has no dynamic key masks */

/* ipv6_racl has no dynamic key masks */

/* acl_stats has no match fields */

/* racl_stats has no match fields */

/* system_acl has no dynamic key masks */

/* drop_stats has no match fields */

/* egress_system_acl has no dynamic key masks */

/* ipv4_multicast_bridge_star_g has no dynamic key masks */

/* ipv4_multicast_bridge has no dynamic key masks */

/* ipv4_multicast_route_star_g has no dynamic key masks */

/* ipv4_multicast_route has no dynamic key masks */

/* ipv6_multicast_bridge_star_g has no dynamic key masks */

/* ipv6_multicast_bridge has no dynamic key masks */

/* ipv6_multicast_route_star_g has no dynamic key masks */

/* ipv6_multicast_route has no dynamic key masks */

/* bd_flood has no dynamic key masks */

/* rid has no dynamic key masks */

/* mcast_egress_ifindex has no dynamic key masks */

/* replica_type has no dynamic key masks */

/* fwd_result has no dynamic key masks */

/* ecmp_group has no dynamic key masks */

/* nexthop has no dynamic key masks */

/* rewrite has no dynamic key masks */

/* storm_control_stats has no dynamic key masks */

/* storm_control has no dynamic key masks */

/* fabric_ingress_dst_lkp has no dynamic key masks */

/* mirror has no dynamic key masks */

/* compute_ipv4_hashes has no dynamic key masks */

/* compute_ipv6_hashes has no dynamic key masks */

/* compute_non_ip_hashes has no dynamic key masks */

/* compute_other_hashes has no dynamic key masks */



/* ACTION STRUCTS */

/* Enum of all action names. */
typedef enum p4_pd_dc_action_names {
  p4_pd_dc_set_config_parameters,
  p4_pd_dc_malformed_outer_ethernet_packet,
  p4_pd_dc_set_valid_outer_unicast_packet_untagged,
  p4_pd_dc_set_valid_outer_multicast_packet_untagged,
  p4_pd_dc_set_valid_outer_broadcast_packet_untagged,
  p4_pd_dc_set_valid_outer_unicast_packet_single_tagged,
  p4_pd_dc_set_valid_outer_unicast_packet_qinq_tagged,
  p4_pd_dc_set_valid_outer_multicast_packet_single_tagged,
  p4_pd_dc_set_valid_outer_multicast_packet_qinq_tagged,
  p4_pd_dc_set_valid_outer_broadcast_packet_single_tagged,
  p4_pd_dc_set_valid_outer_broadcast_packet_qinq_tagged,
  p4_pd_dc_set_port_lag_index,
  p4_pd_dc_set_ingress_port_properties,
  p4_pd_dc_set_bd_properties,
  p4_pd_dc_port_vlan_mapping_miss,
  p4_pd_dc_set_ingress_interface_properties,
  p4_pd_dc___meta_init_miss_action_port_vlan_to_ifindex_mapping__,
  p4_pd_dc_nop,
  p4_pd_dc_update_ingress_bd_stats,
  p4_pd_dc_set_lag_miss,
  p4_pd_dc_set_lag_port,
  p4_pd_dc_egress_port_type_cpu,
  p4_pd_dc___meta_init_miss_action_egress_port_mapping__,
  p4_pd_dc_egress_port_type_normal,
  p4_pd_dc_set_egress_if_params_untagged,
  p4_pd_dc_set_egress_if_params_tagged,
  p4_pd_dc_set_capture_tstamp,
  p4_pd_dc_set_stp_state,
  p4_pd_dc_smac_miss,
  p4_pd_dc_smac_hit,
  p4_pd_dc_dmac_hit,
  p4_pd_dc_dmac_multicast_hit,
  p4_pd_dc_dmac_miss,
  p4_pd_dc_dmac_redirect_nexthop,
  p4_pd_dc_dmac_redirect_ecmp,
  p4_pd_dc_dmac_drop,
  p4_pd_dc_generate_learn_notify,
  p4_pd_dc_set_unicast,
  p4_pd_dc_set_unicast_and_ipv6_src_is_link_local,
  p4_pd_dc_set_multicast,
  p4_pd_dc_set_multicast_and_ipv6_src_is_link_local,
  p4_pd_dc_set_broadcast,
  p4_pd_dc_set_malformed_packet,
  p4_pd_dc_set_egress_bd_properties,
  p4_pd_dc___meta_init_miss_action_egress_bd_map__,
  p4_pd_dc_set_egress_outer_bd_properties,
  p4_pd_dc___meta_init_miss_action_egress_outer_bd_map__,
  p4_pd_dc_remove_vlan_single_tagged,
  p4_pd_dc_rmac_hit,
  p4_pd_dc___meta_init_miss_action_rmac__,
  p4_pd_dc_rmac_miss,
  p4_pd_dc_urpf_bd_miss,
  p4_pd_dc_rewrite_smac,
  p4_pd_dc_ipv4_unicast_rewrite,
  p4_pd_dc_ipv4_multicast_rewrite,
  p4_pd_dc_ipv6_unicast_rewrite,
  p4_pd_dc_ipv6_multicast_rewrite,
  p4_pd_dc_mpls_rewrite,
  p4_pd_dc_mtu_miss,
  p4_pd_dc_ipv4_mtu_check,
  p4_pd_dc_ipv6_mtu_check,
  p4_pd_dc_set_malformed_outer_ipv4_packet,
  p4_pd_dc_set_valid_outer_ipv4_packet,
  p4_pd_dc_set_valid_outer_ipv4_llmc_packet,
  p4_pd_dc_set_valid_outer_ipv4_mc_packet,
  p4_pd_dc_on_miss,
  p4_pd_dc_fib_hit_nexthop,
  p4_pd_dc_fib_hit_myip,
  p4_pd_dc_fib_hit_ecmp,
  p4_pd_dc_ipv4_urpf_hit,
  p4_pd_dc_urpf_miss,
  p4_pd_dc_set_malformed_outer_ipv6_packet,
  p4_pd_dc_set_valid_outer_ipv6_packet,
  p4_pd_dc_set_valid_outer_ipv6_llmc_packet,
  p4_pd_dc_set_valid_outer_ipv6_mc_packet,
  p4_pd_dc_ipv6_urpf_hit,
  p4_pd_dc_outer_rmac_hit,
  p4_pd_dc_set_tunnel_lookup_flag,
  p4_pd_dc_set_tunnel_vni_and_lookup_flag,
  p4_pd_dc_src_vtep_hit,
  p4_pd_dc_tunnel_lookup_miss,
  p4_pd_dc_terminate_tunnel_inner_non_ip,
  p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4,
  p4_pd_dc_terminate_tunnel_inner_ipv4,
  p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6,
  p4_pd_dc_terminate_tunnel_inner_ipv6,
  p4_pd_dc_terminate_eompls,
  p4_pd_dc_terminate_vpls,
  p4_pd_dc_terminate_ipv4_over_mpls,
  p4_pd_dc_terminate_ipv6_over_mpls,
  p4_pd_dc_terminate_pw,
  p4_pd_dc_forward_mpls,
  p4_pd_dc_non_ip_lkp,
  p4_pd_dc_ipv4_lkp,
  p4_pd_dc_ipv6_lkp,
  p4_pd_dc_tunnel_check_pass,
  p4_pd_dc_set_valid_mpls_label,
  p4_pd_dc_decap_vxlan_inner_ipv4,
  p4_pd_dc_decap_vxlan_inner_non_ip,
  p4_pd_dc_decap_genv_inner_ipv4,
  p4_pd_dc_decap_genv_inner_non_ip,
  p4_pd_dc_decap_gre_inner_ipv4,
  p4_pd_dc_decap_gre_inner_non_ip,
  p4_pd_dc_decap_ip_inner_ipv4,
  p4_pd_dc_decap_vxlan_inner_ipv6,
  p4_pd_dc_decap_genv_inner_ipv6,
  p4_pd_dc_decap_gre_inner_ipv6,
  p4_pd_dc_decap_ip_inner_ipv6,
  p4_pd_dc_decap_nvgre_inner_ipv4,
  p4_pd_dc_decap_nvgre_inner_non_ip,
  p4_pd_dc_decap_nvgre_inner_ipv6,
  p4_pd_dc_decap_mpls_inner_ipv4_pop1,
  p4_pd_dc_decap_mpls_inner_ethernet_ipv4_pop1,
  p4_pd_dc_decap_mpls_inner_ethernet_non_ip_pop1,
  p4_pd_dc_decap_mpls_inner_ipv4_pop2,
  p4_pd_dc_decap_mpls_inner_ethernet_ipv4_pop2,
  p4_pd_dc_decap_mpls_inner_ethernet_non_ip_pop2,
  p4_pd_dc_decap_mpls_inner_ipv4_pop3,
  p4_pd_dc_decap_mpls_inner_ethernet_ipv4_pop3,
  p4_pd_dc_decap_mpls_inner_ethernet_non_ip_pop3,
  p4_pd_dc_decap_mpls_inner_ipv6_pop1,
  p4_pd_dc_decap_mpls_inner_ethernet_ipv6_pop1,
  p4_pd_dc_decap_mpls_inner_ipv6_pop2,
  p4_pd_dc_decap_mpls_inner_ethernet_ipv6_pop2,
  p4_pd_dc_decap_mpls_inner_ipv6_pop3,
  p4_pd_dc_decap_mpls_inner_ethernet_ipv6_pop3,
  p4_pd_dc_decap_inner_udp,
  p4_pd_dc_decap_inner_tcp,
  p4_pd_dc_decap_inner_icmp,
  p4_pd_dc_decap_inner_unknown,
  p4_pd_dc_set_egress_tunnel_vni,
  p4_pd_dc_inner_ipv4_udp_rewrite,
  p4_pd_dc_inner_ipv4_tcp_rewrite,
  p4_pd_dc_inner_ipv4_icmp_rewrite,
  p4_pd_dc_inner_ipv4_unknown_rewrite,
  p4_pd_dc_inner_ipv6_udp_rewrite,
  p4_pd_dc_inner_ipv6_tcp_rewrite,
  p4_pd_dc_inner_ipv6_icmp_rewrite,
  p4_pd_dc_inner_ipv6_unknown_rewrite,
  p4_pd_dc_inner_non_ip_rewrite,
  p4_pd_dc_ipv4_nvgre_rewrite,
  p4_pd_dc_ipv4_gre_rewrite,
  p4_pd_dc_ipv4_ip_rewrite,
  p4_pd_dc_ipv6_gre_rewrite,
  p4_pd_dc_ipv6_ip_rewrite,
  p4_pd_dc_ipv6_nvgre_rewrite,
  p4_pd_dc_mpls_ethernet_push1_rewrite,
  p4_pd_dc_mpls_ip_push1_rewrite,
  p4_pd_dc_mpls_ethernet_push2_rewrite,
  p4_pd_dc_mpls_ip_push2_rewrite,
  p4_pd_dc_mpls_ethernet_push3_rewrite,
  p4_pd_dc_mpls_ip_push3_rewrite,
  p4_pd_dc_ipv4_vxlan_rewrite,
  p4_pd_dc_ipv4_genv_rewrite,
  p4_pd_dc_ipv6_vxlan_rewrite,
  p4_pd_dc_ipv6_genv_rewrite,
  p4_pd_dc_set_ipv4_tunnel_rewrite_details,
  p4_pd_dc_set_ipv6_tunnel_rewrite_details,
  p4_pd_dc_set_mpls_rewrite_push1,
  p4_pd_dc_set_mpls_rewrite_push2,
  p4_pd_dc_set_mpls_rewrite_push3,
  p4_pd_dc_rewrite_tunnel_ipv4_dst,
  p4_pd_dc_rewrite_tunnel_ipv6_dst,
  p4_pd_dc_rewrite_tunnel_smac,
  p4_pd_dc_rewrite_tunnel_dmac,
  p4_pd_dc_set_tunnel_mgid,
  p4_pd_dc_set_ingress_src_port_range_id,
  p4_pd_dc_set_ingress_dst_port_range_id,
  p4_pd_dc_acl_deny,
  p4_pd_dc_acl_permit,
  p4_pd_dc_acl_redirect_nexthop,
  p4_pd_dc_acl_redirect_ecmp,
  p4_pd_dc_acl_mirror,
  p4_pd_dc_racl_deny,
  p4_pd_dc_racl_permit,
  p4_pd_dc_racl_redirect_nexthop,
  p4_pd_dc_racl_redirect_ecmp,
  p4_pd_dc_acl_stats_update,
  p4_pd_dc_racl_stats_update,
  p4_pd_dc_drop_packet,
  p4_pd_dc_drop_packet_with_reason,
  p4_pd_dc_redirect_to_cpu,
  p4_pd_dc_redirect_to_cpu_with_reason,
  p4_pd_dc_copy_to_cpu,
  p4_pd_dc_copy_to_cpu_with_reason,
  p4_pd_dc_drop_stats_update,
  p4_pd_dc_egress_copy_to_cpu,
  p4_pd_dc_egress_redirect_to_cpu,
  p4_pd_dc_egress_copy_to_cpu_with_reason,
  p4_pd_dc_egress_redirect_to_cpu_with_reason,
  p4_pd_dc_egress_mirror_coal_hdr,
  p4_pd_dc_egress_insert_cpu_timestamp,
  p4_pd_dc_egress_mirror,
  p4_pd_dc_egress_mirror_and_drop,
  p4_pd_dc_multicast_bridge_star_g_hit,
  p4_pd_dc_multicast_bridge_s_g_hit,
  p4_pd_dc_multicast_route_star_g_miss,
  p4_pd_dc_multicast_route_sm_star_g_hit,
  p4_pd_dc_multicast_route_bidir_star_g_hit,
  p4_pd_dc_multicast_route_s_g_hit,
  p4_pd_dc_set_bd_flood_mc_index,
  p4_pd_dc_outer_replica_from_rid,
  p4_pd_dc_encap_replica_from_rid,
  p4_pd_dc_inner_replica_from_rid,
  p4_pd_dc_unicast_replica_from_rid,
  p4_pd_dc_set_egress_ifindex_from_rid,
  p4_pd_dc_set_replica_copy_bridged,
  p4_pd_dc_set_l2_redirect,
  p4_pd_dc_set_fib_redirect,
  p4_pd_dc_set_cpu_redirect,
  p4_pd_dc_set_acl_redirect,
  p4_pd_dc_set_racl_redirect,
  p4_pd_dc_set_rmac_non_ip_drop,
  p4_pd_dc_set_multicast_route,
  p4_pd_dc_set_multicast_rpf_fail_bridge,
  p4_pd_dc_set_multicast_rpf_fail_flood_to_mrouters,
  p4_pd_dc_set_multicast_bridge,
  p4_pd_dc_set_multicast_miss_flood,
  p4_pd_dc_set_multicast_miss_flood_to_mrouters,
  p4_pd_dc_set_multicast_drop,
  p4_pd_dc_set_ecmp_nexthop_details,
  p4_pd_dc_set_ecmp_nexthop_details_with_tunnel,
  p4_pd_dc_set_ecmp_nexthop_details_for_post_routed_flood,
  p4_pd_dc_set_nexthop_details,
  p4_pd_dc_set_nexthop_details_with_tunnel,
  p4_pd_dc_set_nexthop_details_for_post_routed_flood,
  p4_pd_dc_set_nexthop_details_for_glean,
  p4_pd_dc_set_nexthop_details_for_drop,
  p4_pd_dc_set_l2_rewrite,
  p4_pd_dc_set_l2_rewrite_with_tunnel,
  p4_pd_dc_set_l3_rewrite_with_tunnel,
  p4_pd_dc_set_l3_rewrite_with_tunnel_vnid,
  p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf,
  p4_pd_dc_set_l3_rewrite,
  p4_pd_dc_set_mpls_push_rewrite_l2,
  p4_pd_dc_set_mpls_swap_push_rewrite_l3,
  p4_pd_dc_set_mpls_push_rewrite_l3,
  p4_pd_dc___meta_init_miss_action_storm_control_stats__,
  p4_pd_dc_set_storm_control_meter,
  p4_pd_dc_terminate_cpu_packet,
  p4_pd_dc_set_mirror_bd,
  p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr,
  p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag,
  p4_pd_dc_compute_lkp_ipv4_hash,
  p4_pd_dc___meta_init_miss_action_compute_ipv4_hashes__,
  p4_pd_dc_compute_lkp_ipv6_hash,
  p4_pd_dc___meta_init_miss_action_compute_ipv6_hashes__,
  p4_pd_dc_compute_lkp_non_ip_hash,
  p4_pd_dc___meta_init_miss_action_compute_non_ip_hashes__,
  p4_pd_dc_compute_other_hashes,
  p4_pd_dc_action_names_t_invalid
} p4_pd_dc_action_names_t;

const char* p4_pd_dc_action_enum_to_string(p4_pd_dc_action_names_t e);

p4_pd_dc_action_names_t p4_pd_dc_action_string_to_enum(const char* s);

typedef struct p4_pd_dc_set_config_parameters_action_spec {
  uint32_t action_enable_flowlet;
  uint32_t action_switch_id;
} p4_pd_dc_set_config_parameters_action_spec_t;

typedef struct p4_pd_dc_malformed_outer_ethernet_packet_action_spec {
  uint8_t action_drop_reason;
} p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t;

  /* set_valid_outer_unicast_packet_untagged has no parameters */

  /* set_valid_outer_multicast_packet_untagged has no parameters */

  /* set_valid_outer_broadcast_packet_untagged has no parameters */

  /* set_valid_outer_unicast_packet_single_tagged has no parameters */

  /* set_valid_outer_unicast_packet_qinq_tagged has no parameters */

  /* set_valid_outer_multicast_packet_single_tagged has no parameters */

  /* set_valid_outer_multicast_packet_qinq_tagged has no parameters */

  /* set_valid_outer_broadcast_packet_single_tagged has no parameters */

  /* set_valid_outer_broadcast_packet_qinq_tagged has no parameters */

typedef struct p4_pd_dc_set_port_lag_index_action_spec {
  uint16_t action_port_lag_index;
  uint8_t action_port_type;
} p4_pd_dc_set_port_lag_index_action_spec_t;

typedef struct p4_pd_dc_set_ingress_port_properties_action_spec {
  uint16_t action_port_lag_label;
  uint16_t action_exclusion_id;
  uint8_t action_qos_group;
  uint32_t action_tc_qos_group;
  uint8_t action_tc;
  uint8_t action_color;
  uint8_t action_learning_enabled;
  uint8_t action_trust_dscp;
  uint8_t action_trust_pcp;
} p4_pd_dc_set_ingress_port_properties_action_spec_t;

typedef struct p4_pd_dc_set_bd_properties_action_spec {
  uint16_t action_bd;
  uint16_t action_vrf;
  uint16_t action_stp_group;
  uint8_t action_learning_enabled;
  uint16_t action_bd_label;
  uint16_t action_stats_idx;
  uint16_t action_rmac_group;
  uint8_t action_ipv4_unicast_enabled;
  uint8_t action_ipv6_unicast_enabled;
  uint8_t action_ipv4_urpf_mode;
  uint8_t action_ipv6_urpf_mode;
  uint8_t action_igmp_snooping_enabled;
  uint8_t action_mld_snooping_enabled;
  uint8_t action_ipv4_multicast_enabled;
  uint8_t action_ipv6_multicast_enabled;
  uint16_t action_mrpf_group;
  uint32_t action_ipv4_mcast_key;
  uint32_t action_ipv4_mcast_key_type;
  uint32_t action_ipv6_mcast_key;
  uint32_t action_ipv6_mcast_key_type;
} p4_pd_dc_set_bd_properties_action_spec_t;

  /* port_vlan_mapping_miss has no parameters */

typedef struct p4_pd_dc_set_ingress_interface_properties_action_spec {
  uint16_t action_ingress_rid;
  uint16_t action_ifindex;
  uint32_t action_if_label;
} p4_pd_dc_set_ingress_interface_properties_action_spec_t;

  /* __meta_init_miss_action_port_vlan_to_ifindex_mapping__ has no parameters */

  /* nop has no parameters */

  /* update_ingress_bd_stats has no parameters */

  /* set_lag_miss has no parameters */

typedef struct p4_pd_dc_set_lag_port_action_spec {
  uint16_t action_port;
} p4_pd_dc_set_lag_port_action_spec_t;

  /* egress_port_type_cpu has no parameters */

  /* __meta_init_miss_action_egress_port_mapping__ has no parameters */

typedef struct p4_pd_dc_egress_port_type_normal_action_spec {
  uint8_t action_qos_group;
  uint16_t action_port_lag_label;
  uint32_t action_mlag_member;
} p4_pd_dc_egress_port_type_normal_action_spec_t;

  /* set_egress_if_params_untagged has no parameters */

typedef struct p4_pd_dc_set_egress_if_params_tagged_action_spec {
  uint16_t action_vlan_id;
  uint32_t action_egress_if_label;
} p4_pd_dc_set_egress_if_params_tagged_action_spec_t;

  /* set_capture_tstamp has no parameters */

typedef struct p4_pd_dc_set_stp_state_action_spec {
  uint8_t action_stp_state;
} p4_pd_dc_set_stp_state_action_spec_t;

  /* smac_miss has no parameters */

typedef struct p4_pd_dc_smac_hit_action_spec {
  uint16_t action_ifindex;
} p4_pd_dc_smac_hit_action_spec_t;

typedef struct p4_pd_dc_dmac_hit_action_spec {
  uint16_t action_ifindex;
  uint16_t action_port_lag_index;
} p4_pd_dc_dmac_hit_action_spec_t;

typedef struct p4_pd_dc_dmac_multicast_hit_action_spec {
  uint16_t action_mc_index;
} p4_pd_dc_dmac_multicast_hit_action_spec_t;

  /* dmac_miss has no parameters */

typedef struct p4_pd_dc_dmac_redirect_nexthop_action_spec {
  uint16_t action_nexthop_index;
} p4_pd_dc_dmac_redirect_nexthop_action_spec_t;

typedef struct p4_pd_dc_dmac_redirect_ecmp_action_spec {
  uint16_t action_ecmp_index;
} p4_pd_dc_dmac_redirect_ecmp_action_spec_t;

  /* dmac_drop has no parameters */

  /* generate_learn_notify has no parameters */

  /* set_unicast has no parameters */

  /* set_unicast_and_ipv6_src_is_link_local has no parameters */

  /* set_multicast has no parameters */

  /* set_multicast_and_ipv6_src_is_link_local has no parameters */

  /* set_broadcast has no parameters */

typedef struct p4_pd_dc_set_malformed_packet_action_spec {
  uint8_t action_drop_reason;
} p4_pd_dc_set_malformed_packet_action_spec_t;

typedef struct p4_pd_dc_set_egress_bd_properties_action_spec {
  uint16_t action_smac_idx;
  uint8_t action_mtu_index;
  uint8_t action_nat_mode;
  uint16_t action_bd_label;
} p4_pd_dc_set_egress_bd_properties_action_spec_t;

  /* __meta_init_miss_action_egress_bd_map__ has no parameters */

typedef struct p4_pd_dc_set_egress_outer_bd_properties_action_spec {
  uint8_t action_smac_idx;
  uint8_t action_sip_idx;
  uint32_t action_mtu_index;
  uint32_t action_outer_bd_label;
} p4_pd_dc_set_egress_outer_bd_properties_action_spec_t;

  /* __meta_init_miss_action_egress_outer_bd_map__ has no parameters */

  /* remove_vlan_single_tagged has no parameters */

  /* rmac_hit has no parameters */

  /* __meta_init_miss_action_rmac__ has no parameters */

  /* rmac_miss has no parameters */

  /* urpf_bd_miss has no parameters */

typedef struct p4_pd_dc_rewrite_smac_action_spec {
  uint8_t action_smac[6];
} p4_pd_dc_rewrite_smac_action_spec_t;

  /* ipv4_unicast_rewrite has no parameters */

  /* ipv4_multicast_rewrite has no parameters */

  /* ipv6_unicast_rewrite has no parameters */

  /* ipv6_multicast_rewrite has no parameters */

  /* mpls_rewrite has no parameters */

  /* mtu_miss has no parameters */

typedef struct p4_pd_dc_ipv4_mtu_check_action_spec {
  uint16_t action_l3_mtu;
} p4_pd_dc_ipv4_mtu_check_action_spec_t;

typedef struct p4_pd_dc_ipv6_mtu_check_action_spec {
  uint16_t action_l3_mtu;
} p4_pd_dc_ipv6_mtu_check_action_spec_t;

typedef struct p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec {
  uint8_t action_drop_reason;
} p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t;

  /* set_valid_outer_ipv4_packet has no parameters */

  /* set_valid_outer_ipv4_llmc_packet has no parameters */

  /* set_valid_outer_ipv4_mc_packet has no parameters */

  /* on_miss has no parameters */

typedef struct p4_pd_dc_fib_hit_nexthop_action_spec {
  uint16_t action_nexthop_index;
  uint32_t action_acl_label;
} p4_pd_dc_fib_hit_nexthop_action_spec_t;

typedef struct p4_pd_dc_fib_hit_myip_action_spec {
  uint16_t action_nexthop_index;
  uint32_t action_acl_label;
} p4_pd_dc_fib_hit_myip_action_spec_t;

typedef struct p4_pd_dc_fib_hit_ecmp_action_spec {
  uint16_t action_ecmp_index;
  uint32_t action_acl_label;
} p4_pd_dc_fib_hit_ecmp_action_spec_t;

typedef struct p4_pd_dc_ipv4_urpf_hit_action_spec {
  uint16_t action_urpf_bd_group;
} p4_pd_dc_ipv4_urpf_hit_action_spec_t;

  /* urpf_miss has no parameters */

typedef struct p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec {
  uint8_t action_drop_reason;
} p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t;

  /* set_valid_outer_ipv6_packet has no parameters */

  /* set_valid_outer_ipv6_llmc_packet has no parameters */

  /* set_valid_outer_ipv6_mc_packet has no parameters */

typedef struct p4_pd_dc_ipv6_urpf_hit_action_spec {
  uint16_t action_urpf_bd_group;
} p4_pd_dc_ipv6_urpf_hit_action_spec_t;

  /* outer_rmac_hit has no parameters */

typedef struct p4_pd_dc_set_tunnel_lookup_flag_action_spec {
  uint8_t action_term_type;
} p4_pd_dc_set_tunnel_lookup_flag_action_spec_t;

typedef struct p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec {
  uint32_t action_tunnel_vni;
  uint8_t action_term_type;
} p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t;

typedef struct p4_pd_dc_src_vtep_hit_action_spec {
  uint16_t action_ifindex;
} p4_pd_dc_src_vtep_hit_action_spec_t;

  /* tunnel_lookup_miss has no parameters */

typedef struct p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec {
  uint16_t action_bd;
  uint16_t action_bd_label;
  uint16_t action_stats_idx;
  uint16_t action_exclusion_id;
  uint16_t action_ingress_rid;
} p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec_t;

typedef struct p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec {
  uint16_t action_bd;
  uint16_t action_vrf;
  uint16_t action_rmac_group;
  uint16_t action_bd_label;
  uint8_t action_ipv4_unicast_enabled;
  uint8_t action_ipv4_urpf_mode;
  uint8_t action_igmp_snooping_enabled;
  uint16_t action_stats_idx;
  uint8_t action_ipv4_multicast_enabled;
  uint16_t action_mrpf_group;
  uint16_t action_exclusion_id;
  uint16_t action_ingress_rid;
} p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t;

typedef struct p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec {
  uint16_t action_vrf;
  uint16_t action_rmac_group;
  uint8_t action_ipv4_urpf_mode;
  uint8_t action_ipv4_unicast_enabled;
  uint8_t action_ipv4_multicast_enabled;
  uint16_t action_mrpf_group;
} p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec_t;

typedef struct p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec {
  uint16_t action_bd;
  uint16_t action_vrf;
  uint16_t action_rmac_group;
  uint16_t action_bd_label;
  uint8_t action_ipv6_unicast_enabled;
  uint8_t action_ipv6_urpf_mode;
  uint8_t action_mld_snooping_enabled;
  uint16_t action_stats_idx;
  uint8_t action_ipv6_multicast_enabled;
  uint16_t action_mrpf_group;
  uint16_t action_exclusion_id;
  uint16_t action_ingress_rid;
} p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t;

typedef struct p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec {
  uint16_t action_vrf;
  uint16_t action_rmac_group;
  uint8_t action_ipv6_unicast_enabled;
  uint8_t action_ipv6_urpf_mode;
  uint8_t action_ipv6_multicast_enabled;
  uint16_t action_mrpf_group;
} p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec_t;

typedef struct p4_pd_dc_terminate_eompls_action_spec {
  uint16_t action_bd;
  uint8_t action_tunnel_type;
} p4_pd_dc_terminate_eompls_action_spec_t;

typedef struct p4_pd_dc_terminate_vpls_action_spec {
  uint16_t action_bd;
  uint8_t action_tunnel_type;
} p4_pd_dc_terminate_vpls_action_spec_t;

typedef struct p4_pd_dc_terminate_ipv4_over_mpls_action_spec {
  uint16_t action_vrf;
  uint8_t action_tunnel_type;
} p4_pd_dc_terminate_ipv4_over_mpls_action_spec_t;

typedef struct p4_pd_dc_terminate_ipv6_over_mpls_action_spec {
  uint16_t action_vrf;
  uint8_t action_tunnel_type;
} p4_pd_dc_terminate_ipv6_over_mpls_action_spec_t;

typedef struct p4_pd_dc_terminate_pw_action_spec {
  uint16_t action_ifindex;
} p4_pd_dc_terminate_pw_action_spec_t;

typedef struct p4_pd_dc_forward_mpls_action_spec {
  uint16_t action_nexthop_index;
} p4_pd_dc_forward_mpls_action_spec_t;

  /* non_ip_lkp has no parameters */

  /* ipv4_lkp has no parameters */

  /* ipv6_lkp has no parameters */

  /* tunnel_check_pass has no parameters */

  /* set_valid_mpls_label has no parameters */

  /* decap_vxlan_inner_ipv4 has no parameters */

  /* decap_vxlan_inner_non_ip has no parameters */

  /* decap_genv_inner_ipv4 has no parameters */

  /* decap_genv_inner_non_ip has no parameters */

  /* decap_gre_inner_ipv4 has no parameters */

  /* decap_gre_inner_non_ip has no parameters */

  /* decap_ip_inner_ipv4 has no parameters */

  /* decap_vxlan_inner_ipv6 has no parameters */

  /* decap_genv_inner_ipv6 has no parameters */

  /* decap_gre_inner_ipv6 has no parameters */

  /* decap_ip_inner_ipv6 has no parameters */

  /* decap_nvgre_inner_ipv4 has no parameters */

  /* decap_nvgre_inner_non_ip has no parameters */

  /* decap_nvgre_inner_ipv6 has no parameters */

  /* decap_mpls_inner_ipv4_pop1 has no parameters */

  /* decap_mpls_inner_ethernet_ipv4_pop1 has no parameters */

  /* decap_mpls_inner_ethernet_non_ip_pop1 has no parameters */

  /* decap_mpls_inner_ipv4_pop2 has no parameters */

  /* decap_mpls_inner_ethernet_ipv4_pop2 has no parameters */

  /* decap_mpls_inner_ethernet_non_ip_pop2 has no parameters */

  /* decap_mpls_inner_ipv4_pop3 has no parameters */

  /* decap_mpls_inner_ethernet_ipv4_pop3 has no parameters */

  /* decap_mpls_inner_ethernet_non_ip_pop3 has no parameters */

  /* decap_mpls_inner_ipv6_pop1 has no parameters */

  /* decap_mpls_inner_ethernet_ipv6_pop1 has no parameters */

  /* decap_mpls_inner_ipv6_pop2 has no parameters */

  /* decap_mpls_inner_ethernet_ipv6_pop2 has no parameters */

  /* decap_mpls_inner_ipv6_pop3 has no parameters */

  /* decap_mpls_inner_ethernet_ipv6_pop3 has no parameters */

  /* decap_inner_udp has no parameters */

  /* decap_inner_tcp has no parameters */

  /* decap_inner_icmp has no parameters */

  /* decap_inner_unknown has no parameters */

typedef struct p4_pd_dc_set_egress_tunnel_vni_action_spec {
  uint32_t action_vnid;
} p4_pd_dc_set_egress_tunnel_vni_action_spec_t;

  /* inner_ipv4_udp_rewrite has no parameters */

  /* inner_ipv4_tcp_rewrite has no parameters */

  /* inner_ipv4_icmp_rewrite has no parameters */

  /* inner_ipv4_unknown_rewrite has no parameters */

  /* inner_ipv6_udp_rewrite has no parameters */

  /* inner_ipv6_tcp_rewrite has no parameters */

  /* inner_ipv6_icmp_rewrite has no parameters */

  /* inner_ipv6_unknown_rewrite has no parameters */

  /* inner_non_ip_rewrite has no parameters */

  /* ipv4_nvgre_rewrite has no parameters */

  /* ipv4_gre_rewrite has no parameters */

  /* ipv4_ip_rewrite has no parameters */

  /* ipv6_gre_rewrite has no parameters */

  /* ipv6_ip_rewrite has no parameters */

  /* ipv6_nvgre_rewrite has no parameters */

  /* mpls_ethernet_push1_rewrite has no parameters */

  /* mpls_ip_push1_rewrite has no parameters */

  /* mpls_ethernet_push2_rewrite has no parameters */

  /* mpls_ip_push2_rewrite has no parameters */

  /* mpls_ethernet_push3_rewrite has no parameters */

  /* mpls_ip_push3_rewrite has no parameters */

  /* ipv4_vxlan_rewrite has no parameters */

  /* ipv4_genv_rewrite has no parameters */

  /* ipv6_vxlan_rewrite has no parameters */

  /* ipv6_genv_rewrite has no parameters */

typedef struct p4_pd_dc_set_ipv4_tunnel_rewrite_details_action_spec {
  uint32_t action_ipv4_sa;
} p4_pd_dc_set_ipv4_tunnel_rewrite_details_action_spec_t;

typedef struct p4_pd_dc_set_ipv6_tunnel_rewrite_details_action_spec {
  uint8_t action_ipv6_sa[16];
} p4_pd_dc_set_ipv6_tunnel_rewrite_details_action_spec_t;

typedef struct p4_pd_dc_set_mpls_rewrite_push1_action_spec {
  uint32_t action_label1;
  uint8_t action_exp1;
  uint8_t action_ttl1;
  uint32_t action_smac_idx;
  uint32_t action_dmac_idx;
  uint8_t action_bos;
} p4_pd_dc_set_mpls_rewrite_push1_action_spec_t;

typedef struct p4_pd_dc_set_mpls_rewrite_push2_action_spec {
  uint32_t action_label1;
  uint8_t action_exp1;
  uint8_t action_ttl1;
  uint32_t action_label2;
  uint8_t action_exp2;
  uint8_t action_ttl2;
  uint32_t action_smac_idx;
  uint32_t action_dmac_idx;
  uint8_t action_bos;
} p4_pd_dc_set_mpls_rewrite_push2_action_spec_t;

typedef struct p4_pd_dc_set_mpls_rewrite_push3_action_spec {
  uint32_t action_label1;
  uint8_t action_exp1;
  uint8_t action_ttl1;
  uint32_t action_label2;
  uint8_t action_exp2;
  uint8_t action_ttl2;
  uint32_t action_label3;
  uint8_t action_exp3;
  uint8_t action_ttl3;
  uint32_t action_smac_idx;
  uint32_t action_dmac_idx;
  uint8_t action_bos;
} p4_pd_dc_set_mpls_rewrite_push3_action_spec_t;

typedef struct p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec {
  uint32_t action_ip;
} p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec_t;

typedef struct p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec {
  uint8_t action_ip[16];
} p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec_t;

typedef struct p4_pd_dc_rewrite_tunnel_smac_action_spec {
  uint8_t action_smac[6];
} p4_pd_dc_rewrite_tunnel_smac_action_spec_t;

typedef struct p4_pd_dc_rewrite_tunnel_dmac_action_spec {
  uint8_t action_dmac[6];
} p4_pd_dc_rewrite_tunnel_dmac_action_spec_t;

typedef struct p4_pd_dc_set_tunnel_mgid_action_spec {
  uint16_t action_mc_index;
} p4_pd_dc_set_tunnel_mgid_action_spec_t;

typedef struct p4_pd_dc_set_ingress_src_port_range_id_action_spec {
  uint8_t action_range_id;
} p4_pd_dc_set_ingress_src_port_range_id_action_spec_t;

typedef struct p4_pd_dc_set_ingress_dst_port_range_id_action_spec {
  uint8_t action_range_id;
} p4_pd_dc_set_ingress_dst_port_range_id_action_spec_t;

typedef struct p4_pd_dc_acl_deny_action_spec {
  uint16_t action_acl_stats_index;
  uint32_t action_acl_meter_index;
  uint16_t action_acl_copy_reason;
  uint8_t action_nat_mode;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_acl_deny_action_spec_t;

typedef struct p4_pd_dc_acl_permit_action_spec {
  uint16_t action_acl_stats_index;
  uint32_t action_acl_meter_index;
  uint16_t action_acl_copy_reason;
  uint8_t action_nat_mode;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_acl_permit_action_spec_t;

typedef struct p4_pd_dc_acl_redirect_nexthop_action_spec {
  uint16_t action_nexthop_index;
  uint16_t action_acl_stats_index;
  uint32_t action_acl_meter_index;
  uint16_t action_acl_copy_reason;
  uint8_t action_nat_mode;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_acl_redirect_nexthop_action_spec_t;

typedef struct p4_pd_dc_acl_redirect_ecmp_action_spec {
  uint16_t action_ecmp_index;
  uint16_t action_acl_stats_index;
  uint32_t action_acl_meter_index;
  uint16_t action_acl_copy_reason;
  uint8_t action_nat_mode;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_acl_redirect_ecmp_action_spec_t;

typedef struct p4_pd_dc_acl_mirror_action_spec {
  uint32_t action_session_id;
  uint16_t action_acl_stats_index;
  uint32_t action_acl_meter_index;
  uint8_t action_nat_mode;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_acl_mirror_action_spec_t;

typedef struct p4_pd_dc_racl_deny_action_spec {
  uint16_t action_acl_stats_index;
  uint32_t action_acl_copy_reason;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_racl_deny_action_spec_t;

typedef struct p4_pd_dc_racl_permit_action_spec {
  uint16_t action_acl_stats_index;
  uint32_t action_acl_copy_reason;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_racl_permit_action_spec_t;

typedef struct p4_pd_dc_racl_redirect_nexthop_action_spec {
  uint16_t action_nexthop_index;
  uint16_t action_acl_stats_index;
  uint32_t action_acl_copy_reason;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_racl_redirect_nexthop_action_spec_t;

typedef struct p4_pd_dc_racl_redirect_ecmp_action_spec {
  uint16_t action_ecmp_index;
  uint16_t action_acl_stats_index;
  uint32_t action_acl_copy_reason;
  uint32_t action_ingress_cos;
  uint32_t action_tc;
  uint32_t action_color;
} p4_pd_dc_racl_redirect_ecmp_action_spec_t;

  /* acl_stats_update has no parameters */

  /* racl_stats_update has no parameters */

  /* drop_packet has no parameters */

typedef struct p4_pd_dc_drop_packet_with_reason_action_spec {
  uint32_t action_drop_reason;
} p4_pd_dc_drop_packet_with_reason_action_spec_t;

typedef struct p4_pd_dc_redirect_to_cpu_action_spec {
  uint8_t action_qid;
  uint32_t action_meter_id;
  uint8_t action_icos;
} p4_pd_dc_redirect_to_cpu_action_spec_t;

typedef struct p4_pd_dc_redirect_to_cpu_with_reason_action_spec {
  uint16_t action_reason_code;
  uint8_t action_qid;
  uint32_t action_meter_id;
  uint8_t action_icos;
} p4_pd_dc_redirect_to_cpu_with_reason_action_spec_t;

typedef struct p4_pd_dc_copy_to_cpu_action_spec {
  uint8_t action_qid;
  uint32_t action_meter_id;
  uint8_t action_icos;
} p4_pd_dc_copy_to_cpu_action_spec_t;

typedef struct p4_pd_dc_copy_to_cpu_with_reason_action_spec {
  uint16_t action_reason_code;
  uint8_t action_qid;
  uint32_t action_meter_id;
  uint8_t action_icos;
} p4_pd_dc_copy_to_cpu_with_reason_action_spec_t;

  /* drop_stats_update has no parameters */

  /* egress_copy_to_cpu has no parameters */

  /* egress_redirect_to_cpu has no parameters */

typedef struct p4_pd_dc_egress_copy_to_cpu_with_reason_action_spec {
  uint16_t action_reason_code;
} p4_pd_dc_egress_copy_to_cpu_with_reason_action_spec_t;

typedef struct p4_pd_dc_egress_redirect_to_cpu_with_reason_action_spec {
  uint16_t action_reason_code;
} p4_pd_dc_egress_redirect_to_cpu_with_reason_action_spec_t;

typedef struct p4_pd_dc_egress_mirror_coal_hdr_action_spec {
  uint32_t action_session_id;
  uint32_t action_id;
} p4_pd_dc_egress_mirror_coal_hdr_action_spec_t;

  /* egress_insert_cpu_timestamp has no parameters */

typedef struct p4_pd_dc_egress_mirror_action_spec {
  uint32_t action_session_id;
} p4_pd_dc_egress_mirror_action_spec_t;

typedef struct p4_pd_dc_egress_mirror_and_drop_action_spec {
  uint32_t action_reason_code;
} p4_pd_dc_egress_mirror_and_drop_action_spec_t;

typedef struct p4_pd_dc_multicast_bridge_star_g_hit_action_spec {
  uint16_t action_mc_index;
  uint8_t action_copy_to_cpu;
} p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t;

typedef struct p4_pd_dc_multicast_bridge_s_g_hit_action_spec {
  uint16_t action_mc_index;
  uint8_t action_copy_to_cpu;
} p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t;

  /* multicast_route_star_g_miss has no parameters */

typedef struct p4_pd_dc_multicast_route_sm_star_g_hit_action_spec {
  uint16_t action_mc_index;
  uint16_t action_mcast_rpf_group;
  uint8_t action_copy_to_cpu;
} p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t;

typedef struct p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec {
  uint16_t action_mc_index;
  uint16_t action_mcast_rpf_group;
  uint8_t action_copy_to_cpu;
} p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t;

typedef struct p4_pd_dc_multicast_route_s_g_hit_action_spec {
  uint16_t action_mc_index;
  uint16_t action_mcast_rpf_group;
  uint8_t action_copy_to_cpu;
} p4_pd_dc_multicast_route_s_g_hit_action_spec_t;

typedef struct p4_pd_dc_set_bd_flood_mc_index_action_spec {
  uint16_t action_mc_index;
} p4_pd_dc_set_bd_flood_mc_index_action_spec_t;

typedef struct p4_pd_dc_outer_replica_from_rid_action_spec {
  uint16_t action_bd;
  uint16_t action_dmac_idx;
  uint16_t action_tunnel_index;
  uint8_t action_tunnel_type;
  uint8_t action_header_count;
} p4_pd_dc_outer_replica_from_rid_action_spec_t;

typedef struct p4_pd_dc_encap_replica_from_rid_action_spec {
  uint16_t action_bd;
  uint16_t action_dmac_idx;
  uint16_t action_tunnel_index;
  uint8_t action_tunnel_type;
  uint8_t action_header_count;
  uint16_t action_outer_bd;
} p4_pd_dc_encap_replica_from_rid_action_spec_t;

typedef struct p4_pd_dc_inner_replica_from_rid_action_spec {
  uint16_t action_bd;
} p4_pd_dc_inner_replica_from_rid_action_spec_t;

typedef struct p4_pd_dc_unicast_replica_from_rid_action_spec {
  uint16_t action_outer_bd;
  uint16_t action_dmac_idx;
} p4_pd_dc_unicast_replica_from_rid_action_spec_t;

typedef struct p4_pd_dc_set_egress_ifindex_from_rid_action_spec {
  uint16_t action_egress_ifindex;
} p4_pd_dc_set_egress_ifindex_from_rid_action_spec_t;

  /* set_replica_copy_bridged has no parameters */

  /* set_l2_redirect has no parameters */

  /* set_fib_redirect has no parameters */

typedef struct p4_pd_dc_set_cpu_redirect_action_spec {
  uint16_t action_cpu_ifindex;
} p4_pd_dc_set_cpu_redirect_action_spec_t;

  /* set_acl_redirect has no parameters */

  /* set_racl_redirect has no parameters */

  /* set_rmac_non_ip_drop has no parameters */

  /* set_multicast_route has no parameters */

  /* set_multicast_rpf_fail_bridge has no parameters */

  /* set_multicast_rpf_fail_flood_to_mrouters has no parameters */

  /* set_multicast_bridge has no parameters */

  /* set_multicast_miss_flood has no parameters */

  /* set_multicast_miss_flood_to_mrouters has no parameters */

  /* set_multicast_drop has no parameters */

typedef struct p4_pd_dc_set_ecmp_nexthop_details_action_spec {
  uint16_t action_ifindex;
  uint16_t action_port_lag_index;
  uint16_t action_bd;
  uint16_t action_nhop_index;
  uint8_t action_tunnel;
} p4_pd_dc_set_ecmp_nexthop_details_action_spec_t;

typedef struct p4_pd_dc_set_ecmp_nexthop_details_with_tunnel_action_spec {
  uint16_t action_bd;
  uint16_t action_tunnel_dst_index;
  uint8_t action_tunnel;
} p4_pd_dc_set_ecmp_nexthop_details_with_tunnel_action_spec_t;

typedef struct p4_pd_dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec {
  uint16_t action_bd;
  uint16_t action_uuc_mc_index;
  uint16_t action_nhop_index;
} p4_pd_dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec_t;

typedef struct p4_pd_dc_set_nexthop_details_action_spec {
  uint16_t action_ifindex;
  uint16_t action_port_lag_index;
  uint16_t action_bd;
  uint8_t action_tunnel;
} p4_pd_dc_set_nexthop_details_action_spec_t;

typedef struct p4_pd_dc_set_nexthop_details_with_tunnel_action_spec {
  uint16_t action_bd;
  uint16_t action_tunnel_dst_index;
  uint8_t action_tunnel;
} p4_pd_dc_set_nexthop_details_with_tunnel_action_spec_t;

typedef struct p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec {
  uint16_t action_bd;
  uint16_t action_uuc_mc_index;
} p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t;

typedef struct p4_pd_dc_set_nexthop_details_for_glean_action_spec {
  uint16_t action_ifindex;
} p4_pd_dc_set_nexthop_details_for_glean_action_spec_t;

  /* set_nexthop_details_for_drop has no parameters */

  /* set_l2_rewrite has no parameters */

typedef struct p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec {
  uint16_t action_tunnel_index;
  uint8_t action_tunnel_type;
} p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec_t;

typedef struct p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec {
  uint16_t action_bd;
  uint8_t action_dmac[6];
  uint16_t action_tunnel_index;
  uint8_t action_tunnel_type;
} p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t;

typedef struct p4_pd_dc_set_l3_rewrite_with_tunnel_vnid_action_spec {
  uint8_t action_dmac[6];
  uint16_t action_tunnel_index;
  uint8_t action_tunnel_type;
  uint32_t action_vnid;
} p4_pd_dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t;

typedef struct p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec {
  uint8_t action_dmac[6];
  uint16_t action_tunnel_index;
  uint8_t action_tunnel_type;
} p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t;

typedef struct p4_pd_dc_set_l3_rewrite_action_spec {
  uint16_t action_bd;
  uint8_t action_dmac[6];
} p4_pd_dc_set_l3_rewrite_action_spec_t;

typedef struct p4_pd_dc_set_mpls_push_rewrite_l2_action_spec {
  uint16_t action_tunnel_index;
  uint8_t action_header_count;
  uint16_t action_dmac_idx;
} p4_pd_dc_set_mpls_push_rewrite_l2_action_spec_t;

typedef struct p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec {
  uint16_t action_bd;
  uint8_t action_dmac[6];
  uint32_t action_label;
  uint16_t action_tunnel_index;
  uint8_t action_header_count;
  uint16_t action_dmac_idx;
} p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t;

typedef struct p4_pd_dc_set_mpls_push_rewrite_l3_action_spec {
  uint16_t action_bd;
  uint8_t action_dmac[6];
  uint16_t action_tunnel_index;
  uint8_t action_header_count;
  uint16_t action_dmac_idx;
} p4_pd_dc_set_mpls_push_rewrite_l3_action_spec_t;

  /* __meta_init_miss_action_storm_control_stats__ has no parameters */

typedef struct p4_pd_dc_set_storm_control_meter_action_spec {
  uint32_t action_meter_idx;
} p4_pd_dc_set_storm_control_meter_action_spec_t;

  /* terminate_cpu_packet has no parameters */

typedef struct p4_pd_dc_set_mirror_bd_action_spec {
  uint16_t action_bd;
  uint16_t action_session_id;
} p4_pd_dc_set_mirror_bd_action_spec_t;

typedef struct p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec {
  uint8_t action_smac[6];
  uint8_t action_dmac[6];
  uint32_t action_sip;
  uint32_t action_dip;
  uint8_t action_tos;
  uint8_t action_ttl;
} p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t;

typedef struct p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec {
  uint8_t action_smac[6];
  uint8_t action_dmac[6];
  uint32_t action_sip;
  uint32_t action_dip;
  uint8_t action_tos;
  uint8_t action_ttl;
  uint16_t action_vlan_tpid;
  uint16_t action_vlan_id;
  uint8_t action_cos;
} p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t;

  /* compute_lkp_ipv4_hash has no parameters */

  /* __meta_init_miss_action_compute_ipv4_hashes__ has no parameters */

  /* compute_lkp_ipv6_hash has no parameters */

  /* __meta_init_miss_action_compute_ipv6_hashes__ has no parameters */

  /* compute_lkp_non_ip_hash has no parameters */

  /* __meta_init_miss_action_compute_non_ip_hashes__ has no parameters */

  /* compute_other_hashes has no parameters */


typedef struct p4_pd_dc_action_specs_t {
  p4_pd_dc_action_names_t name;
  union {
    struct p4_pd_dc_set_config_parameters_action_spec p4_pd_dc_set_config_parameters;
    struct p4_pd_dc_malformed_outer_ethernet_packet_action_spec p4_pd_dc_malformed_outer_ethernet_packet;
  /* set_valid_outer_unicast_packet_untagged has no parameters */
  /* set_valid_outer_multicast_packet_untagged has no parameters */
  /* set_valid_outer_broadcast_packet_untagged has no parameters */
  /* set_valid_outer_unicast_packet_single_tagged has no parameters */
  /* set_valid_outer_unicast_packet_qinq_tagged has no parameters */
  /* set_valid_outer_multicast_packet_single_tagged has no parameters */
  /* set_valid_outer_multicast_packet_qinq_tagged has no parameters */
  /* set_valid_outer_broadcast_packet_single_tagged has no parameters */
  /* set_valid_outer_broadcast_packet_qinq_tagged has no parameters */
    struct p4_pd_dc_set_port_lag_index_action_spec p4_pd_dc_set_port_lag_index;
    struct p4_pd_dc_set_ingress_port_properties_action_spec p4_pd_dc_set_ingress_port_properties;
    struct p4_pd_dc_set_bd_properties_action_spec p4_pd_dc_set_bd_properties;
  /* port_vlan_mapping_miss has no parameters */
    struct p4_pd_dc_set_ingress_interface_properties_action_spec p4_pd_dc_set_ingress_interface_properties;
  /* __meta_init_miss_action_port_vlan_to_ifindex_mapping__ has no parameters */
  /* nop has no parameters */
  /* update_ingress_bd_stats has no parameters */
  /* set_lag_miss has no parameters */
    struct p4_pd_dc_set_lag_port_action_spec p4_pd_dc_set_lag_port;
  /* egress_port_type_cpu has no parameters */
  /* __meta_init_miss_action_egress_port_mapping__ has no parameters */
    struct p4_pd_dc_egress_port_type_normal_action_spec p4_pd_dc_egress_port_type_normal;
  /* set_egress_if_params_untagged has no parameters */
    struct p4_pd_dc_set_egress_if_params_tagged_action_spec p4_pd_dc_set_egress_if_params_tagged;
  /* set_capture_tstamp has no parameters */
    struct p4_pd_dc_set_stp_state_action_spec p4_pd_dc_set_stp_state;
  /* smac_miss has no parameters */
    struct p4_pd_dc_smac_hit_action_spec p4_pd_dc_smac_hit;
    struct p4_pd_dc_dmac_hit_action_spec p4_pd_dc_dmac_hit;
    struct p4_pd_dc_dmac_multicast_hit_action_spec p4_pd_dc_dmac_multicast_hit;
  /* dmac_miss has no parameters */
    struct p4_pd_dc_dmac_redirect_nexthop_action_spec p4_pd_dc_dmac_redirect_nexthop;
    struct p4_pd_dc_dmac_redirect_ecmp_action_spec p4_pd_dc_dmac_redirect_ecmp;
  /* dmac_drop has no parameters */
  /* generate_learn_notify has no parameters */
  /* set_unicast has no parameters */
  /* set_unicast_and_ipv6_src_is_link_local has no parameters */
  /* set_multicast has no parameters */
  /* set_multicast_and_ipv6_src_is_link_local has no parameters */
  /* set_broadcast has no parameters */
    struct p4_pd_dc_set_malformed_packet_action_spec p4_pd_dc_set_malformed_packet;
    struct p4_pd_dc_set_egress_bd_properties_action_spec p4_pd_dc_set_egress_bd_properties;
  /* __meta_init_miss_action_egress_bd_map__ has no parameters */
    struct p4_pd_dc_set_egress_outer_bd_properties_action_spec p4_pd_dc_set_egress_outer_bd_properties;
  /* __meta_init_miss_action_egress_outer_bd_map__ has no parameters */
  /* remove_vlan_single_tagged has no parameters */
  /* rmac_hit has no parameters */
  /* __meta_init_miss_action_rmac__ has no parameters */
  /* rmac_miss has no parameters */
  /* urpf_bd_miss has no parameters */
    struct p4_pd_dc_rewrite_smac_action_spec p4_pd_dc_rewrite_smac;
  /* ipv4_unicast_rewrite has no parameters */
  /* ipv4_multicast_rewrite has no parameters */
  /* ipv6_unicast_rewrite has no parameters */
  /* ipv6_multicast_rewrite has no parameters */
  /* mpls_rewrite has no parameters */
  /* mtu_miss has no parameters */
    struct p4_pd_dc_ipv4_mtu_check_action_spec p4_pd_dc_ipv4_mtu_check;
    struct p4_pd_dc_ipv6_mtu_check_action_spec p4_pd_dc_ipv6_mtu_check;
    struct p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec p4_pd_dc_set_malformed_outer_ipv4_packet;
  /* set_valid_outer_ipv4_packet has no parameters */
  /* set_valid_outer_ipv4_llmc_packet has no parameters */
  /* set_valid_outer_ipv4_mc_packet has no parameters */
  /* on_miss has no parameters */
    struct p4_pd_dc_fib_hit_nexthop_action_spec p4_pd_dc_fib_hit_nexthop;
    struct p4_pd_dc_fib_hit_myip_action_spec p4_pd_dc_fib_hit_myip;
    struct p4_pd_dc_fib_hit_ecmp_action_spec p4_pd_dc_fib_hit_ecmp;
    struct p4_pd_dc_ipv4_urpf_hit_action_spec p4_pd_dc_ipv4_urpf_hit;
  /* urpf_miss has no parameters */
    struct p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec p4_pd_dc_set_malformed_outer_ipv6_packet;
  /* set_valid_outer_ipv6_packet has no parameters */
  /* set_valid_outer_ipv6_llmc_packet has no parameters */
  /* set_valid_outer_ipv6_mc_packet has no parameters */
    struct p4_pd_dc_ipv6_urpf_hit_action_spec p4_pd_dc_ipv6_urpf_hit;
  /* outer_rmac_hit has no parameters */
    struct p4_pd_dc_set_tunnel_lookup_flag_action_spec p4_pd_dc_set_tunnel_lookup_flag;
    struct p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec p4_pd_dc_set_tunnel_vni_and_lookup_flag;
    struct p4_pd_dc_src_vtep_hit_action_spec p4_pd_dc_src_vtep_hit;
  /* tunnel_lookup_miss has no parameters */
    struct p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec p4_pd_dc_terminate_tunnel_inner_non_ip;
    struct p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4;
    struct p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec p4_pd_dc_terminate_tunnel_inner_ipv4;
    struct p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6;
    struct p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec p4_pd_dc_terminate_tunnel_inner_ipv6;
    struct p4_pd_dc_terminate_eompls_action_spec p4_pd_dc_terminate_eompls;
    struct p4_pd_dc_terminate_vpls_action_spec p4_pd_dc_terminate_vpls;
    struct p4_pd_dc_terminate_ipv4_over_mpls_action_spec p4_pd_dc_terminate_ipv4_over_mpls;
    struct p4_pd_dc_terminate_ipv6_over_mpls_action_spec p4_pd_dc_terminate_ipv6_over_mpls;
    struct p4_pd_dc_terminate_pw_action_spec p4_pd_dc_terminate_pw;
    struct p4_pd_dc_forward_mpls_action_spec p4_pd_dc_forward_mpls;
  /* non_ip_lkp has no parameters */
  /* ipv4_lkp has no parameters */
  /* ipv6_lkp has no parameters */
  /* tunnel_check_pass has no parameters */
  /* set_valid_mpls_label has no parameters */
  /* decap_vxlan_inner_ipv4 has no parameters */
  /* decap_vxlan_inner_non_ip has no parameters */
  /* decap_genv_inner_ipv4 has no parameters */
  /* decap_genv_inner_non_ip has no parameters */
  /* decap_gre_inner_ipv4 has no parameters */
  /* decap_gre_inner_non_ip has no parameters */
  /* decap_ip_inner_ipv4 has no parameters */
  /* decap_vxlan_inner_ipv6 has no parameters */
  /* decap_genv_inner_ipv6 has no parameters */
  /* decap_gre_inner_ipv6 has no parameters */
  /* decap_ip_inner_ipv6 has no parameters */
  /* decap_nvgre_inner_ipv4 has no parameters */
  /* decap_nvgre_inner_non_ip has no parameters */
  /* decap_nvgre_inner_ipv6 has no parameters */
  /* decap_mpls_inner_ipv4_pop1 has no parameters */
  /* decap_mpls_inner_ethernet_ipv4_pop1 has no parameters */
  /* decap_mpls_inner_ethernet_non_ip_pop1 has no parameters */
  /* decap_mpls_inner_ipv4_pop2 has no parameters */
  /* decap_mpls_inner_ethernet_ipv4_pop2 has no parameters */
  /* decap_mpls_inner_ethernet_non_ip_pop2 has no parameters */
  /* decap_mpls_inner_ipv4_pop3 has no parameters */
  /* decap_mpls_inner_ethernet_ipv4_pop3 has no parameters */
  /* decap_mpls_inner_ethernet_non_ip_pop3 has no parameters */
  /* decap_mpls_inner_ipv6_pop1 has no parameters */
  /* decap_mpls_inner_ethernet_ipv6_pop1 has no parameters */
  /* decap_mpls_inner_ipv6_pop2 has no parameters */
  /* decap_mpls_inner_ethernet_ipv6_pop2 has no parameters */
  /* decap_mpls_inner_ipv6_pop3 has no parameters */
  /* decap_mpls_inner_ethernet_ipv6_pop3 has no parameters */
  /* decap_inner_udp has no parameters */
  /* decap_inner_tcp has no parameters */
  /* decap_inner_icmp has no parameters */
  /* decap_inner_unknown has no parameters */
    struct p4_pd_dc_set_egress_tunnel_vni_action_spec p4_pd_dc_set_egress_tunnel_vni;
  /* inner_ipv4_udp_rewrite has no parameters */
  /* inner_ipv4_tcp_rewrite has no parameters */
  /* inner_ipv4_icmp_rewrite has no parameters */
  /* inner_ipv4_unknown_rewrite has no parameters */
  /* inner_ipv6_udp_rewrite has no parameters */
  /* inner_ipv6_tcp_rewrite has no parameters */
  /* inner_ipv6_icmp_rewrite has no parameters */
  /* inner_ipv6_unknown_rewrite has no parameters */
  /* inner_non_ip_rewrite has no parameters */
  /* ipv4_nvgre_rewrite has no parameters */
  /* ipv4_gre_rewrite has no parameters */
  /* ipv4_ip_rewrite has no parameters */
  /* ipv6_gre_rewrite has no parameters */
  /* ipv6_ip_rewrite has no parameters */
  /* ipv6_nvgre_rewrite has no parameters */
  /* mpls_ethernet_push1_rewrite has no parameters */
  /* mpls_ip_push1_rewrite has no parameters */
  /* mpls_ethernet_push2_rewrite has no parameters */
  /* mpls_ip_push2_rewrite has no parameters */
  /* mpls_ethernet_push3_rewrite has no parameters */
  /* mpls_ip_push3_rewrite has no parameters */
  /* ipv4_vxlan_rewrite has no parameters */
  /* ipv4_genv_rewrite has no parameters */
  /* ipv6_vxlan_rewrite has no parameters */
  /* ipv6_genv_rewrite has no parameters */
    struct p4_pd_dc_set_ipv4_tunnel_rewrite_details_action_spec p4_pd_dc_set_ipv4_tunnel_rewrite_details;
    struct p4_pd_dc_set_ipv6_tunnel_rewrite_details_action_spec p4_pd_dc_set_ipv6_tunnel_rewrite_details;
    struct p4_pd_dc_set_mpls_rewrite_push1_action_spec p4_pd_dc_set_mpls_rewrite_push1;
    struct p4_pd_dc_set_mpls_rewrite_push2_action_spec p4_pd_dc_set_mpls_rewrite_push2;
    struct p4_pd_dc_set_mpls_rewrite_push3_action_spec p4_pd_dc_set_mpls_rewrite_push3;
    struct p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec p4_pd_dc_rewrite_tunnel_ipv4_dst;
    struct p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec p4_pd_dc_rewrite_tunnel_ipv6_dst;
    struct p4_pd_dc_rewrite_tunnel_smac_action_spec p4_pd_dc_rewrite_tunnel_smac;
    struct p4_pd_dc_rewrite_tunnel_dmac_action_spec p4_pd_dc_rewrite_tunnel_dmac;
    struct p4_pd_dc_set_tunnel_mgid_action_spec p4_pd_dc_set_tunnel_mgid;
    struct p4_pd_dc_set_ingress_src_port_range_id_action_spec p4_pd_dc_set_ingress_src_port_range_id;
    struct p4_pd_dc_set_ingress_dst_port_range_id_action_spec p4_pd_dc_set_ingress_dst_port_range_id;
    struct p4_pd_dc_acl_deny_action_spec p4_pd_dc_acl_deny;
    struct p4_pd_dc_acl_permit_action_spec p4_pd_dc_acl_permit;
    struct p4_pd_dc_acl_redirect_nexthop_action_spec p4_pd_dc_acl_redirect_nexthop;
    struct p4_pd_dc_acl_redirect_ecmp_action_spec p4_pd_dc_acl_redirect_ecmp;
    struct p4_pd_dc_acl_mirror_action_spec p4_pd_dc_acl_mirror;
    struct p4_pd_dc_racl_deny_action_spec p4_pd_dc_racl_deny;
    struct p4_pd_dc_racl_permit_action_spec p4_pd_dc_racl_permit;
    struct p4_pd_dc_racl_redirect_nexthop_action_spec p4_pd_dc_racl_redirect_nexthop;
    struct p4_pd_dc_racl_redirect_ecmp_action_spec p4_pd_dc_racl_redirect_ecmp;
  /* acl_stats_update has no parameters */
  /* racl_stats_update has no parameters */
  /* drop_packet has no parameters */
    struct p4_pd_dc_drop_packet_with_reason_action_spec p4_pd_dc_drop_packet_with_reason;
    struct p4_pd_dc_redirect_to_cpu_action_spec p4_pd_dc_redirect_to_cpu;
    struct p4_pd_dc_redirect_to_cpu_with_reason_action_spec p4_pd_dc_redirect_to_cpu_with_reason;
    struct p4_pd_dc_copy_to_cpu_action_spec p4_pd_dc_copy_to_cpu;
    struct p4_pd_dc_copy_to_cpu_with_reason_action_spec p4_pd_dc_copy_to_cpu_with_reason;
  /* drop_stats_update has no parameters */
  /* egress_copy_to_cpu has no parameters */
  /* egress_redirect_to_cpu has no parameters */
    struct p4_pd_dc_egress_copy_to_cpu_with_reason_action_spec p4_pd_dc_egress_copy_to_cpu_with_reason;
    struct p4_pd_dc_egress_redirect_to_cpu_with_reason_action_spec p4_pd_dc_egress_redirect_to_cpu_with_reason;
    struct p4_pd_dc_egress_mirror_coal_hdr_action_spec p4_pd_dc_egress_mirror_coal_hdr;
  /* egress_insert_cpu_timestamp has no parameters */
    struct p4_pd_dc_egress_mirror_action_spec p4_pd_dc_egress_mirror;
    struct p4_pd_dc_egress_mirror_and_drop_action_spec p4_pd_dc_egress_mirror_and_drop;
    struct p4_pd_dc_multicast_bridge_star_g_hit_action_spec p4_pd_dc_multicast_bridge_star_g_hit;
    struct p4_pd_dc_multicast_bridge_s_g_hit_action_spec p4_pd_dc_multicast_bridge_s_g_hit;
  /* multicast_route_star_g_miss has no parameters */
    struct p4_pd_dc_multicast_route_sm_star_g_hit_action_spec p4_pd_dc_multicast_route_sm_star_g_hit;
    struct p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec p4_pd_dc_multicast_route_bidir_star_g_hit;
    struct p4_pd_dc_multicast_route_s_g_hit_action_spec p4_pd_dc_multicast_route_s_g_hit;
    struct p4_pd_dc_set_bd_flood_mc_index_action_spec p4_pd_dc_set_bd_flood_mc_index;
    struct p4_pd_dc_outer_replica_from_rid_action_spec p4_pd_dc_outer_replica_from_rid;
    struct p4_pd_dc_encap_replica_from_rid_action_spec p4_pd_dc_encap_replica_from_rid;
    struct p4_pd_dc_inner_replica_from_rid_action_spec p4_pd_dc_inner_replica_from_rid;
    struct p4_pd_dc_unicast_replica_from_rid_action_spec p4_pd_dc_unicast_replica_from_rid;
    struct p4_pd_dc_set_egress_ifindex_from_rid_action_spec p4_pd_dc_set_egress_ifindex_from_rid;
  /* set_replica_copy_bridged has no parameters */
  /* set_l2_redirect has no parameters */
  /* set_fib_redirect has no parameters */
    struct p4_pd_dc_set_cpu_redirect_action_spec p4_pd_dc_set_cpu_redirect;
  /* set_acl_redirect has no parameters */
  /* set_racl_redirect has no parameters */
  /* set_rmac_non_ip_drop has no parameters */
  /* set_multicast_route has no parameters */
  /* set_multicast_rpf_fail_bridge has no parameters */
  /* set_multicast_rpf_fail_flood_to_mrouters has no parameters */
  /* set_multicast_bridge has no parameters */
  /* set_multicast_miss_flood has no parameters */
  /* set_multicast_miss_flood_to_mrouters has no parameters */
  /* set_multicast_drop has no parameters */
    struct p4_pd_dc_set_ecmp_nexthop_details_action_spec p4_pd_dc_set_ecmp_nexthop_details;
    struct p4_pd_dc_set_ecmp_nexthop_details_with_tunnel_action_spec p4_pd_dc_set_ecmp_nexthop_details_with_tunnel;
    struct p4_pd_dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec p4_pd_dc_set_ecmp_nexthop_details_for_post_routed_flood;
    struct p4_pd_dc_set_nexthop_details_action_spec p4_pd_dc_set_nexthop_details;
    struct p4_pd_dc_set_nexthop_details_with_tunnel_action_spec p4_pd_dc_set_nexthop_details_with_tunnel;
    struct p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec p4_pd_dc_set_nexthop_details_for_post_routed_flood;
    struct p4_pd_dc_set_nexthop_details_for_glean_action_spec p4_pd_dc_set_nexthop_details_for_glean;
  /* set_nexthop_details_for_drop has no parameters */
  /* set_l2_rewrite has no parameters */
    struct p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec p4_pd_dc_set_l2_rewrite_with_tunnel;
    struct p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec p4_pd_dc_set_l3_rewrite_with_tunnel;
    struct p4_pd_dc_set_l3_rewrite_with_tunnel_vnid_action_spec p4_pd_dc_set_l3_rewrite_with_tunnel_vnid;
    struct p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf;
    struct p4_pd_dc_set_l3_rewrite_action_spec p4_pd_dc_set_l3_rewrite;
    struct p4_pd_dc_set_mpls_push_rewrite_l2_action_spec p4_pd_dc_set_mpls_push_rewrite_l2;
    struct p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec p4_pd_dc_set_mpls_swap_push_rewrite_l3;
    struct p4_pd_dc_set_mpls_push_rewrite_l3_action_spec p4_pd_dc_set_mpls_push_rewrite_l3;
  /* __meta_init_miss_action_storm_control_stats__ has no parameters */
    struct p4_pd_dc_set_storm_control_meter_action_spec p4_pd_dc_set_storm_control_meter;
  /* terminate_cpu_packet has no parameters */
    struct p4_pd_dc_set_mirror_bd_action_spec p4_pd_dc_set_mirror_bd;
    struct p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr;
    struct p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag;
  /* compute_lkp_ipv4_hash has no parameters */
  /* __meta_init_miss_action_compute_ipv4_hashes__ has no parameters */
  /* compute_lkp_ipv6_hash has no parameters */
  /* __meta_init_miss_action_compute_ipv6_hashes__ has no parameters */
  /* compute_lkp_non_ip_hash has no parameters */
  /* __meta_init_miss_action_compute_non_ip_hashes__ has no parameters */
  /* compute_other_hashes has no parameters */
  } u;
} p4_pd_dc_action_specs_t;

void p4_pd_dc_init(void);

/* HA TESTING INFRASTRUCTURE */

/* REGISTER VALUES */


/* IDLE TIME CONFIG */

p4_pd_status_t
p4_pd_dc_smac_idle_tmo_enable
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_idle_time_params_t params
);

p4_pd_status_t
p4_pd_dc_smac_idle_register_tmo_cb
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_idle_tmo_expiry_cb cb,
 void *cookie
);

p4_pd_status_t
p4_pd_dc_smac_idle_tmo_disable
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id
);

p4_pd_status_t
p4_pd_dc_smac_set_ttl
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 uint32_t ttl
);

p4_pd_status_t
p4_pd_dc_smac_get_ttl
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 uint32_t *ttl
);

p4_pd_status_t
p4_pd_dc_smac_update_hit_state
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_idle_time_update_complete_cb callback_fn,
 void *cookie
);

p4_pd_status_t
p4_pd_dc_smac_get_hit_state
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_idle_time_hit_state_e *hit_state
);


p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_properties_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_bd_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_cpu_packet_transform_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_lag_group_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vlan_xlate_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_spanning_tree_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_spanning_tree_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_smac_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_dmac_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_learn_notify_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_learn_notify_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_packet_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_stats_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_vlan_decap_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_vlan_decap_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_rmac_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_urpf_bd_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_urpf_bd_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_mtu_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_outer_rmac_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_outer_rmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_src_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_src_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_check_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_check_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_mpls_packet_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_vni_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vni_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_smac_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dmac_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_src_port_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_dst_port_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_mac_acl_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ip_acl_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_system_acl_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_bd_flood_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_bd_flood_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_rid_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mcast_egress_ifindex_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_replica_type_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_replica_type_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_fwd_result_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ecmp_group_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_nexthop_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_rewrite_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_stats_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_storm_control_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_mirror_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv4_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv6_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_non_ip_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_match_spec_to_entry_hdl
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_other_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);



/* Dynamic Exm Table Key Mask */


/* ADD ENTRIES */

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_malformed_outer_ethernet_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_malformed_outer_ethernet_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_port_mapping_table_add_with_set_port_lag_index
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_port_mapping_table_add_with_set_port_lag_index
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_mapping_match_spec_t *match_spec,
 p4_pd_dc_set_port_lag_index_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_port_properties_table_add_with_set_ingress_port_properties
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_port_properties_table_add_with_set_ingress_port_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_properties_match_spec_t *match_spec,
 p4_pd_dc_set_ingress_port_properties_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_add_with_set_ingress_interface_properties
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_add_with_set_ingress_interface_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec,
 p4_pd_dc_set_ingress_interface_properties_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_add_with___meta_init_miss_action_port_vlan_to_ifindex_mapping__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_add_with___meta_init_miss_action_port_vlan_to_ifindex_mapping__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_add_with_egress_port_type_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_add_with_egress_port_type_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_add_with___meta_init_miss_action_egress_port_mapping__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_add_with___meta_init_miss_action_egress_port_mapping__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_add_with_egress_port_type_normal
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_add_with_egress_port_type_normal
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec,
 p4_pd_dc_egress_port_type_normal_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_add_with_set_egress_if_params_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_add_with_set_egress_if_params_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vlan_xlate_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_add_with_set_egress_if_params_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_add_with_set_egress_if_params_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vlan_xlate_match_spec_t *match_spec,
 p4_pd_dc_set_egress_if_params_tagged_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_spanning_tree_table_add_with_set_stp_state
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_spanning_tree_table_add_with_set_stp_state
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_spanning_tree_match_spec_t *match_spec,
 p4_pd_dc_set_stp_state_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec,
 uint32_t ttl,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_table_add_with_smac_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_table_add_with_smac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec,
 uint32_t ttl,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_table_add_with_smac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_table_add_with_smac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec,
 p4_pd_dc_smac_hit_action_spec_t *action_spec,
 uint32_t ttl,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_add_with_dmac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_add_with_dmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_add_with_dmac_multicast_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_add_with_dmac_multicast_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_multicast_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_add_with_dmac_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_add_with_dmac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_add_with_dmac_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_add_with_dmac_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_add_with_dmac_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_add_with_dmac_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_add_with_dmac_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_add_with_dmac_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_learn_notify_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_learn_notify_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_learn_notify_table_add_with_generate_learn_notify
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_add_with_generate_learn_notify
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_learn_notify_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_add_with_set_unicast
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_add_with_set_unicast
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_add_with_set_unicast_and_ipv6_src_is_link_local
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_add_with_set_unicast_and_ipv6_src_is_link_local
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_add_with_set_multicast
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_add_with_set_multicast
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_add_with_set_multicast_and_ipv6_src_is_link_local
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_add_with_set_multicast_and_ipv6_src_is_link_local
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_add_with_set_broadcast
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_add_with_set_broadcast
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_add_with_set_malformed_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_add_with_set_malformed_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_malformed_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_stats_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_stats_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_stats_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_add_with_set_egress_bd_properties
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_add_with_set_egress_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec,
 p4_pd_dc_set_egress_bd_properties_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_add_with___meta_init_miss_action_egress_bd_map__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_add_with___meta_init_miss_action_egress_bd_map__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_add_with_set_egress_outer_bd_properties
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_add_with_set_egress_outer_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec,
 p4_pd_dc_set_egress_outer_bd_properties_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_add_with___meta_init_miss_action_egress_outer_bd_map__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_add_with___meta_init_miss_action_egress_outer_bd_map__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_vlan_decap_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_vlan_decap_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_vlan_decap_table_add_with_remove_vlan_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_add_with_remove_vlan_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_vlan_decap_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rmac_table_add_with_rmac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_table_add_with_rmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rmac_table_add_with___meta_init_miss_action_rmac__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_table_add_with___meta_init_miss_action_rmac__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rmac_table_add_with_rmac_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_table_add_with_rmac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_urpf_bd_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_urpf_bd_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_urpf_bd_table_add_with_urpf_bd_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_add_with_urpf_bd_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_urpf_bd_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_rewrite_table_add_with_rewrite_smac
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_rewrite_table_add_with_rewrite_smac
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_smac_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_add_with_ipv4_unicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_add_with_ipv4_unicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_add_with_ipv4_multicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_add_with_ipv4_multicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_add_with_ipv6_unicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_add_with_ipv6_unicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_add_with_ipv6_multicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_add_with_ipv6_multicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_add_with_mpls_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_add_with_mpls_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mtu_table_add_with_mtu_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_table_add_with_mtu_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mtu_table_add_with_ipv4_mtu_check
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_table_add_with_ipv4_mtu_check
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec,
 p4_pd_dc_ipv4_mtu_check_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mtu_table_add_with_ipv6_mtu_check
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_table_add_with_ipv6_mtu_check
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec,
 p4_pd_dc_ipv6_mtu_check_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_malformed_outer_ipv4_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_malformed_outer_ipv4_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_llmc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_llmc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_mc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_mc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_add_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_add_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_add_with_fib_hit_myip
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_add_with_fib_hit_myip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_add_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_add_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_add_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_add_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_add_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_add_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_add_with_ipv4_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_add_with_ipv4_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_lpm_match_spec_t *match_spec,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_add_with_urpf_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_add_with_urpf_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_add_with_ipv4_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_add_with_ipv4_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_match_spec_t *match_spec,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_malformed_outer_ipv6_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_malformed_outer_ipv6_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_llmc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_llmc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_mc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_mc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_add_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_add_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_add_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_add_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_add_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_add_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_add_with_fib_hit_myip
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_add_with_fib_hit_myip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_add_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_add_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_add_with_ipv6_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_add_with_ipv6_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_lpm_match_spec_t *match_spec,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_add_with_urpf_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_add_with_urpf_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_lpm_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_add_with_ipv6_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_add_with_ipv6_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_match_spec_t *match_spec,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_outer_rmac_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_outer_rmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_outer_rmac_table_add_with_outer_rmac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_add_with_outer_rmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_outer_rmac_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_add_with_set_tunnel_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_add_with_set_tunnel_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_add_with_set_tunnel_vni_and_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_add_with_set_tunnel_vni_and_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_src_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_add_with_src_vtep_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_add_with_src_vtep_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_src_vtep_match_spec_t *match_spec,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_add_with_set_tunnel_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_add_with_set_tunnel_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_add_with_set_tunnel_vni_and_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_add_with_set_tunnel_vni_and_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_src_vtep_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_add_with_src_vtep_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_add_with_src_vtep_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_src_vtep_match_spec_t *match_spec,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_tunnel_lookup_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_tunnel_lookup_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_eompls
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_eompls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_eompls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_vpls
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_vpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_vpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_ipv4_over_mpls
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_ipv4_over_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_ipv4_over_mpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_ipv6_over_mpls
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_ipv6_over_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_ipv6_over_mpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_terminate_pw
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_terminate_pw
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_pw_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_add_with_forward_mpls
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_add_with_forward_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_forward_mpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_add_with_non_ip_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_add_with_non_ip_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_add_with_ipv4_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_add_with_ipv4_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_add_with_ipv6_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_add_with_ipv6_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_add_with_non_ip_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_add_with_non_ip_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_add_with_ipv4_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_add_with_ipv4_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_add_with_ipv6_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_add_with_ipv6_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_check_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_check_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_check_table_add_with_tunnel_check_pass
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_add_with_tunnel_check_pass
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_check_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_mpls_packet_table_add_with_set_valid_mpls_label
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_mpls_packet_table_add_with_set_valid_mpls_label
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_mpls_packet_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_gre_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_gre_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_gre_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_gre_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_ip_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_ip_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_gre_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_gre_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_ip_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_ip_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_udp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_udp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_tcp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_tcp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_icmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_icmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_unknown
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_unknown
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vni_table_add_with_set_egress_tunnel_vni
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vni_table_add_with_set_egress_tunnel_vni
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vni_match_spec_t *match_spec,
 p4_pd_dc_set_egress_tunnel_vni_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_udp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_udp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_tcp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_tcp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_icmp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_icmp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_unknown_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_unknown_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_udp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_udp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_tcp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_tcp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_icmp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_icmp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_unknown_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_unknown_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_non_ip_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_non_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_nvgre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_nvgre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_gre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_gre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_ip_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_gre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_gre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_ip_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_nvgre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_nvgre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push1_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push1_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push1_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push1_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push2_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push2_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push3_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push3_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_vxlan_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_vxlan_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_genv_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_genv_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_vxlan_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_vxlan_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_genv_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_genv_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_add_with_set_ipv4_tunnel_rewrite_details
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_add_with_set_ipv4_tunnel_rewrite_details
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_ipv4_tunnel_rewrite_details_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_add_with_set_ipv6_tunnel_rewrite_details
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_add_with_set_ipv6_tunnel_rewrite_details
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_ipv6_tunnel_rewrite_details_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push1
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_rewrite_push1_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push2
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_rewrite_push2_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_rewrite_push3_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv6_dst
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv6_dst
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_smac_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_add_with_rewrite_tunnel_smac
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_add_with_rewrite_tunnel_smac
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_smac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_smac_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dmac_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_add_with_rewrite_tunnel_dmac
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_add_with_rewrite_tunnel_dmac
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dmac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_dmac_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_add_with_set_tunnel_mgid
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_add_with_set_tunnel_mgid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_mgid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_src_port_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_add_with_set_ingress_src_port_range_id
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_add_with_set_ingress_src_port_range_id
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_src_port_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_ingress_src_port_range_id_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_dst_port_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_add_with_set_ingress_dst_port_range_id
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_add_with_set_ingress_dst_port_range_id
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_dst_port_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_ingress_dst_port_range_id_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_add_with_acl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_add_with_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_add_with_acl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_add_with_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_add_with_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_add_with_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_add_with_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_add_with_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_add_with_acl_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_add_with_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_add_with_acl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_add_with_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_add_with_acl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_add_with_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_add_with_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_add_with_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_add_with_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_add_with_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_add_with_acl_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_add_with_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_add_with_acl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_add_with_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_add_with_acl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_add_with_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_add_with_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_add_with_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_add_with_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_add_with_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_add_with_acl_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_add_with_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_add_with_racl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_add_with_racl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_add_with_racl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_add_with_racl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_add_with_racl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_add_with_racl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_add_with_racl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_add_with_racl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_add_with_racl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_add_with_racl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_add_with_racl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_add_with_racl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_add_with_racl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_add_with_racl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_add_with_racl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_add_with_racl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_add_with_drop_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_add_with_drop_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_add_with_drop_packet_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_add_with_drop_packet_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_drop_packet_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_add_with_redirect_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_add_with_redirect_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_redirect_to_cpu_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_add_with_redirect_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_add_with_redirect_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_redirect_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_add_with_copy_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_add_with_copy_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_copy_to_cpu_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_add_with_copy_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_add_with_copy_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_copy_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_drop_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_drop_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_copy_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_copy_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_redirect_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_redirect_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_copy_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_copy_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_copy_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_redirect_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_redirect_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_redirect_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_mirror_coal_hdr
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_mirror_coal_hdr
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_mirror_coal_hdr_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_insert_cpu_timestamp
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_insert_cpu_timestamp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_add_with_egress_mirror_and_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_add_with_egress_mirror_and_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_mirror_and_drop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_add_with_multicast_bridge_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_add_with_multicast_bridge_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_star_g_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_star_g_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_add_with_multicast_route_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_add_with_multicast_route_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_add_with_multicast_bridge_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_add_with_multicast_bridge_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_star_g_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_star_g_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_add_with_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_add_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_add_with_multicast_route_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_add_with_multicast_route_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_bd_flood_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_bd_flood_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_bd_flood_table_add_with_set_bd_flood_mc_index
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_add_with_set_bd_flood_mc_index
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_bd_flood_match_spec_t *match_spec,
 p4_pd_dc_set_bd_flood_mc_index_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_table_add_with_outer_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_table_add_with_outer_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_outer_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_table_add_with_encap_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_table_add_with_encap_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_encap_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_table_add_with_inner_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_table_add_with_inner_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_inner_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_table_add_with_unicast_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_table_add_with_unicast_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_unicast_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mcast_egress_ifindex_table_add_with_set_egress_ifindex_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_table_add_with_set_egress_ifindex_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mcast_egress_ifindex_match_spec_t *match_spec,
 p4_pd_dc_set_egress_ifindex_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_replica_type_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_replica_type_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_replica_type_table_add_with_set_replica_copy_bridged
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_add_with_set_replica_copy_bridged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_replica_type_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_l2_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_l2_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_fib_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_fib_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_cpu_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_cpu_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_cpu_redirect_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_acl_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_acl_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_racl_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_racl_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_rmac_non_ip_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_rmac_non_ip_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_multicast_route
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_multicast_route
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_multicast_rpf_fail_bridge
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_multicast_rpf_fail_bridge
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_multicast_rpf_fail_flood_to_mrouters
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_multicast_rpf_fail_flood_to_mrouters
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_multicast_bridge
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_multicast_bridge
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_multicast_miss_flood
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_multicast_miss_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_multicast_miss_flood_to_mrouters
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_multicast_miss_flood_to_mrouters
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_add_with_set_multicast_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_add_with_set_multicast_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_add_with_set_nexthop_details
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_add_with_set_nexthop_details
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_add_with_set_nexthop_details_with_tunnel
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_add_with_set_nexthop_details_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_with_tunnel_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_add_with_set_nexthop_details_for_post_routed_flood
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_add_with_set_nexthop_details_for_post_routed_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_add_with_set_nexthop_details_for_glean
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_add_with_set_nexthop_details_for_glean
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_for_glean_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_add_with_set_nexthop_details_for_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_add_with_set_nexthop_details_for_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_l2_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_l2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_l2_rewrite_with_tunnel
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_l2_rewrite_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_l3_rewrite_with_tunnel
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_l3_rewrite_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_l3_rewrite_with_tunnel_vnid
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_l3_rewrite_with_tunnel_vnid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_l3_rewrite_with_tunnel_and_ingress_vrf
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_l3_rewrite_with_tunnel_and_ingress_vrf
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_l3_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_l3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_mpls_push_rewrite_l2
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_mpls_push_rewrite_l2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_push_rewrite_l2_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_mpls_swap_push_rewrite_l3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_mpls_swap_push_rewrite_l3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_add_with_set_mpls_push_rewrite_l3
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_add_with_set_mpls_push_rewrite_l3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_push_rewrite_l3_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_stats_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_add_with___meta_init_miss_action_storm_control_stats__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_add_with___meta_init_miss_action_storm_control_stats__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_stats_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_match_spec_t *match_spec,
 int priority,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_table_add_with_set_storm_control_meter
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_add_with_set_storm_control_meter
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_storm_control_meter_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_add_with_terminate_cpu_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_add_with_terminate_cpu_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_table_add_with_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_table_add_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_table_add_with_set_mirror_bd
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_table_add_with_set_mirror_bd
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_dc_set_mirror_bd_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_table_add_with_ipv4_erspan_t3_rewrite_with_eth_hdr
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_table_add_with_ipv4_erspan_t3_rewrite_with_eth_hdr
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_table_add_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_table_add_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_add_with_compute_lkp_ipv4_hash
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_add_with_compute_lkp_ipv4_hash
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv4_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_add_with___meta_init_miss_action_compute_ipv4_hashes__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_add_with___meta_init_miss_action_compute_ipv4_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv4_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_add_with_compute_lkp_ipv6_hash
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_add_with_compute_lkp_ipv6_hash
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv6_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_add_with___meta_init_miss_action_compute_ipv6_hashes__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_add_with___meta_init_miss_action_compute_ipv6_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv6_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_add_with_compute_lkp_non_ip_hash
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_add_with_compute_lkp_non_ip_hash
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_non_ip_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_add_with___meta_init_miss_action_compute_non_ip_hashes__
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_add_with___meta_init_miss_action_compute_non_ip_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_non_ip_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_other_hashes_table_add_with_compute_other_hashes
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_other_hashes_table_add_with_compute_other_hashes
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_other_hashes_match_spec_t *match_spec,
 p4_pd_entry_hdl_t *entry_hdl
);


/* DELETE ENTRIES */

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ingress_port_mapping_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_port_mapping_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_port_mapping_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_port_mapping_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ingress_port_properties_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_port_properties_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_port_properties_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_port_properties_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_properties_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vlan_xlate_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_spanning_tree_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_spanning_tree_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_spanning_tree_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_spanning_tree_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_spanning_tree_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_smac_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_smac_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_smac_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_dmac_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_learn_notify_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_learn_notify_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_learn_notify_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_egress_bd_stats_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_stats_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_stats_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_bd_stats_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_stats_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_vlan_decap_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_vlan_decap_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_vlan_decap_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rmac_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_rmac_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rmac_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_urpf_bd_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_urpf_bd_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_urpf_bd_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_smac_rewrite_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_rewrite_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_smac_rewrite_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_smac_rewrite_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_mtu_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_mtu_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_mtu_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_outer_rmac_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_outer_rmac_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_outer_rmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_src_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_src_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_check_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_check_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_check_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_mpls_packet_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_mpls_packet_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_validate_mpls_packet_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_validate_mpls_packet_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_mpls_packet_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_vni_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vni_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vni_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_vni_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vni_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_smac_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dmac_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_src_port_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_dst_port_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_mac_acl_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ip_acl_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_system_acl_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_bd_flood_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_bd_flood_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_bd_flood_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rid_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_rid_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_mcast_egress_ifindex_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_mcast_egress_ifindex_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mcast_egress_ifindex_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_replica_type_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_replica_type_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_replica_type_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_nexthop_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_stats_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_storm_control_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_mirror_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv4_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv6_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_non_ip_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_other_hashes_table_delete
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_other_hashes_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

/**
 * @brief p4_pd_dc_compute_other_hashes_table_delete_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_other_hashes_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_other_hashes_match_spec_t *match_spec
);


/* Get default entry handle */

p4_pd_status_t
p4_pd_dc_switch_config_params_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_spanning_tree_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_smac_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_dmac_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_learn_notify_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_packet_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_vlan_decap_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_rmac_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_urpf_bd_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_mtu_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_outer_rmac_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_check_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_vni_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_mac_acl_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ip_acl_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_acl_stats_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_racl_stats_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_system_acl_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_drop_stats_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_bd_flood_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_rid_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_replica_type_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_fwd_result_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_nexthop_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_rewrite_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_storm_control_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_mirror_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_table_get_default_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt,
 p4_pd_entry_hdl_t* entry_hdl
);


/* Clear default entry */

p4_pd_status_t
p4_pd_dc_switch_config_params_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_lag_group_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_spanning_tree_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_smac_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_dmac_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_learn_notify_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_validate_packet_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_vlan_decap_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_rmac_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_urpf_bd_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_mtu_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_outer_rmac_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_check_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_egress_vni_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_mac_acl_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ip_acl_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_acl_stats_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_racl_stats_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_system_acl_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_drop_stats_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_bd_flood_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_rid_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_replica_type_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_fwd_result_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_ecmp_group_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_nexthop_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_rewrite_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_storm_control_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_mirror_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_table_reset_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t pd_dev_tgt
);


/* MODIFY TABLE PROPERTIES */

p4_pd_status_t
p4_pd_dc_switch_config_params_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_switch_config_params_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_lag_group_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_lag_group_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_spanning_tree_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_spanning_tree_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_smac_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_smac_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_dmac_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_dmac_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_learn_notify_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_learn_notify_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_validate_packet_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_validate_packet_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_vlan_decap_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_vlan_decap_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_rmac_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_rmac_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_urpf_bd_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_urpf_bd_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_mtu_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_mtu_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_outer_rmac_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_outer_rmac_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_check_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_check_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_egress_vni_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_egress_vni_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_mac_acl_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_mac_acl_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ip_acl_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ip_acl_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_acl_stats_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_acl_stats_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_racl_stats_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_racl_stats_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_system_acl_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_system_acl_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_drop_stats_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_drop_stats_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_bd_flood_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_bd_flood_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_rid_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_rid_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_replica_type_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_replica_type_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_fwd_result_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_fwd_result_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_ecmp_group_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_ecmp_group_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_nexthop_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_nexthop_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_rewrite_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_rewrite_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_storm_control_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_storm_control_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_mirror_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_mirror_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value,
 p4_pd_tbl_prop_args_t args
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_get_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t *value,
 p4_pd_tbl_prop_args_t *args
);


/* MODIFY ENTRIES */

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_malformed_outer_ethernet_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_malformed_outer_ethernet_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_malformed_outer_ethernet_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_malformed_outer_ethernet_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_untagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_untagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_untagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_untagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_untagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_untagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_untagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_untagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_untagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_single_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_single_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_single_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_qinq_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_qinq_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_single_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_single_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_single_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_qinq_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_qinq_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_single_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_single_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_single_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_qinq_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_qinq_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ingress_port_mapping_table_modify_with_set_port_lag_index
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_port_mapping_table_modify_with_set_port_lag_index
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_port_lag_index_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ingress_port_mapping_table_modify_with_set_port_lag_index_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_port_mapping_table_modify_with_set_port_lag_index_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_mapping_match_spec_t *match_spec,
 p4_pd_dc_set_port_lag_index_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ingress_port_properties_table_modify_with_set_ingress_port_properties
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_port_properties_table_modify_with_set_ingress_port_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_ingress_port_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ingress_port_properties_table_modify_with_set_ingress_port_properties_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_port_properties_table_modify_with_set_ingress_port_properties_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_port_properties_match_spec_t *match_spec,
 p4_pd_dc_set_ingress_port_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_set_ingress_interface_properties
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_set_ingress_interface_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_ingress_interface_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_set_ingress_interface_properties_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_set_ingress_interface_properties_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec,
 p4_pd_dc_set_ingress_interface_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with___meta_init_miss_action_port_vlan_to_ifindex_mapping__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with___meta_init_miss_action_port_vlan_to_ifindex_mapping__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with___meta_init_miss_action_port_vlan_to_ifindex_mapping___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with___meta_init_miss_action_port_vlan_to_ifindex_mapping___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_cpu
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_cpu_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_cpu_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_modify_with___meta_init_miss_action_egress_port_mapping__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_modify_with___meta_init_miss_action_egress_port_mapping__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_modify_with___meta_init_miss_action_egress_port_mapping___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_modify_with___meta_init_miss_action_egress_port_mapping___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_normal
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_normal
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_egress_port_type_normal_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_normal_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_table_modify_with_egress_port_type_normal_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec,
 p4_pd_dc_egress_port_type_normal_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_untagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_untagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_untagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vlan_xlate_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_egress_if_params_tagged_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_table_modify_with_set_egress_if_params_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vlan_xlate_match_spec_t *match_spec,
 p4_pd_dc_set_egress_if_params_tagged_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_spanning_tree_table_modify_with_set_stp_state
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_spanning_tree_table_modify_with_set_stp_state
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_stp_state_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_spanning_tree_table_modify_with_set_stp_state_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_spanning_tree_table_modify_with_set_stp_state_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_spanning_tree_match_spec_t *match_spec,
 p4_pd_dc_set_stp_state_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_smac_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_smac_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_smac_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_smac_table_modify_with_smac_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_table_modify_with_smac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_smac_table_modify_with_smac_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_smac_table_modify_with_smac_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_smac_table_modify_with_smac_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_smac_table_modify_with_smac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_smac_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_smac_table_modify_with_smac_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_smac_table_modify_with_smac_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_match_spec_t *match_spec,
 p4_pd_dc_smac_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_dmac_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_multicast_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_multicast_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_dmac_multicast_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_multicast_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_multicast_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_multicast_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_redirect_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_dmac_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_redirect_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_redirect_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_redirect_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_dmac_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_redirect_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_redirect_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_dmac_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_drop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_dmac_table_modify_with_dmac_drop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_dmac_table_modify_with_dmac_drop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_learn_notify_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_learn_notify_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_learn_notify_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_learn_notify_table_modify_with_generate_learn_notify
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_modify_with_generate_learn_notify
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_learn_notify_table_modify_with_generate_learn_notify_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_learn_notify_table_modify_with_generate_learn_notify_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_learn_notify_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_unicast
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_unicast
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_unicast_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_unicast_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_unicast_and_ipv6_src_is_link_local
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_unicast_and_ipv6_src_is_link_local
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_unicast_and_ipv6_src_is_link_local_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_unicast_and_ipv6_src_is_link_local_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_multicast
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_multicast
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_multicast_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_multicast_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_multicast_and_ipv6_src_is_link_local
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_multicast_and_ipv6_src_is_link_local
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_multicast_and_ipv6_src_is_link_local_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_multicast_and_ipv6_src_is_link_local_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_broadcast
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_broadcast
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_broadcast_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_broadcast_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_malformed_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_malformed_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_malformed_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_packet_table_modify_with_set_malformed_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_packet_table_modify_with_set_malformed_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_malformed_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_bd_stats_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_stats_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_stats_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_bd_stats_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_stats_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_modify_with_set_egress_bd_properties
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_modify_with_set_egress_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_egress_bd_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_modify_with_set_egress_bd_properties_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_modify_with_set_egress_bd_properties_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec,
 p4_pd_dc_set_egress_bd_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_modify_with___meta_init_miss_action_egress_bd_map__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_modify_with___meta_init_miss_action_egress_bd_map__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_table_modify_with___meta_init_miss_action_egress_bd_map___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_table_modify_with___meta_init_miss_action_egress_bd_map___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_modify_with_set_egress_outer_bd_properties
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_modify_with_set_egress_outer_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_egress_outer_bd_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_modify_with_set_egress_outer_bd_properties_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_modify_with_set_egress_outer_bd_properties_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec,
 p4_pd_dc_set_egress_outer_bd_properties_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_modify_with___meta_init_miss_action_egress_outer_bd_map__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_modify_with___meta_init_miss_action_egress_outer_bd_map__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_table_modify_with___meta_init_miss_action_egress_outer_bd_map___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_table_modify_with___meta_init_miss_action_egress_outer_bd_map___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_vlan_decap_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_vlan_decap_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_vlan_decap_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_vlan_decap_table_modify_with_remove_vlan_single_tagged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_modify_with_remove_vlan_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_vlan_decap_table_modify_with_remove_vlan_single_tagged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_table_modify_with_remove_vlan_single_tagged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_vlan_decap_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rmac_table_modify_with_rmac_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_table_modify_with_rmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_rmac_table_modify_with_rmac_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rmac_table_modify_with_rmac_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rmac_table_modify_with___meta_init_miss_action_rmac__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_table_modify_with___meta_init_miss_action_rmac__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_rmac_table_modify_with___meta_init_miss_action_rmac___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rmac_table_modify_with___meta_init_miss_action_rmac___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rmac_table_modify_with_rmac_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_table_modify_with_rmac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_rmac_table_modify_with_rmac_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rmac_table_modify_with_rmac_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_urpf_bd_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_urpf_bd_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_urpf_bd_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_urpf_bd_table_modify_with_urpf_bd_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_modify_with_urpf_bd_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_urpf_bd_table_modify_with_urpf_bd_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_table_modify_with_urpf_bd_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_urpf_bd_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_smac_rewrite_table_modify_with_rewrite_smac
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_smac_rewrite_table_modify_with_rewrite_smac
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_rewrite_smac_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_smac_rewrite_table_modify_with_rewrite_smac_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_smac_rewrite_table_modify_with_rewrite_smac_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_smac_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv4_unicast_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv4_unicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv4_unicast_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv4_unicast_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv4_multicast_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv4_multicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv4_multicast_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv4_multicast_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv6_unicast_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv6_unicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv6_unicast_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv6_unicast_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv6_multicast_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv6_multicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_ipv6_multicast_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_ipv6_multicast_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_mpls_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_mpls_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_table_modify_with_mpls_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_table_modify_with_mpls_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_mtu_table_modify_with_mtu_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_table_modify_with_mtu_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_mtu_table_modify_with_mtu_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_mtu_table_modify_with_mtu_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_mtu_table_modify_with_ipv4_mtu_check
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mtu_table_modify_with_ipv4_mtu_check
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv4_mtu_check_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mtu_table_modify_with_ipv4_mtu_check_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mtu_table_modify_with_ipv4_mtu_check_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec,
 p4_pd_dc_ipv4_mtu_check_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mtu_table_modify_with_ipv6_mtu_check
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mtu_table_modify_with_ipv6_mtu_check
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv6_mtu_check_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mtu_table_modify_with_ipv6_mtu_check_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mtu_table_modify_with_ipv6_mtu_check_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mtu_match_spec_t *match_spec,
 p4_pd_dc_ipv6_mtu_check_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_malformed_outer_ipv4_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_malformed_outer_ipv4_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_malformed_outer_ipv4_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_malformed_outer_ipv4_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_llmc_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_llmc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_llmc_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_llmc_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_mc_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_mc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_mc_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_mc_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_myip
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_myip
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_myip_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_myip_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_modify_with_ipv4_urpf_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_modify_with_ipv4_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_modify_with_ipv4_urpf_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_modify_with_ipv4_urpf_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_lpm_match_spec_t *match_spec,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_modify_with_urpf_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_modify_with_urpf_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_table_modify_with_urpf_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_table_modify_with_urpf_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_modify_with_ipv4_urpf_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_modify_with_ipv4_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_urpf_table_modify_with_ipv4_urpf_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_table_modify_with_ipv4_urpf_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_match_spec_t *match_spec,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_malformed_outer_ipv6_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_malformed_outer_ipv6_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_malformed_outer_ipv6_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_malformed_outer_ipv6_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_llmc_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_llmc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_llmc_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_llmc_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_mc_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_mc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_mc_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_mc_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_myip
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_myip
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_myip_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_myip_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_modify_with_ipv6_urpf_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_modify_with_ipv6_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_modify_with_ipv6_urpf_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_modify_with_ipv6_urpf_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_lpm_match_spec_t *match_spec,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_modify_with_urpf_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_modify_with_urpf_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_table_modify_with_urpf_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_table_modify_with_urpf_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_lpm_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_modify_with_ipv6_urpf_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_modify_with_ipv6_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_urpf_table_modify_with_ipv6_urpf_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_table_modify_with_ipv6_urpf_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_match_spec_t *match_spec,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_outer_rmac_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_outer_rmac_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_outer_rmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_outer_rmac_table_modify_with_outer_rmac_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_modify_with_outer_rmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_outer_rmac_table_modify_with_outer_rmac_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_table_modify_with_outer_rmac_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_outer_rmac_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_lookup_flag
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_lookup_flag_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_lookup_flag_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_src_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_modify_with_src_vtep_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_modify_with_src_vtep_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_table_modify_with_src_vtep_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_table_modify_with_src_vtep_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_src_vtep_match_spec_t *match_spec,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_lookup_flag
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_lookup_flag_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_lookup_flag_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_src_vtep_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_modify_with_src_vtep_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_modify_with_src_vtep_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_table_modify_with_src_vtep_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_table_modify_with_src_vtep_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_src_vtep_match_spec_t *match_spec,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_tunnel_lookup_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_tunnel_lookup_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_tunnel_lookup_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_tunnel_lookup_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_non_ip
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_non_ip_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_non_ip_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv4
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv4_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv4_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv4
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv4_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv4_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv6
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv6_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv6_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv6
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv6_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_tunnel_inner_ipv6_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_eompls
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_eompls
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_eompls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_eompls_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_eompls_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_eompls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_vpls
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_vpls
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_vpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_vpls_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_vpls_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_vpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_ipv4_over_mpls
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_ipv4_over_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_ipv4_over_mpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_ipv4_over_mpls_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_ipv4_over_mpls_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_ipv4_over_mpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_ipv6_over_mpls
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_ipv6_over_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_ipv6_over_mpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_ipv6_over_mpls_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_ipv6_over_mpls_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_ipv6_over_mpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_pw
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_pw
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_terminate_pw_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_terminate_pw_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_terminate_pw_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_terminate_pw_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_forward_mpls
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_forward_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_forward_mpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_table_modify_with_forward_mpls_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_table_modify_with_forward_mpls_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_forward_mpls_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_modify_with_non_ip_lkp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_modify_with_non_ip_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_modify_with_non_ip_lkp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_modify_with_non_ip_lkp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv4_lkp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv4_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv4_lkp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv4_lkp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv6_lkp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv6_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv6_lkp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_table_modify_with_ipv6_lkp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_modify_with_non_ip_lkp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_modify_with_non_ip_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_modify_with_non_ip_lkp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_modify_with_non_ip_lkp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv4_lkp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv4_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv4_lkp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv4_lkp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv6_lkp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv6_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv6_lkp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_table_modify_with_ipv6_lkp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_check_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_check_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_check_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_tunnel_check_table_modify_with_tunnel_check_pass
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_modify_with_tunnel_check_pass
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_check_table_modify_with_tunnel_check_pass_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_table_modify_with_tunnel_check_pass_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_check_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_validate_mpls_packet_table_modify_with_set_valid_mpls_label
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_mpls_packet_table_modify_with_set_valid_mpls_label
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_validate_mpls_packet_table_modify_with_set_valid_mpls_label_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_validate_mpls_packet_table_modify_with_set_valid_mpls_label_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_validate_mpls_packet_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv4
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv4_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv4_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_non_ip
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_non_ip_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_non_ip_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv4
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv4_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv4_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_non_ip
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_non_ip_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_non_ip_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv4
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv4_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv4_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_non_ip
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_non_ip_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_non_ip_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv4
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv4_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv4_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv6
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv6_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv6_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv6
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv6_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv6_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv6
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv6_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv6_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv6
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv6_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv6_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv4
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv4_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv4_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_non_ip
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_non_ip_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_non_ip_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv6
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv6_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv6_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop1
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop1_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop1_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop1
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop1_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop1_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop1
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop1_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop1_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop2
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop2_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop2_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop2
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop2_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop2_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop2
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop2_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop2_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop1
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop1_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop1_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop1
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop1_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop1_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop2
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop2_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop2_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop2
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop2_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop2_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_udp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_udp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_udp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_udp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_tcp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_tcp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_tcp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_tcp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_icmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_icmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_icmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_icmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_unknown
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_unknown
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_unknown_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_table_modify_with_decap_inner_unknown_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_egress_vni_table_modify_with_set_egress_tunnel_vni
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_vni_table_modify_with_set_egress_tunnel_vni
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_egress_tunnel_vni_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_vni_table_modify_with_set_egress_tunnel_vni_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_vni_table_modify_with_set_egress_tunnel_vni_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_vni_match_spec_t *match_spec,
 p4_pd_dc_set_egress_tunnel_vni_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_udp_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_udp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_udp_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_udp_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_tcp_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_tcp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_tcp_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_tcp_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_icmp_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_icmp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_icmp_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_icmp_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_unknown_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_unknown_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_unknown_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv4_unknown_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_udp_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_udp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_udp_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_udp_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_tcp_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_tcp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_tcp_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_tcp_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_icmp_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_icmp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_icmp_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_icmp_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_unknown_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_unknown_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_unknown_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_ipv6_unknown_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_non_ip_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_non_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_non_ip_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_table_modify_with_inner_non_ip_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_nvgre_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_nvgre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_nvgre_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_nvgre_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_gre_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_gre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_gre_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_gre_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_ip_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_ip_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_ip_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_gre_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_gre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_gre_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_gre_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_ip_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_ip_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_ip_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_nvgre_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_nvgre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_nvgre_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_nvgre_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push1_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push1_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push1_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push1_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push1_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push1_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push1_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push1_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push2_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push2_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push2_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push2_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push2_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push2_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push3_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push3_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push3_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push3_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push3_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_mpls_ip_push3_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_vxlan_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_vxlan_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_vxlan_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_vxlan_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_genv_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_genv_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_genv_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv4_genv_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_vxlan_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_vxlan_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_vxlan_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_vxlan_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_genv_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_genv_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_genv_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_table_modify_with_ipv6_genv_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv4_tunnel_rewrite_details
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv4_tunnel_rewrite_details
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_ipv4_tunnel_rewrite_details_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv4_tunnel_rewrite_details_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv4_tunnel_rewrite_details_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_ipv4_tunnel_rewrite_details_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv6_tunnel_rewrite_details
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv6_tunnel_rewrite_details
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_ipv6_tunnel_rewrite_details_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv6_tunnel_rewrite_details_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_ipv6_tunnel_rewrite_details_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_ipv6_tunnel_rewrite_details_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push1
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push1
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_mpls_rewrite_push1_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push1_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push1_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_rewrite_push1_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push2
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push2
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_mpls_rewrite_push2_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push2_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push2_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_rewrite_push2_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_mpls_rewrite_push3_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_table_modify_with_set_mpls_rewrite_push3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_rewrite_push3_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv4_dst
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv4_dst
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv4_dst_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv4_dst_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv6_dst
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv6_dst
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv6_dst_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv6_dst_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_smac_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_modify_with_rewrite_tunnel_smac
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_modify_with_rewrite_tunnel_smac
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_rewrite_tunnel_smac_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_table_modify_with_rewrite_tunnel_smac_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_table_modify_with_rewrite_tunnel_smac_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_smac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_smac_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dmac_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_rewrite_tunnel_dmac
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_rewrite_tunnel_dmac
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_rewrite_tunnel_dmac_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_rewrite_tunnel_dmac_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_table_modify_with_rewrite_tunnel_dmac_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_dmac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_rewrite_tunnel_dmac_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_set_tunnel_mgid
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_set_tunnel_mgid
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_tunnel_mgid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_set_tunnel_mgid_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_table_modify_with_set_tunnel_mgid_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t *match_spec,
 p4_pd_dc_set_tunnel_mgid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_src_port_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_modify_with_set_ingress_src_port_range_id
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_modify_with_set_ingress_src_port_range_id
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_ingress_src_port_range_id_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_table_modify_with_set_ingress_src_port_range_id_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_table_modify_with_set_ingress_src_port_range_id_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_src_port_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_ingress_src_port_range_id_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_dst_port_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_modify_with_set_ingress_dst_port_range_id
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_modify_with_set_ingress_dst_port_range_id
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_ingress_dst_port_range_id_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_table_modify_with_set_ingress_dst_port_range_id_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_table_modify_with_set_ingress_dst_port_range_id_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ingress_l4_dst_port_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_ingress_dst_port_range_id_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_deny
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_deny_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_deny_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_permit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_permit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_permit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_redirect_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_redirect_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_redirect_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_redirect_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_mirror
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mac_acl_table_modify_with_acl_mirror_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mac_acl_table_modify_with_acl_mirror_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_deny
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_deny_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_deny_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_permit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_permit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_permit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_redirect_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_redirect_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_redirect_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_redirect_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_mirror
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ip_acl_table_modify_with_acl_mirror_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ip_acl_table_modify_with_acl_mirror_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_deny
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_deny_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_deny_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_permit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_permit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_permit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_redirect_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_mirror
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_acl_table_modify_with_acl_mirror_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_table_modify_with_acl_mirror_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_deny
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_deny_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_deny_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_permit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_permit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_permit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_table_modify_with_racl_redirect_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_deny
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_deny_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_deny_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_deny_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_permit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_permit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_permit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_permit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_nexthop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_nexthop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_nexthop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_ecmp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_ecmp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_table_modify_with_racl_redirect_ecmp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_drop_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_drop_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_drop_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_drop_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_drop_packet_with_reason
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_drop_packet_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_drop_packet_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_drop_packet_with_reason_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_drop_packet_with_reason_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_drop_packet_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_redirect_to_cpu_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_redirect_to_cpu_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_redirect_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu_with_reason_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_redirect_to_cpu_with_reason_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_redirect_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_copy_to_cpu
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_copy_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_copy_to_cpu_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_copy_to_cpu_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_copy_to_cpu_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_copy_to_cpu_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_copy_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_copy_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_copy_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_system_acl_table_modify_with_copy_to_cpu_with_reason_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_system_acl_table_modify_with_copy_to_cpu_with_reason_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_copy_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_drop_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_drop_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_drop_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_drop_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_egress_copy_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu_with_reason_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_copy_to_cpu_with_reason_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_copy_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_egress_redirect_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu_with_reason_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_redirect_to_cpu_with_reason_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_redirect_to_cpu_with_reason_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_coal_hdr
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_coal_hdr
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_egress_mirror_coal_hdr_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_coal_hdr_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_coal_hdr_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_mirror_coal_hdr_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_insert_cpu_timestamp
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_insert_cpu_timestamp
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_insert_cpu_timestamp_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_insert_cpu_timestamp_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_egress_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_mirror_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_and_drop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_and_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_egress_mirror_and_drop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_and_drop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_table_modify_with_egress_mirror_and_drop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_egress_mirror_and_drop_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_bridge_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_modify_with_multicast_route_s_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_modify_with_multicast_route_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_table_modify_with_multicast_route_s_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_table_modify_with_multicast_route_s_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_multicast_route_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_bridge_match_spec_t *match_spec,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_modify_with_on_miss
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_modify_with_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_modify_with_on_miss_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_modify_with_on_miss_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_modify_with_multicast_route_s_g_hit
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_modify_with_multicast_route_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_table_modify_with_multicast_route_s_g_hit_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_table_modify_with_multicast_route_s_g_hit_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_multicast_route_match_spec_t *match_spec,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_bd_flood_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_bd_flood_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_bd_flood_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_bd_flood_table_modify_with_set_bd_flood_mc_index
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_modify_with_set_bd_flood_mc_index
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_bd_flood_mc_index_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_bd_flood_table_modify_with_set_bd_flood_mc_index_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_bd_flood_table_modify_with_set_bd_flood_mc_index_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_bd_flood_match_spec_t *match_spec,
 p4_pd_dc_set_bd_flood_mc_index_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_outer_replica_from_rid
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_outer_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_outer_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_outer_replica_from_rid_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_outer_replica_from_rid_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_outer_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_encap_replica_from_rid
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_encap_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_encap_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_encap_replica_from_rid_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_encap_replica_from_rid_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_encap_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_inner_replica_from_rid
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_inner_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_inner_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_inner_replica_from_rid_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_inner_replica_from_rid_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_inner_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_unicast_replica_from_rid
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_unicast_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_unicast_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rid_table_modify_with_unicast_replica_from_rid_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rid_table_modify_with_unicast_replica_from_rid_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_unicast_replica_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mcast_egress_ifindex_table_modify_with_set_egress_ifindex_from_rid
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_table_modify_with_set_egress_ifindex_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_egress_ifindex_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mcast_egress_ifindex_table_modify_with_set_egress_ifindex_from_rid_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_table_modify_with_set_egress_ifindex_from_rid_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mcast_egress_ifindex_match_spec_t *match_spec,
 p4_pd_dc_set_egress_ifindex_from_rid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_replica_type_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_replica_type_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_replica_type_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_replica_type_table_modify_with_set_replica_copy_bridged
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_modify_with_set_replica_copy_bridged
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_replica_type_table_modify_with_set_replica_copy_bridged_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_replica_type_table_modify_with_set_replica_copy_bridged_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_replica_type_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_l2_redirect
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_l2_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_l2_redirect_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_l2_redirect_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_fib_redirect
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_fib_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_fib_redirect_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_fib_redirect_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_cpu_redirect
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_cpu_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_cpu_redirect_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_cpu_redirect_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_cpu_redirect_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_cpu_redirect_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_acl_redirect
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_acl_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_acl_redirect_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_acl_redirect_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_racl_redirect
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_racl_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_racl_redirect_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_racl_redirect_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_rmac_non_ip_drop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_rmac_non_ip_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_rmac_non_ip_drop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_rmac_non_ip_drop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_route
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_route
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_route_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_route_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_bridge
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_bridge
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_bridge_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_bridge_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_flood_to_mrouters
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_flood_to_mrouters
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_flood_to_mrouters_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_rpf_fail_flood_to_mrouters_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_bridge
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_bridge
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_bridge_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_bridge_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood_to_mrouters
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood_to_mrouters
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood_to_mrouters_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_miss_flood_to_mrouters_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_drop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_table_modify_with_set_multicast_drop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_fwd_result_table_modify_with_set_multicast_drop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_nexthop_details_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_with_tunnel
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_nexthop_details_with_tunnel_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_with_tunnel_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_with_tunnel_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_with_tunnel_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_post_routed_flood
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_post_routed_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_post_routed_flood_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_post_routed_flood_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_glean
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_glean
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_nexthop_details_for_glean_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_glean_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_glean_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_set_nexthop_details_for_glean_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_drop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_drop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_drop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_nexthop_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite_with_tunnel
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite_with_tunnel_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite_with_tunnel_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_vnid
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_vnid
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_vnid_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_vnid_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_and_ingress_vrf
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_and_ingress_vrf
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_and_ingress_vrf_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel_and_ingress_vrf_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_l3_rewrite_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_l3_rewrite_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l2
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l2
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_mpls_push_rewrite_l2_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l2_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l2_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_push_rewrite_l2_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_mpls_swap_push_rewrite_l3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_mpls_swap_push_rewrite_l3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_mpls_swap_push_rewrite_l3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_mpls_swap_push_rewrite_l3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l3
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l3
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_mpls_push_rewrite_l3_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l3_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_rewrite_table_modify_with_set_mpls_push_rewrite_l3_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_set_mpls_push_rewrite_l3_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_stats_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_modify_with___meta_init_miss_action_storm_control_stats__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_modify_with___meta_init_miss_action_storm_control_stats__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_storm_control_stats_table_modify_with___meta_init_miss_action_storm_control_stats___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_table_modify_with___meta_init_miss_action_storm_control_stats___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_stats_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_storm_control_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_storm_control_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_match_spec_t *match_spec,
 int priority
);

/**
 * @brief p4_pd_dc_storm_control_table_modify_with_set_storm_control_meter
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_modify_with_set_storm_control_meter
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_storm_control_meter_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_storm_control_table_modify_with_set_storm_control_meter_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param priority
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_storm_control_table_modify_with_set_storm_control_meter_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_storm_control_match_spec_t *match_spec,
 int priority,
 p4_pd_dc_set_storm_control_meter_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_terminate_cpu_packet
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_terminate_cpu_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_terminate_cpu_packet_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_table_modify_with_terminate_cpu_packet_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_nop
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_nop_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_nop_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_set_mirror_bd
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_set_mirror_bd
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_set_mirror_bd_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_set_mirror_bd_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_set_mirror_bd_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_dc_set_mirror_bd_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
 * @param action_spec
*/
p4_pd_status_t
p4_pd_dc_mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t *action_spec
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_modify_with_compute_lkp_ipv4_hash
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_modify_with_compute_lkp_ipv4_hash
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_modify_with_compute_lkp_ipv4_hash_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_modify_with_compute_lkp_ipv4_hash_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv4_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_modify_with___meta_init_miss_action_compute_ipv4_hashes__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_modify_with___meta_init_miss_action_compute_ipv4_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_table_modify_with___meta_init_miss_action_compute_ipv4_hashes___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_table_modify_with___meta_init_miss_action_compute_ipv4_hashes___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv4_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_modify_with_compute_lkp_ipv6_hash
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_modify_with_compute_lkp_ipv6_hash
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_modify_with_compute_lkp_ipv6_hash_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_modify_with_compute_lkp_ipv6_hash_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv6_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_modify_with___meta_init_miss_action_compute_ipv6_hashes__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_modify_with___meta_init_miss_action_compute_ipv6_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_table_modify_with___meta_init_miss_action_compute_ipv6_hashes___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_table_modify_with___meta_init_miss_action_compute_ipv6_hashes___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_ipv6_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_modify_with_compute_lkp_non_ip_hash
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_modify_with_compute_lkp_non_ip_hash
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_modify_with_compute_lkp_non_ip_hash_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_modify_with_compute_lkp_non_ip_hash_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_non_ip_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_modify_with___meta_init_miss_action_compute_non_ip_hashes__
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_modify_with___meta_init_miss_action_compute_non_ip_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_table_modify_with___meta_init_miss_action_compute_non_ip_hashes___by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_table_modify_with___meta_init_miss_action_compute_non_ip_hashes___by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_non_ip_hashes_match_spec_t *match_spec
);

/**
 * @brief p4_pd_dc_compute_other_hashes_table_modify_with_compute_other_hashes
 * @param sess_hdl
 * @param dev_id
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_other_hashes_table_modify_with_compute_other_hashes
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t ent_hdl
);

/**
 * @brief p4_pd_dc_compute_other_hashes_table_modify_with_compute_other_hashes_by_match_spec
 * @param sess_hdl
 * @param dev_tgt
 * @param match_spec
*/
p4_pd_status_t
p4_pd_dc_compute_other_hashes_table_modify_with_compute_other_hashes_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_compute_other_hashes_match_spec_t *match_spec
);



/* SET DEFAULT_ACTION */

/**
 * @brief p4_pd_dc_switch_config_params_set_default_action_set_config_parameters
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_switch_config_params_set_default_action_set_config_parameters
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_config_parameters_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_malformed_outer_ethernet_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_malformed_outer_ethernet_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_qinq_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_qinq_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_port_mapping_set_default_action_set_port_lag_index
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_port_mapping_set_default_action_set_port_lag_index
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_port_lag_index_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_set_default_action_set_ingress_interface_properties
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_set_default_action_set_ingress_interface_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ingress_interface_properties_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_set_default_action___meta_init_miss_action_port_vlan_to_ifindex_mapping__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_set_default_action___meta_init_miss_action_port_vlan_to_ifindex_mapping__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_port_vlan_to_ifindex_mapping_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_bd_stats_set_default_action_update_ingress_bd_stats
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_bd_stats_set_default_action_update_ingress_bd_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_set_default_action_egress_port_type_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_set_default_action_egress_port_type_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_set_default_action___meta_init_miss_action_egress_port_mapping__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_set_default_action___meta_init_miss_action_egress_port_mapping__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_port_mapping_set_default_action_egress_port_type_normal
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_port_mapping_set_default_action_egress_port_type_normal
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_port_type_normal_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_set_default_action_set_egress_if_params_untagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_set_default_action_set_egress_if_params_untagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vlan_xlate_set_default_action_set_egress_if_params_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_set_default_action_set_egress_if_params_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_egress_if_params_tagged_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_capture_tstamp_set_default_action_set_capture_tstamp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_capture_tstamp_set_default_action_set_capture_tstamp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_spanning_tree_set_default_action_set_stp_state
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_spanning_tree_set_default_action_set_stp_state
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_stp_state_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_set_default_action_smac_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_set_default_action_smac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_set_default_action_smac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_set_default_action_smac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_smac_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_set_default_action_dmac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_set_default_action_dmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_set_default_action_dmac_multicast_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_set_default_action_dmac_multicast_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_multicast_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_set_default_action_dmac_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_set_default_action_dmac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_set_default_action_dmac_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_set_default_action_dmac_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_set_default_action_dmac_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_set_default_action_dmac_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_dmac_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_dmac_set_default_action_dmac_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_dmac_set_default_action_dmac_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_learn_notify_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_learn_notify_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_learn_notify_set_default_action_generate_learn_notify
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_learn_notify_set_default_action_generate_learn_notify
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_set_default_action_set_unicast
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_set_default_action_set_unicast
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_set_default_action_set_unicast_and_ipv6_src_is_link_local
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_set_default_action_set_unicast_and_ipv6_src_is_link_local
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_set_default_action_set_multicast
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_set_default_action_set_multicast
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_set_default_action_set_multicast_and_ipv6_src_is_link_local
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_set_default_action_set_multicast_and_ipv6_src_is_link_local
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_set_default_action_set_broadcast
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_set_default_action_set_broadcast
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_packet_set_default_action_set_malformed_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_packet_set_default_action_set_malformed_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_malformed_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_stats_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_stats_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_set_default_action_set_egress_bd_properties
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_set_default_action_set_egress_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_egress_bd_properties_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_bd_map_set_default_action___meta_init_miss_action_egress_bd_map__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_bd_map_set_default_action___meta_init_miss_action_egress_bd_map__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_set_default_action_set_egress_outer_bd_properties
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_set_default_action_set_egress_outer_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_egress_outer_bd_properties_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_outer_bd_map_set_default_action___meta_init_miss_action_egress_outer_bd_map__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_set_default_action___meta_init_miss_action_egress_outer_bd_map__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_vlan_decap_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_vlan_decap_set_default_action_remove_vlan_single_tagged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_vlan_decap_set_default_action_remove_vlan_single_tagged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rmac_set_default_action_rmac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_set_default_action_rmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rmac_set_default_action___meta_init_miss_action_rmac__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_set_default_action___meta_init_miss_action_rmac__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rmac_set_default_action_rmac_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rmac_set_default_action_rmac_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_urpf_bd_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_urpf_bd_set_default_action_urpf_bd_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_urpf_bd_set_default_action_urpf_bd_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_smac_rewrite_set_default_action_rewrite_smac
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_smac_rewrite_set_default_action_rewrite_smac
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_smac_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_set_default_action_ipv4_unicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_set_default_action_ipv4_unicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_set_default_action_ipv4_multicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_set_default_action_ipv4_multicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_set_default_action_ipv6_unicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_set_default_action_ipv6_unicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_set_default_action_ipv6_multicast_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_set_default_action_ipv6_multicast_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_l3_rewrite_set_default_action_mpls_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_l3_rewrite_set_default_action_mpls_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mtu_set_default_action_mtu_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_set_default_action_mtu_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mtu_set_default_action_ipv4_mtu_check
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_set_default_action_ipv4_mtu_check
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_mtu_check_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mtu_set_default_action_ipv6_mtu_check
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mtu_set_default_action_ipv6_mtu_check
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_mtu_check_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_malformed_outer_ipv4_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_malformed_outer_ipv4_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_llmc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_llmc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_mc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_mc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_set_default_action_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_set_default_action_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_set_default_action_fib_hit_myip
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_set_default_action_fib_hit_myip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_set_default_action_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_set_default_action_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_set_default_action_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_set_default_action_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_fib_lpm_set_default_action_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_set_default_action_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_set_default_action_ipv4_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_set_default_action_ipv4_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_lpm_set_default_action_urpf_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_set_default_action_urpf_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_urpf_set_default_action_ipv4_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_urpf_set_default_action_ipv4_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_malformed_outer_ipv6_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_malformed_outer_ipv6_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_llmc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_llmc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_mc_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_mc_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_set_default_action_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_set_default_action_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_lpm_set_default_action_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_set_default_action_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_set_default_action_fib_hit_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_set_default_action_fib_hit_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_set_default_action_fib_hit_myip
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_set_default_action_fib_hit_myip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_myip_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_fib_set_default_action_fib_hit_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_fib_set_default_action_fib_hit_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_fib_hit_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_set_default_action_ipv6_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_set_default_action_ipv6_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_lpm_set_default_action_urpf_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_set_default_action_urpf_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_urpf_set_default_action_ipv6_urpf_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_urpf_set_default_action_ipv6_urpf_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv6_urpf_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_outer_rmac_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_outer_rmac_set_default_action_outer_rmac_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_outer_rmac_set_default_action_outer_rmac_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_set_default_action_set_tunnel_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_set_default_action_set_tunnel_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_dest_vtep_set_default_action_set_tunnel_vni_and_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_set_default_action_set_tunnel_vni_and_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_src_vtep_set_default_action_src_vtep_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_set_default_action_src_vtep_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_set_default_action_set_tunnel_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_set_default_action_set_tunnel_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_tunnel_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_dest_vtep_set_default_action_set_tunnel_vni_and_lookup_flag
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_set_default_action_set_tunnel_vni_and_lookup_flag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_tunnel_vni_and_lookup_flag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_src_vtep_set_default_action_src_vtep_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_set_default_action_src_vtep_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_src_vtep_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_tunnel_lookup_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_tunnel_lookup_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ethernet_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ethernet_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ethernet_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ethernet_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_tunnel_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_eompls
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_eompls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_eompls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_vpls
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_vpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_vpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_ipv4_over_mpls
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_ipv4_over_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_ipv4_over_mpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_ipv6_over_mpls
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_ipv6_over_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_ipv6_over_mpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_terminate_pw
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_terminate_pw
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_terminate_pw_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_set_default_action_forward_mpls
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_set_default_action_forward_mpls
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_forward_mpls_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_set_default_action_non_ip_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_set_default_action_non_ip_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_set_default_action_ipv4_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_set_default_action_ipv4_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_adjust_lkp_fields_set_default_action_ipv6_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_set_default_action_ipv6_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_set_default_action_non_ip_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_set_default_action_non_ip_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_set_default_action_ipv4_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_set_default_action_ipv4_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_lookup_miss_set_default_action_ipv6_lkp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_set_default_action_ipv6_lkp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_check_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_check_set_default_action_tunnel_check_pass
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_check_set_default_action_tunnel_check_pass
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_genv_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_genv_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_genv_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_genv_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_gre_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_gre_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_gre_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_gre_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_ip_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_ip_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_genv_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_genv_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_gre_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_gre_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_ip_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_ip_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_ipv4
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_ipv4
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_non_ip
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_non_ip
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_ipv6
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_ipv6
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop1
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop2
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop3
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_udp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_udp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_tcp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_tcp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_icmp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_icmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_unknown
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_set_default_action_decap_inner_unknown
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_vni_set_default_action_set_egress_tunnel_vni
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_vni_set_default_action_set_egress_tunnel_vni
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_egress_tunnel_vni_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_udp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_udp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_tcp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_tcp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_icmp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_icmp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_unknown_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv4_unknown_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_udp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_udp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_tcp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_tcp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_icmp_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_icmp_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_unknown_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_ipv6_unknown_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_non_ip_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_set_default_action_inner_non_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_nvgre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_nvgre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_gre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_gre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_ip_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_gre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_gre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_ip_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_ip_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_nvgre_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_nvgre_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ethernet_push1_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ethernet_push1_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ip_push1_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ip_push1_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ethernet_push2_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ethernet_push2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ip_push2_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ip_push2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ethernet_push3_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ethernet_push3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ip_push3_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_mpls_ip_push3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_vxlan_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_vxlan_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_genv_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv4_genv_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_vxlan_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_vxlan_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_genv_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_set_default_action_ipv6_genv_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_set_default_action_set_ipv4_tunnel_rewrite_details
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_set_default_action_set_ipv4_tunnel_rewrite_details
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ipv4_tunnel_rewrite_details_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_set_default_action_set_ipv6_tunnel_rewrite_details
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_set_default_action_set_ipv6_tunnel_rewrite_details
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ipv6_tunnel_rewrite_details_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_set_default_action_set_mpls_rewrite_push1
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_set_default_action_set_mpls_rewrite_push1
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_mpls_rewrite_push1_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_set_default_action_set_mpls_rewrite_push2
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_set_default_action_set_mpls_rewrite_push2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_mpls_rewrite_push2_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_rewrite_set_default_action_set_mpls_rewrite_push3
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_rewrite_set_default_action_set_mpls_rewrite_push3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_mpls_rewrite_push3_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dst_rewrite_set_default_action_rewrite_tunnel_ipv4_dst
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_set_default_action_rewrite_tunnel_ipv4_dst
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_smac_rewrite_set_default_action_rewrite_tunnel_smac
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_set_default_action_rewrite_tunnel_smac
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_tunnel_smac_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_dmac_rewrite_set_default_action_rewrite_tunnel_dmac
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_set_default_action_rewrite_tunnel_dmac
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_rewrite_tunnel_dmac_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_tunnel_to_mgid_mapping_set_default_action_set_tunnel_mgid
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_set_default_action_set_tunnel_mgid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_tunnel_mgid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_src_port_set_default_action_set_ingress_src_port_range_id
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_set_default_action_set_ingress_src_port_range_id
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ingress_src_port_range_id_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ingress_l4_dst_port_set_default_action_set_ingress_dst_port_range_id
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_set_default_action_set_ingress_dst_port_range_id
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ingress_dst_port_range_id_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_set_default_action_acl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_set_default_action_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_set_default_action_acl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_set_default_action_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_set_default_action_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_set_default_action_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_set_default_action_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_set_default_action_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mac_acl_set_default_action_acl_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mac_acl_set_default_action_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_set_default_action_acl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_set_default_action_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_set_default_action_acl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_set_default_action_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_set_default_action_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_set_default_action_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_set_default_action_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_set_default_action_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ip_acl_set_default_action_acl_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ip_acl_set_default_action_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_set_default_action_acl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_set_default_action_acl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_set_default_action_acl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_set_default_action_acl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_set_default_action_acl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_set_default_action_acl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_set_default_action_acl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_set_default_action_acl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_acl_set_default_action_acl_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_acl_set_default_action_acl_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_acl_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_set_default_action_racl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_set_default_action_racl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_set_default_action_racl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_set_default_action_racl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_set_default_action_racl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_set_default_action_racl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_racl_set_default_action_racl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_racl_set_default_action_racl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_set_default_action_racl_deny
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_set_default_action_racl_deny
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_deny_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_set_default_action_racl_permit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_set_default_action_racl_permit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_permit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_set_default_action_racl_redirect_nexthop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_set_default_action_racl_redirect_nexthop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_redirect_nexthop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_racl_set_default_action_racl_redirect_ecmp
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_racl_set_default_action_racl_redirect_ecmp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_racl_redirect_ecmp_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_acl_stats_set_default_action_acl_stats_update
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_acl_stats_set_default_action_acl_stats_update
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_racl_stats_set_default_action_racl_stats_update
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_racl_stats_set_default_action_racl_stats_update
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_set_default_action_drop_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_set_default_action_drop_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_set_default_action_drop_packet_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_set_default_action_drop_packet_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_drop_packet_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_set_default_action_redirect_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_set_default_action_redirect_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_redirect_to_cpu_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_set_default_action_redirect_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_set_default_action_redirect_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_redirect_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_set_default_action_copy_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_set_default_action_copy_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_copy_to_cpu_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_system_acl_set_default_action_copy_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_system_acl_set_default_action_copy_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_copy_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_drop_stats_set_default_action_drop_stats_update
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_drop_stats_set_default_action_drop_stats_update
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_drop_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_drop_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_copy_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_copy_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_redirect_to_cpu
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_redirect_to_cpu
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_copy_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_copy_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_copy_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_redirect_to_cpu_with_reason
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_redirect_to_cpu_with_reason
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_redirect_to_cpu_with_reason_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_mirror_coal_hdr
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_mirror_coal_hdr
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_mirror_coal_hdr_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_insert_cpu_timestamp
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_insert_cpu_timestamp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_mirror
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_mirror
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_mirror_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_egress_system_acl_set_default_action_egress_mirror_and_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_egress_system_acl_set_default_action_egress_mirror_and_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_egress_mirror_and_drop_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_star_g_set_default_action_multicast_bridge_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_set_default_action_multicast_bridge_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_bridge_set_default_action_multicast_bridge_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_set_default_action_multicast_bridge_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_set_default_action_multicast_route_star_g_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_set_default_action_multicast_route_star_g_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_set_default_action_multicast_route_sm_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_set_default_action_multicast_route_sm_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_star_g_set_default_action_multicast_route_bidir_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_set_default_action_multicast_route_bidir_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv4_multicast_route_set_default_action_multicast_route_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_set_default_action_multicast_route_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_star_g_set_default_action_multicast_bridge_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_set_default_action_multicast_bridge_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_bridge_set_default_action_multicast_bridge_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_set_default_action_multicast_bridge_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_set_default_action_multicast_route_star_g_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_set_default_action_multicast_route_star_g_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_set_default_action_multicast_route_sm_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_set_default_action_multicast_route_sm_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_star_g_set_default_action_multicast_route_bidir_star_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_set_default_action_multicast_route_bidir_star_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_set_default_action_on_miss
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_set_default_action_on_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_ipv6_multicast_route_set_default_action_multicast_route_s_g_hit
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_set_default_action_multicast_route_s_g_hit
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_multicast_route_s_g_hit_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_bd_flood_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_bd_flood_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_bd_flood_set_default_action_set_bd_flood_mc_index
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_bd_flood_set_default_action_set_bd_flood_mc_index
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_bd_flood_mc_index_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_set_default_action_outer_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_set_default_action_outer_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_outer_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_set_default_action_encap_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_set_default_action_encap_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_encap_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_set_default_action_inner_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_set_default_action_inner_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_inner_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rid_set_default_action_unicast_replica_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rid_set_default_action_unicast_replica_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_unicast_replica_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mcast_egress_ifindex_set_default_action_set_egress_ifindex_from_rid
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_set_default_action_set_egress_ifindex_from_rid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_egress_ifindex_from_rid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_replica_type_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_replica_type_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_replica_type_set_default_action_set_replica_copy_bridged
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_replica_type_set_default_action_set_replica_copy_bridged
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_l2_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_l2_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_fib_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_fib_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_cpu_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_cpu_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_cpu_redirect_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_acl_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_acl_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_racl_redirect
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_racl_redirect
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_rmac_non_ip_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_rmac_non_ip_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_multicast_route
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_multicast_route
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_multicast_rpf_fail_bridge
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_multicast_rpf_fail_bridge
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_multicast_rpf_fail_flood_to_mrouters
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_multicast_rpf_fail_flood_to_mrouters
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_multicast_bridge
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_multicast_bridge
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_multicast_miss_flood
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_multicast_miss_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_multicast_miss_flood_to_mrouters
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_multicast_miss_flood_to_mrouters
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fwd_result_set_default_action_set_multicast_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fwd_result_set_default_action_set_multicast_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_set_default_action_set_nexthop_details
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_set_default_action_set_nexthop_details
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_nexthop_details_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_set_default_action_set_nexthop_details_with_tunnel
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_set_default_action_set_nexthop_details_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_nexthop_details_with_tunnel_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_set_default_action_set_nexthop_details_for_post_routed_flood
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_set_default_action_set_nexthop_details_for_post_routed_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_set_default_action_set_nexthop_details_for_glean
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_set_default_action_set_nexthop_details_for_glean
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_nexthop_details_for_glean_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_nexthop_set_default_action_set_nexthop_details_for_drop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_nexthop_set_default_action_set_nexthop_details_for_drop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_l2_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_l2_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_l2_rewrite_with_tunnel
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_l2_rewrite_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_l3_rewrite_with_tunnel
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_l3_rewrite_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_l3_rewrite_with_tunnel_vnid
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_l3_rewrite_with_tunnel_vnid
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_l3_rewrite_with_tunnel_and_ingress_vrf
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_l3_rewrite_with_tunnel_and_ingress_vrf
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_l3_rewrite
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_l3_rewrite
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_l3_rewrite_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_mpls_push_rewrite_l2
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_mpls_push_rewrite_l2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_mpls_push_rewrite_l2_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_mpls_swap_push_rewrite_l3
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_mpls_swap_push_rewrite_l3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_rewrite_set_default_action_set_mpls_push_rewrite_l3
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_rewrite_set_default_action_set_mpls_push_rewrite_l3
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_mpls_push_rewrite_l3_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_stats_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_stats_set_default_action___meta_init_miss_action_storm_control_stats__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_stats_set_default_action___meta_init_miss_action_storm_control_stats__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_storm_control_set_default_action_set_storm_control_meter
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_storm_control_set_default_action_set_storm_control_meter
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_storm_control_meter_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_fabric_ingress_dst_lkp_set_default_action_terminate_cpu_packet
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_set_default_action_terminate_cpu_packet
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_set_default_action_nop
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_set_default_action_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_set_default_action_set_mirror_bd
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_set_default_action_set_mirror_bd
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_mirror_bd_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_set_default_action_ipv4_erspan_t3_rewrite_with_eth_hdr
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_set_default_action_ipv4_erspan_t3_rewrite_with_eth_hdr
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_mirror_set_default_action_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag
 * @param sess_hdl
 * @param dev_tgt
 * @param action_spec
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_mirror_set_default_action_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t *action_spec,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv4_hashes_set_default_action___meta_init_miss_action_compute_ipv4_hashes__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_set_default_action___meta_init_miss_action_compute_ipv4_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_ipv6_hashes_set_default_action___meta_init_miss_action_compute_ipv6_hashes__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_set_default_action___meta_init_miss_action_compute_ipv6_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_non_ip_hashes_set_default_action___meta_init_miss_action_compute_non_ip_hashes__
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_set_default_action___meta_init_miss_action_compute_non_ip_hashes__
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);

/**
 * @brief p4_pd_dc_compute_other_hashes_set_default_action_compute_other_hashes
 * @param sess_hdl
 * @param dev_tgt
 * @param entry_hdl
*/
p4_pd_status_t
p4_pd_dc_compute_other_hashes_set_default_action_compute_other_hashes
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t *entry_hdl
);



/* INDIRECT ACTION DATA AND MATCH SELECT */

p4_pd_status_t
p4_pd_dc_bd_action_profile_add_member_with_set_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_bd_properties_action_spec_t *action_spec,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_bd_action_profile_modify_member_with_set_bd_properties
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_dc_set_bd_properties_action_spec_t *action_spec
);
p4_pd_status_t
p4_pd_dc_bd_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_bd_action_profile_add_member_with_port_vlan_mapping_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_bd_action_profile_modify_member_with_port_vlan_mapping_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl
);
p4_pd_status_t
p4_pd_dc_bd_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_bd_action_profile_del_member
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_add_member_with_set_lag_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_modify_member_with_set_lag_miss
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl
);
p4_pd_status_t
p4_pd_dc_lag_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_lag_action_profile_add_member_with_set_lag_port
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_lag_port_action_spec_t *action_spec,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_modify_member_with_set_lag_port
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_dc_set_lag_port_action_spec_t *action_spec
);
p4_pd_status_t
p4_pd_dc_lag_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_lag_action_profile_del_member
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_register_callback
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_sel_tbl_update_cb cb,
 void *cb_ctx
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_create_group
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t max_grp_size,
 p4_pd_grp_hdl_t *grp_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_del_group
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_add_member_to_group
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_del_member_from_group
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_group_member_state_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl,
 enum p4_pd_grp_mbr_state_e mbr_state
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_group_member_state_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl,
 enum p4_pd_grp_mbr_state_e *mbr_state_p
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_set_dynamic_action_selection_fallback_member
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_reset_dynamic_action_selection_fallback_member
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_sel_track_updates
(
 uint8_t dev_id,
 int (*cb_func)(p4_pd_sess_hdl_t, p4_pd_dev_target_t, void*, unsigned int, unsigned int, int, bool),
 void *cookie
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_add_member_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_modify_member_with_nop
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_add_member_with_set_ecmp_nexthop_details
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ecmp_nexthop_details_action_spec_t *action_spec,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_modify_member_with_set_ecmp_nexthop_details
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_dc_set_ecmp_nexthop_details_action_spec_t *action_spec
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_add_member_with_set_ecmp_nexthop_details_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ecmp_nexthop_details_with_tunnel_action_spec_t *action_spec,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_modify_member_with_set_ecmp_nexthop_details_with_tunnel
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_dc_set_ecmp_nexthop_details_with_tunnel_action_spec_t *action_spec
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_add_member_with_set_ecmp_nexthop_details_for_post_routed_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec_t *action_spec,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_modify_member_with_set_ecmp_nexthop_details_for_post_routed_flood
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec_t *action_spec
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_set_property
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_tbl_prop_type_t property,
 p4_pd_tbl_prop_value_t value
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_del_member
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_register_callback
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_sel_tbl_update_cb cb,
 void *cb_ctx
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_create_group
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t max_grp_size,
 p4_pd_grp_hdl_t *grp_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_del_group
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_add_member_to_group
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_del_member_from_group
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_group_member_state_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl,
 enum p4_pd_grp_mbr_state_e mbr_state
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_group_member_state_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_mbr_hdl_t mbr_hdl,
 enum p4_pd_grp_mbr_state_e *mbr_state_p
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_set_dynamic_action_selection_fallback_member
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_reset_dynamic_action_selection_fallback_member
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_sel_track_updates
(
 uint8_t dev_id,
 int (*cb_func)(p4_pd_sess_hdl_t, p4_pd_dev_target_t, void*, unsigned int, unsigned int, int, bool),
 void *cookie
);


p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_add_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_bd_mapping_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_add_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_cpu_packet_transform_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_add_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_lag_group_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_add_entry_with_selector
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_lag_group_match_spec_t *match_spec,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_add_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ecmp_group_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_add_entry_with_selector
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ecmp_group_match_spec_t *match_spec,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);



p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_modify_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_modify_entry_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_bd_mapping_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_modify_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_modify_entry_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_cpu_packet_transform_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_modify_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_modify_entry_with_selector
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_grp_hdl_t grp_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_modify_entry_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_lag_group_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_modify_entry_with_selector_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_lag_group_match_spec_t *match_spec,
 p4_pd_grp_hdl_t grp_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_modify_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_modify_entry_with_selector
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_grp_hdl_t grp_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_modify_entry_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ecmp_group_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_modify_entry_with_selector_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ecmp_group_match_spec_t *match_spec,
 p4_pd_grp_hdl_t grp_hdl
);



p4_pd_status_t
p4_pd_dc_switch_config_params_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_lag_group_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_spanning_tree_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_smac_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_dmac_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_learn_notify_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_validate_packet_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_vlan_decap_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_rmac_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_urpf_bd_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_mtu_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_outer_rmac_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_check_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_egress_vni_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_mac_acl_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ip_acl_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_acl_stats_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_racl_stats_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_system_acl_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_drop_stats_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_bd_flood_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_rid_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_replica_type_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_fwd_result_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ecmp_group_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_nexthop_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_rewrite_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_storm_control_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_mirror_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_get_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);


p4_pd_status_t
p4_pd_dc_bd_action_profile_get_act_prof_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_act_prof_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_selector_group_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_act_prof_entry_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_selector_group_count
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 uint32_t *count
);


p4_pd_status_t
p4_pd_dc_switch_config_params_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_switch_config_params_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_switch_config_params_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_validate_outer_ethernet_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_validate_outer_ethernet_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ingress_port_mapping_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ingress_port_mapping_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ingress_port_properties_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ingress_port_properties_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_port_vlan_to_bd_mapping_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_ifindex_mapping_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_port_vlan_to_ifindex_mapping_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_cpu_packet_transform_match_spec_t *match_spec,
 p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ingress_bd_stats_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_lag_group_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_lag_group_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_lag_group_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_lag_group_match_spec_t *match_spec,
 bool *has_mbr_hdl, bool *has_grp_hdl, p4_pd_grp_hdl_t *grp_hdl, p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_egress_port_mapping_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_egress_port_mapping_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_egress_vlan_xlate_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_egress_vlan_xlate_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_capture_tstamp_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_spanning_tree_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_spanning_tree_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_spanning_tree_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_spanning_tree_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_smac_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_smac_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_smac_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_smac_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_dmac_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_dmac_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_dmac_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_dmac_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_learn_notify_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_learn_notify_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_learn_notify_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_learn_notify_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_validate_packet_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_validate_packet_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_validate_packet_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_validate_packet_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_egress_bd_stats_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_egress_bd_stats_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_egress_bd_map_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_egress_bd_map_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_egress_outer_bd_map_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_egress_outer_bd_map_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_vlan_decap_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_vlan_decap_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_vlan_decap_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_vlan_decap_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_rmac_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_rmac_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_rmac_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_rmac_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_urpf_bd_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_urpf_bd_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_urpf_bd_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_urpf_bd_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_smac_rewrite_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_smac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_l3_rewrite_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_l3_rewrite_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_mtu_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_mtu_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_mtu_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_mtu_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv4_packet_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_validate_outer_ipv4_packet_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_fib_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_fib_lpm_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_lpm_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_urpf_lpm_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_urpf_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_urpf_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_validate_outer_ipv6_packet_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_validate_outer_ipv6_packet_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_lpm_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_fib_lpm_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_fib_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_fib_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_lpm_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_urpf_lpm_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_urpf_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_urpf_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_outer_rmac_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_outer_rmac_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_outer_rmac_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_outer_rmac_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_dest_vtep_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_src_vtep_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_src_vtep_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_dest_vtep_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_dest_vtep_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_src_vtep_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_src_vtep_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_adjust_lkp_fields_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_adjust_lkp_fields_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_lookup_miss_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_lookup_miss_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_check_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_check_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_check_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_check_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_validate_mpls_packet_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_validate_mpls_packet_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_outer_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_decap_process_outer_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_decap_process_inner_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_decap_process_inner_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_egress_vni_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_egress_vni_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_egress_vni_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_egress_vni_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_inner_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_encap_process_inner_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_encap_process_outer_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_encap_process_outer_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_rewrite_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_rewrite_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_dst_rewrite_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_dst_rewrite_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_smac_rewrite_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_smac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_dmac_rewrite_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_dmac_rewrite_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_tunnel_to_mgid_mapping_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_tunnel_to_mgid_mapping_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ingress_l4_src_port_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ingress_l4_src_port_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ingress_l4_dst_port_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ingress_l4_dst_port_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_mac_acl_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_mac_acl_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_mac_acl_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_mac_acl_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ip_acl_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ip_acl_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ip_acl_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ip_acl_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_acl_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_acl_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_racl_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_racl_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_racl_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_racl_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_acl_stats_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_acl_stats_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_acl_stats_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_racl_stats_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_racl_stats_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_racl_stats_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_system_acl_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_system_acl_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_system_acl_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_system_acl_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_drop_stats_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_drop_stats_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_drop_stats_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_egress_system_acl_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_egress_system_acl_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_star_g_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_bridge_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_multicast_bridge_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_star_g_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv4_multicast_route_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv4_multicast_route_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_star_g_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_bridge_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_multicast_bridge_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_star_g_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ipv6_multicast_route_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ipv6_multicast_route_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_bd_flood_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_bd_flood_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_bd_flood_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_bd_flood_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_rid_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_rid_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_rid_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_rid_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_mcast_egress_ifindex_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_mcast_egress_ifindex_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_replica_type_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_replica_type_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_replica_type_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_replica_type_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_fwd_result_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_fwd_result_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_fwd_result_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_fwd_result_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_ecmp_group_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_ecmp_group_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ecmp_group_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_ecmp_group_match_spec_t *match_spec,
 bool *has_mbr_hdl, bool *has_grp_hdl, p4_pd_grp_hdl_t *grp_hdl, p4_pd_mbr_hdl_t *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_nexthop_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_nexthop_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_nexthop_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_nexthop_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_rewrite_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_rewrite_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_rewrite_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_rewrite_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_storm_control_stats_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_storm_control_stats_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_storm_control_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_storm_control_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_storm_control_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_storm_control_match_spec_t *match_spec,
 int *priority,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_fabric_ingress_dst_lkp_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_mirror_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_mirror_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_mirror_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_mirror_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_compute_ipv4_hashes_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_compute_ipv4_hashes_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_compute_ipv6_hashes_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_compute_ipv6_hashes_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_compute_non_ip_hashes_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_compute_non_ip_hashes_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_get_first_entry_handle
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int *index
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_get_next_entry_handles
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_handle,
 int n,
 int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_compute_other_hashes_get_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl,
 bool read_from_hw,
 p4_pd_dc_compute_other_hashes_match_spec_t *match_spec,
 p4_pd_dc_action_specs_t *action_spec
);


p4_pd_status_t
p4_pd_dc_bd_action_profile_get_member
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);
p4_pd_status_t
p4_pd_dc_bd_action_profile_get_first_member
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, int *entry_handle
);

p4_pd_status_t
p4_pd_dc_bd_action_profile_get_next_members
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, p4_pd_entry_hdl_t entry_handle,
  int n, int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_member
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);
p4_pd_status_t
p4_pd_dc_lag_action_profile_get_first_member
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, int *entry_handle
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_next_members
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, p4_pd_entry_hdl_t entry_handle,
  int n, int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_first_group
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, int *grp_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_next_groups
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, int grp_hdl,
  int n, int *grp_hdls
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_first_group_member
(
  p4_pd_sess_hdl_t sess_hdl, uint8_t dev_id, int grp_hdl,
  int *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_lag_action_profile_get_next_group_members
(
  p4_pd_sess_hdl_t sess_hdl, uint8_t dev_id, int grp_hdl,
  int mbr_hdl, int n, int *mbr_hdls
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_member
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_mbr_hdl_t mbr_hdl,
 bool read_from_hw,
 p4_pd_dc_action_specs_t *action_spec
);
p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_first_member
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, int *entry_handle
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_next_members
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, p4_pd_entry_hdl_t entry_handle,
  int n, int *next_entry_handles
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_first_group
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, int *grp_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_next_groups
(
  p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt, int grp_hdl,
  int n, int *grp_hdls
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_first_group_member
(
  p4_pd_sess_hdl_t sess_hdl, uint8_t dev_id, int grp_hdl,
  int *mbr_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_action_profile_get_next_group_members
(
  p4_pd_sess_hdl_t sess_hdl, uint8_t dev_id, int grp_hdl,
  int mbr_hdl, int n, int *mbr_hdls
);


p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_port_vlan_to_bd_mapping_match_spec_t *match_spec
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

p4_pd_status_t
p4_pd_dc_cpu_packet_transform_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_cpu_packet_transform_match_spec_t *match_spec
);

p4_pd_status_t
p4_pd_dc_lag_group_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

p4_pd_status_t
p4_pd_dc_lag_group_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_lag_group_match_spec_t *match_spec
);

p4_pd_status_t
p4_pd_dc_ecmp_group_table_delete
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

p4_pd_status_t
p4_pd_dc_ecmp_group_table_delete_by_match_spec
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_dc_ecmp_group_match_spec_t *match_spec
);


p4_pd_status_t
p4_pd_dc_port_vlan_to_bd_mapping_set_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);


p4_pd_status_t
p4_pd_dc_cpu_packet_transform_set_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);


p4_pd_status_t
p4_pd_dc_lag_group_set_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);


p4_pd_status_t
p4_pd_dc_lag_group_set_default_entry_with_selector
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);
p4_pd_status_t
p4_pd_dc_ecmp_group_set_default_entry
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_mbr_hdl_t mbr_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);


p4_pd_status_t
p4_pd_dc_ecmp_group_set_default_entry_with_selector
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_grp_hdl_t grp_hdl,
 p4_pd_entry_hdl_t *entry_hdl
);

typedef struct __attribute__((__packed__)) p4_pd_dc_mac_learn_digest_digest_entry {
  uint16_t ingress_metadata_ifindex;
  uint8_t l2_metadata_lkp_mac_sa[6];
  uint16_t ingress_metadata_bd;
} p4_pd_dc_mac_learn_digest_digest_entry_t;

// Should be able to cast this to pipe_flow_lrn_msg_t.
typedef struct p4_pd_dc_mac_learn_digest_digest_msg {
  p4_pd_dev_target_t      dev_tgt;
  uint16_t                num_entries;
  p4_pd_dc_mac_learn_digest_digest_entry_t    *entries;
} p4_pd_dc_mac_learn_digest_digest_msg_t;

// Should be able to cast this to pipe_flow_lrn_notify_cb.
typedef p4_pd_status_t (*p4_pd_dc_mac_learn_digest_digest_notify_cb)(p4_pd_sess_hdl_t sess_hdl,
                                              p4_pd_dc_mac_learn_digest_digest_msg_t *msg,
                                              void *callback_fn_cookie);

p4_pd_status_t
p4_pd_dc_mac_learn_digest_register
(
 p4_pd_sess_hdl_t         sess_hdl,
 uint8_t                  device_id,
 p4_pd_dc_mac_learn_digest_digest_notify_cb      cb_fn,
 void                    *cb_fn_cookie
);

p4_pd_status_t
p4_pd_dc_mac_learn_digest_deregister
(
 p4_pd_sess_hdl_t         sess_hdl,
 uint8_t                  device_id
);

p4_pd_status_t
p4_pd_dc_mac_learn_digest_notify_ack
(
 p4_pd_sess_hdl_t         sess_hdl,
 p4_pd_dc_mac_learn_digest_digest_msg_t        *msg
);

p4_pd_status_t
p4_pd_dc_set_learning_timeout(p4_pd_sess_hdl_t shdl,
                                    uint8_t          device_id,
                                    uint32_t         usecs);

/* COUNTERS */

p4_pd_status_t
p4_pd_dc_counter_read_ipv6_multicast_route_s_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_ipv6_multicast_route_s_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_acl_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_acl_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_storm_control_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_storm_control_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_ingress_bd_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_ingress_bd_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_ipv4_multicast_route_star_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_ipv4_multicast_route_star_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_drop_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_drop_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_ipv4_multicast_route_s_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_ipv4_multicast_route_s_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_drop_stats_2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_drop_stats_2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_ipv6_multicast_route_star_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_ipv6_multicast_route_star_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_racl_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_racl_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_counter_value_t counter_value
);

p4_pd_status_t
p4_pd_dc_counter_read_egress_bd_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 int flags,
 p4_pd_counter_value_t *counter_value
);

p4_pd_status_t
p4_pd_dc_counter_write_egress_bd_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_counter_value_t counter_value
);


p4_pd_status_t
p4_pd_dc_counter_hw_sync_ipv6_multicast_route_s_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_acl_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_storm_control_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_ingress_bd_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_ipv4_multicast_route_star_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_drop_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_ipv4_multicast_route_s_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_drop_stats_2
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_ipv6_multicast_route_star_g_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_racl_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

p4_pd_status_t
p4_pd_dc_counter_hw_sync_egress_bd_stats
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);



// REGISTERS




/* METERS */

p4_pd_status_t
p4_pd_dc_meter_set_storm_control_meter
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_bytes_meter_spec_t *meter_spec
);

p4_pd_status_t
p4_pd_dc_meter_read_storm_control_meter
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_bytes_meter_spec_t *meter_spec
);

p4_pd_status_t
p4_pd_dc_meter_set_copp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_packets_meter_spec_t *meter_spec
);

p4_pd_status_t
p4_pd_dc_meter_read_copp
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 int index,
 p4_pd_packets_meter_spec_t *meter_spec
);


/* LPF */


/* WRED */



typedef struct __attribute__((__packed__)) p4_pd_dc_ig_snapshot_trig_spec {
  uint8_t ig_intr_md_resubmit_flag;
  uint8_t ig_intr_md__pad1;
  uint8_t ig_intr_md__pad2;
  uint8_t ig_intr_md__pad3;
  uint16_t ig_intr_md_ingress_port;
  uint8_t ig_intr_md_ingress_mac_tstamp[6];
  uint16_t ig_intr_md_from_parser_aux_ingress_parser_err;
  uint16_t ig_intr_md_for_tm_ucast_egress_port;
  uint8_t ig_intr_md_for_tm_drop_ctl;
  uint8_t ig_intr_md_for_tm_ingress_cos;
  uint8_t ig_intr_md_for_tm_qid;
  uint8_t ig_intr_md_for_tm_copy_to_cpu;
  uint8_t ig_intr_md_for_tm_packet_color;
  uint8_t ig_intr_md_for_tm_disable_ucast_cutthru;
  uint16_t ig_intr_md_for_tm_mcast_grp_b;
  uint16_t ig_intr_md_for_tm_level1_mcast_hash;
  uint16_t ig_intr_md_for_tm_level2_mcast_hash;
  uint16_t ig_intr_md_for_tm_level1_exclusion_id;
  uint16_t ig_intr_md_for_tm_level2_exclusion_id;
  uint16_t ig_intr_md_for_tm_rid;
  uint16_t ig_intr_md_for_mb_ingress_mirror_id;
  uint8_t ethernet_dstAddr[6];
  uint8_t ethernet_srcAddr[6];
  uint16_t ethernet_etherType;
  uint8_t llc_header_dsap;
  uint8_t llc_header_ssap;
  uint8_t llc_header_control_;
  uint32_t snap_header_oui;
  uint16_t snap_header_type_;
  uint8_t vlan_tag__0__pcp;
  uint8_t vlan_tag__0__cfi;
  uint16_t vlan_tag__0__vid;
  uint16_t vlan_tag__0__etherType;
  uint8_t vlan_tag__1__pcp;
  uint8_t vlan_tag__1__cfi;
  uint16_t vlan_tag__1__vid;
  uint16_t vlan_tag__1__etherType;
  uint32_t mpls_0__label;
  uint8_t mpls_0__exp;
  uint8_t mpls_0__bos;
  uint8_t mpls_0__ttl;
  uint32_t mpls_1__label;
  uint8_t mpls_1__exp;
  uint8_t mpls_1__bos;
  uint8_t mpls_1__ttl;
  uint32_t mpls_2__label;
  uint8_t mpls_2__exp;
  uint8_t mpls_2__bos;
  uint8_t mpls_2__ttl;
  uint8_t ipv4_version;
  uint8_t ipv4_ihl;
  uint8_t ipv4_diffserv;
  uint16_t ipv4_totalLen;
  uint16_t ipv4_identification;
  uint8_t ipv4_flags;
  uint16_t ipv4_fragOffset;
  uint8_t ipv4_ttl;
  uint8_t ipv4_protocol;
  uint16_t ipv4_hdrChecksum;
  uint32_t ipv4_srcAddr;
  uint32_t ipv4_dstAddr;
  uint32_t ipv4_option_32b_option_fields;
  uint8_t ipv6_version;
  uint8_t ipv6_trafficClass;
  uint32_t ipv6_flowLabel;
  uint16_t ipv6_payloadLen;
  uint8_t ipv6_nextHdr;
  uint8_t ipv6_hopLimit;
  uint8_t ipv6_srcAddr[16];
  uint8_t ipv6_dstAddr[16];
  uint16_t icmp_typeCode;
  uint16_t icmp_hdrChecksum;
  uint16_t igmp_typeCode;
  uint16_t igmp_hdrChecksum;
  uint16_t tcp_srcPort;
  uint16_t tcp_dstPort;
  uint32_t tcp_seqNo;
  uint32_t tcp_ackNo;
  uint8_t tcp_dataOffset;
  uint8_t tcp_res;
  uint8_t tcp_flags;
  uint16_t tcp_window;
  uint16_t tcp_checksum;
  uint16_t tcp_urgentPtr;
  uint16_t udp_srcPort;
  uint16_t udp_dstPort;
  uint16_t udp_length_;
  uint16_t udp_checksum;
  uint8_t gre_C;
  uint8_t gre_R;
  uint8_t gre_K;
  uint8_t gre_S;
  uint8_t gre_s;
  uint8_t gre_recurse;
  uint8_t gre_flags;
  uint8_t gre_ver;
  uint16_t gre_proto;
  uint32_t nvgre_tni;
  uint8_t nvgre_flow_id;
  uint8_t inner_ethernet_dstAddr[6];
  uint8_t inner_ethernet_srcAddr[6];
  uint16_t inner_ethernet_etherType;
  uint8_t inner_ipv4_version;
  uint8_t inner_ipv4_ihl;
  uint8_t inner_ipv4_diffserv;
  uint16_t inner_ipv4_totalLen;
  uint16_t inner_ipv4_identification;
  uint8_t inner_ipv4_flags;
  uint16_t inner_ipv4_fragOffset;
  uint8_t inner_ipv4_ttl;
  uint8_t inner_ipv4_protocol;
  uint16_t inner_ipv4_hdrChecksum;
  uint32_t inner_ipv4_srcAddr;
  uint32_t inner_ipv4_dstAddr;
  uint8_t inner_ipv6_version;
  uint8_t inner_ipv6_trafficClass;
  uint32_t inner_ipv6_flowLabel;
  uint16_t inner_ipv6_payloadLen;
  uint8_t inner_ipv6_nextHdr;
  uint8_t inner_ipv6_hopLimit;
  uint8_t inner_ipv6_srcAddr[16];
  uint8_t inner_ipv6_dstAddr[16];
  uint8_t erspan_t3_header_version;
  uint16_t erspan_t3_header_vlan;
  uint16_t erspan_t3_header_priority_span_id;
  uint32_t erspan_t3_header_timestamp;
  uint16_t erspan_t3_header_sgt;
  uint16_t erspan_t3_header_ft_d_other;
  uint8_t vxlan_flags;
  uint32_t vxlan_reserved;
  uint32_t vxlan_vni;
  uint8_t vxlan_reserved2;
  uint8_t genv_ver;
  uint8_t genv_optLen;
  uint8_t genv_oam;
  uint8_t genv_critical;
  uint8_t genv_reserved;
  uint16_t genv_protoType;
  uint32_t genv_vni;
  uint8_t genv_reserved2;
  uint16_t inner_icmp_typeCode;
  uint16_t inner_icmp_hdrChecksum;
  uint16_t inner_tcp_srcPort;
  uint16_t inner_tcp_dstPort;
  uint32_t inner_tcp_seqNo;
  uint32_t inner_tcp_ackNo;
  uint8_t inner_tcp_dataOffset;
  uint8_t inner_tcp_res;
  uint8_t inner_tcp_flags;
  uint16_t inner_tcp_window;
  uint16_t inner_tcp_checksum;
  uint16_t inner_tcp_urgentPtr;
  uint16_t inner_udp_srcPort;
  uint16_t inner_udp_dstPort;
  uint16_t inner_udp_length_;
  uint16_t inner_udp_checksum;
  uint8_t fabric_header_packetType;
  uint8_t fabric_header_headerVersion;
  uint8_t fabric_header_packetVersion;
  uint8_t fabric_header_pad1;
  uint8_t fabric_header_fabricColor;
  uint8_t fabric_header_fabricQos;
  uint8_t fabric_header_dstDevice;
  uint16_t fabric_header_dstPortOrGroup;
  uint8_t fabric_header_cpu_egressQueue;
  uint8_t fabric_header_cpu_txBypass;
  uint8_t fabric_header_cpu_capture_tstamp_on_tx;
  uint8_t fabric_header_cpu_reserved;
  uint16_t fabric_header_cpu_ingressPort;
  uint16_t fabric_header_cpu_ingressIfindex;
  uint16_t fabric_header_cpu_ingressBd;
  uint16_t fabric_header_cpu_reasonCode;
  uint16_t fabric_payload_header_etherType;
  uint16_t fabric_header_timestamp_arrival_time_hi;
  uint32_t fabric_header_timestamp_arrival_time;
  uint16_t ingress_metadata_ingress_port;
  uint16_t ingress_metadata_port_lag_index;
  uint16_t ingress_metadata_egress_port_lag_index;
  uint16_t ingress_metadata_ifindex;
  uint16_t ingress_metadata_egress_ifindex;
  uint8_t ingress_metadata_port_type;
  uint16_t ingress_metadata_bd;
  uint8_t ingress_metadata_drop_flag;
  uint8_t ingress_metadata_drop_reason;
  uint8_t ingress_metadata_bypass_lookups;
  uint8_t egress_metadata_capture_tstamp_on_tx;
  uint8_t egress_metadata_bypass;
  uint8_t l2_metadata_lkp_mac_sa[6];
  uint8_t l2_metadata_lkp_mac_da[6];
  uint8_t l2_metadata_lkp_pkt_type;
  uint16_t l2_metadata_lkp_mac_type;
  uint8_t l2_metadata_non_ip_packet;
  uint8_t l2_metadata_arp_opcode;
  uint16_t l2_metadata_l2_nexthop;
  uint8_t l2_metadata_l2_nexthop_type;
  uint8_t l2_metadata_l2_redirect;
  uint8_t l2_metadata_l2_src_miss;
  uint16_t l2_metadata_l2_src_move;
  uint8_t l2_metadata_l2_dst_miss;
  uint16_t l2_metadata_stp_group;
  uint8_t l2_metadata_stp_state;
  uint16_t l2_metadata_bd_stats_idx;
  uint8_t l2_metadata_learning_enabled;
  uint8_t l2_metadata_port_learning_enabled;
  uint8_t l2_metadata_port_vlan_mapping_miss;
  uint16_t l2_metadata_same_if_check;
  uint8_t l3_metadata_lkp_ip_type;
  uint8_t l3_metadata_lkp_ip_version;
  uint8_t l3_metadata_lkp_ip_proto;
  uint8_t l3_metadata_lkp_ip_ttl;
  uint16_t l3_metadata_lkp_l4_sport;
  uint16_t l3_metadata_lkp_l4_dport;
  uint16_t l3_metadata_lkp_outer_l4_sport;
  uint16_t l3_metadata_lkp_outer_l4_dport;
  uint8_t l3_metadata_lkp_outer_tcp_flags;
  uint8_t l3_metadata_lkp_tcp_flags;
  uint8_t l3_metadata_lkp_ip_llmc;
  uint8_t l3_metadata_lkp_ip_mc;
  uint16_t l3_metadata_vrf;
  uint16_t l3_metadata_rmac_group;
  uint8_t l3_metadata_rmac_hit;
  uint8_t l3_metadata_urpf_mode;
  uint8_t l3_metadata_urpf_hit;
  uint8_t l3_metadata_urpf_check_fail;
  uint16_t l3_metadata_urpf_bd_group;
  uint8_t l3_metadata_fib_hit;
  uint8_t l3_metadata_fib_hit_myip;
  uint16_t l3_metadata_fib_nexthop;
  uint8_t l3_metadata_fib_nexthop_type;
  uint16_t l3_metadata_same_bd_check;
  uint16_t l3_metadata_nexthop_index;
  uint8_t l3_metadata_routed;
  uint8_t l3_metadata_l3_copy;
  uint32_t ipv4_metadata_lkp_ipv4_sa;
  uint32_t ipv4_metadata_lkp_ipv4_da;
  uint8_t ipv4_metadata_ipv4_unicast_enabled;
  uint8_t ipv4_metadata_ipv4_urpf_mode;
  uint8_t ipv6_metadata_lkp_ipv6_sa[16];
  uint8_t ipv6_metadata_lkp_ipv6_da[16];
  uint8_t ipv6_metadata_ipv6_unicast_enabled;
  uint8_t ipv6_metadata_ipv6_src_is_link_local;
  uint8_t ipv6_metadata_ipv6_urpf_mode;
  uint8_t tunnel_metadata_ingress_tunnel_type;
  uint32_t tunnel_metadata_tunnel_vni;
  uint16_t tunnel_metadata_tunnel_dst_index;
  uint8_t tunnel_metadata_tunnel_lookup;
  uint8_t tunnel_metadata_tunnel_terminate;
  uint8_t tunnel_metadata_tunnel_if_check;
  uint8_t tunnel_metadata_src_vtep_hit;
  uint16_t tunnel_metadata_vtep_ifindex;
  uint8_t tunnel_metadata_tunnel_term_type;
  uint8_t acl_metadata_acl_deny;
  uint8_t acl_metadata_racl_deny;
  uint16_t acl_metadata_acl_nexthop;
  uint16_t acl_metadata_racl_nexthop;
  uint8_t acl_metadata_acl_nexthop_type;
  uint8_t acl_metadata_racl_nexthop_type;
  uint8_t acl_metadata_acl_redirect;
  uint8_t acl_metadata_racl_redirect;
  uint16_t acl_metadata_port_lag_label;
  uint16_t acl_metadata_bd_label;
  uint16_t acl_metadata_acl_stats_index;
  uint16_t acl_metadata_racl_stats_index;
  uint8_t acl_metadata_ingress_src_port_range_id;
  uint8_t acl_metadata_ingress_dst_port_range_id;
  uint32_t i2e_metadata_ingress_tstamp;
  uint16_t i2e_metadata_ingress_tstamp_hi;
  uint16_t i2e_metadata_mirror_session_id;
  uint8_t multicast_metadata_mcast_route_hit;
  uint8_t multicast_metadata_mcast_route_s_g_hit;
  uint8_t multicast_metadata_mcast_bridge_hit;
  uint8_t multicast_metadata_mcast_copy_to_cpu;
  uint8_t multicast_metadata_ipv4_multicast_enabled;
  uint8_t multicast_metadata_ipv6_multicast_enabled;
  uint8_t multicast_metadata_igmp_snooping_enabled;
  uint8_t multicast_metadata_mld_snooping_enabled;
  uint16_t multicast_metadata_bd_mrpf_group;
  uint16_t multicast_metadata_mcast_rpf_group;
  uint8_t multicast_metadata_mcast_rpf_fail;
  uint8_t multicast_metadata_flood_to_mrouters;
  uint8_t multicast_metadata_mcast_mode;
  uint16_t multicast_metadata_multicast_route_mc_index;
  uint16_t multicast_metadata_multicast_bridge_mc_index;
  uint8_t nexthop_metadata_nexthop_type;
  uint8_t nexthop_metadata_nexthop_glean;
  uint16_t fabric_metadata_reason_code;
  uint16_t hash_metadata_hash1;
  uint16_t hash_metadata_hash2;
  uint16_t hash_metadata_entropy_hash;
  uint8_t meter_metadata_storm_control_color;
  uint16_t __md_ingress___init_0;
  uint16_t __md_ingress___init_1;
  uint16_t __md_ingress___init_2;
  uint16_t __md_ingress___init_3;
  uint16_t __md_ingress___init_4;
  uint16_t __md_ingress___init_5;
  uint16_t __md_ingress___init_6;
  uint16_t __md_ingress___init_7;
  uint16_t __md_ingress___init_8;
  uint16_t __md_ingress___init_9;
  uint16_t __md_ingress___init_10;
  uint8_t __md_ingress___init_11;
  uint8_t __md_ingress___init_12;
  uint8_t __md_ingress___init_13;
  uint8_t __md_ingress___init_14;
  uint8_t __md_ingress___init_15;
  uint8_t __md_ingress___init_16;
  uint8_t __md_ingress___init_17;
  uint8_t __md_ingress___init_18;
  uint8_t __md_ingress___init_19;
  uint8_t __md_ingress___init_20;
  uint8_t __md_ingress___init_21;
  uint8_t __md_ingress___init_22;
  uint8_t __md_ingress___init_23;
  uint8_t __md_ingress___init_24;
  uint16_t __md_ingress___init_25;
  uint16_t __md_ingress___init_26;
  uint8_t __md_ingress___init_27;
  uint16_t __md_ingress___init_28;
  uint16_t __md_ingress___init_29;
  uint16_t __md_ingress___init_30;
  uint16_t __md_ingress___init_31;
  uint8_t _selector_CLONE_I2E_DIGEST_RCVR;
  uint8_t _selector_FLOW_LRN_DIGEST_RCVR;
  /* POV fields */
  uint8_t ethernet_valid;
  uint8_t llc_header_valid;
  uint8_t snap_header_valid;
  uint8_t ipv4_valid;
  uint8_t ipv4_option_32b_valid;
  uint8_t ipv6_valid;
  uint8_t icmp_valid;
  uint8_t igmp_valid;
  uint8_t tcp_valid;
  uint8_t udp_valid;
  uint8_t gre_valid;
  uint8_t nvgre_valid;
  uint8_t inner_ethernet_valid;
  uint8_t inner_ipv4_valid;
  uint8_t inner_ipv6_valid;
  uint8_t erspan_t3_header_valid;
  uint8_t vxlan_valid;
  uint8_t genv_valid;
  uint8_t inner_icmp_valid;
  uint8_t inner_tcp_valid;
  uint8_t inner_udp_valid;
  uint8_t fabric_header_valid;
  uint8_t fabric_header_cpu_valid;
  uint8_t fabric_payload_header_valid;
  uint8_t fabric_header_timestamp_valid;
  uint8_t vlan_tag__0__valid;
  uint8_t vlan_tag__1__valid;
  uint8_t mpls_0__valid;
  uint8_t mpls_1__valid;
  uint8_t mpls_2__valid;

} p4_pd_dc_ig_snapshot_trig_spec_t;


typedef struct __attribute__((__packed__)) p4_pd_dc_eg_snapshot_trig_spec {
  uint8_t ethernet_dstAddr[6];
  uint8_t ethernet_srcAddr[6];
  uint16_t ethernet_etherType;
  uint8_t llc_header_dsap;
  uint8_t llc_header_ssap;
  uint8_t llc_header_control_;
  uint32_t snap_header_oui;
  uint16_t snap_header_type_;
  uint8_t vlan_tag__0__pcp;
  uint8_t vlan_tag__0__cfi;
  uint16_t vlan_tag__0__vid;
  uint16_t vlan_tag__0__etherType;
  uint8_t vlan_tag__1__pcp;
  uint8_t vlan_tag__1__cfi;
  uint16_t vlan_tag__1__vid;
  uint16_t vlan_tag__1__etherType;
  uint32_t mpls_0__label;
  uint32_t mpls_1__label;
  uint32_t mpls_2__label;
  uint8_t mpls_0__exp;
  uint8_t mpls_1__exp;
  uint8_t mpls_2__exp;
  uint8_t mpls_0__bos;
  uint8_t mpls_1__bos;
  uint8_t mpls_2__bos;
  uint8_t mpls_0__ttl;
  uint8_t mpls_1__ttl;
  uint8_t mpls_2__ttl;
  uint8_t ipv4_version;
  uint8_t ipv4_ihl;
  uint8_t ipv4_diffserv;
  uint16_t ipv4_totalLen;
  uint16_t ipv4_identification;
  uint8_t ipv4_flags;
  uint16_t ipv4_fragOffset;
  uint8_t ipv4_ttl;
  uint8_t ipv4_protocol;
  uint16_t ipv4_hdrChecksum;
  uint32_t ipv4_srcAddr;
  uint32_t ipv4_dstAddr;
  uint32_t ipv4_option_32b_option_fields;
  uint8_t ipv6_version;
  uint8_t ipv6_trafficClass;
  uint32_t ipv6_flowLabel;
  uint16_t ipv6_payloadLen;
  uint8_t ipv6_nextHdr;
  uint8_t ipv6_hopLimit;
  uint8_t ipv6_srcAddr[16];
  uint8_t ipv6_dstAddr[16];
  uint16_t icmp_typeCode;
  uint16_t icmp_hdrChecksum;
  uint16_t igmp_typeCode;
  uint16_t igmp_hdrChecksum;
  uint16_t tcp_srcPort;
  uint16_t tcp_dstPort;
  uint32_t tcp_seqNo;
  uint32_t tcp_ackNo;
  uint8_t tcp_dataOffset;
  uint8_t tcp_res;
  uint8_t tcp_flags;
  uint16_t tcp_window;
  uint16_t tcp_checksum;
  uint16_t tcp_urgentPtr;
  uint16_t udp_srcPort;
  uint16_t udp_dstPort;
  uint16_t udp_length_;
  uint16_t udp_checksum;
  uint8_t gre_C;
  uint8_t gre_R;
  uint8_t gre_K;
  uint8_t gre_S;
  uint8_t gre_s;
  uint8_t gre_recurse;
  uint8_t gre_flags;
  uint8_t gre_ver;
  uint16_t gre_proto;
  uint32_t nvgre_tni;
  uint8_t nvgre_flow_id;
  uint8_t erspan_t3_header_version;
  uint16_t erspan_t3_header_vlan;
  uint16_t erspan_t3_header_priority_span_id;
  uint32_t erspan_t3_header_timestamp;
  uint16_t erspan_t3_header_sgt;
  uint16_t erspan_t3_header_ft_d_other;
  uint8_t vxlan_flags;
  uint32_t vxlan_reserved;
  uint32_t vxlan_vni;
  uint8_t vxlan_reserved2;
  uint8_t genv_ver;
  uint8_t genv_optLen;
  uint8_t genv_oam;
  uint8_t genv_critical;
  uint8_t genv_reserved;
  uint16_t genv_protoType;
  uint32_t genv_vni;
  uint8_t genv_reserved2;
  uint8_t inner_ipv4_version;
  uint8_t inner_ipv4_ihl;
  uint8_t inner_ipv4_diffserv;
  uint16_t inner_ipv4_totalLen;
  uint16_t inner_ipv4_identification;
  uint8_t inner_ipv4_flags;
  uint16_t inner_ipv4_fragOffset;
  uint8_t inner_ipv4_ttl;
  uint8_t inner_ipv4_protocol;
  uint16_t inner_ipv4_hdrChecksum;
  uint32_t inner_ipv4_srcAddr;
  uint32_t inner_ipv4_dstAddr;
  uint16_t inner_icmp_typeCode;
  uint16_t inner_icmp_hdrChecksum;
  uint16_t inner_tcp_srcPort;
  uint16_t inner_tcp_dstPort;
  uint32_t inner_tcp_seqNo;
  uint32_t inner_tcp_ackNo;
  uint8_t inner_tcp_dataOffset;
  uint8_t inner_tcp_res;
  uint8_t inner_tcp_flags;
  uint16_t inner_tcp_window;
  uint16_t inner_tcp_checksum;
  uint16_t inner_tcp_urgentPtr;
  uint16_t inner_udp_srcPort;
  uint16_t inner_udp_dstPort;
  uint16_t inner_udp_length_;
  uint16_t inner_udp_checksum;
  uint8_t inner_ipv6_version;
  uint8_t inner_ipv6_trafficClass;
  uint32_t inner_ipv6_flowLabel;
  uint16_t inner_ipv6_payloadLen;
  uint8_t inner_ipv6_nextHdr;
  uint8_t inner_ipv6_hopLimit;
  uint8_t inner_ipv6_srcAddr[16];
  uint8_t inner_ipv6_dstAddr[16];
  uint8_t inner_ethernet_dstAddr[6];
  uint8_t inner_ethernet_srcAddr[6];
  uint16_t inner_ethernet_etherType;
  uint8_t fabric_header_packetType;
  uint8_t fabric_header_headerVersion;
  uint8_t fabric_header_packetVersion;
  uint8_t fabric_header_pad1;
  uint8_t fabric_header_fabricColor;
  uint8_t fabric_header_fabricQos;
  uint8_t fabric_header_dstDevice;
  uint16_t fabric_header_dstPortOrGroup;
  uint8_t fabric_header_cpu_egressQueue;
  uint8_t fabric_header_cpu_txBypass;
  uint8_t fabric_header_cpu_capture_tstamp_on_tx;
  uint8_t fabric_header_cpu_reserved;
  uint16_t fabric_header_cpu_ingressPort;
  uint16_t fabric_header_cpu_ingressIfindex;
  uint16_t fabric_header_cpu_ingressBd;
  uint16_t fabric_header_cpu_reasonCode;
  uint16_t fabric_header_timestamp_arrival_time_hi;
  uint32_t fabric_header_timestamp_arrival_time;
  uint16_t fabric_payload_header_etherType;
  uint16_t eg_intr_md_egress_port;
  uint16_t ingress_metadata_ingress_port;
  uint16_t ingress_metadata_ifindex;
  uint16_t ingress_metadata_bd;
  uint16_t fabric_metadata_reason_code;
  uint8_t egress_metadata_port_type;
  uint16_t l3_metadata_l3_mtu_check;
  uint16_t ingress_metadata_egress_ifindex;
  uint16_t egress_metadata_outer_bd;
  uint8_t egress_metadata_capture_tstamp_on_tx;
  uint8_t eg_intr_md_for_oport_capture_tstamp_on_tx;
  uint16_t egress_metadata_bd;
  uint8_t l2_metadata_lkp_pkt_type;
  uint16_t egress_metadata_smac_idx;
  uint8_t l3_metadata_mtu_index;
  uint8_t tunnel_metadata_tunnel_smac_index;
  uint8_t eg_intr_md_from_parser_aux_clone_src;
  uint8_t egress_metadata_routed;
  uint8_t egress_metadata_mac_da[6];
  uint8_t tunnel_metadata_ingress_tunnel_type;
  uint8_t multicast_metadata_inner_replica;
  uint8_t multicast_metadata_replica;
  uint32_t tunnel_metadata_vnid;
  uint16_t eg_intr_md_pkt_length;
  uint16_t egress_metadata_payload_length;
  uint8_t tunnel_metadata_inner_ip_proto;
  uint8_t tunnel_metadata_egress_tunnel_type;
  uint8_t tunnel_metadata_egress_header_count;
  uint16_t hash_metadata_entropy_hash;
  uint16_t tunnel_metadata_tunnel_index;
  uint16_t tunnel_metadata_tunnel_dst_index;
  uint16_t tunnel_metadata_tunnel_dmac_index;
  uint8_t ig_intr_md_for_tm_packet_color;
  uint8_t eg_intr_md_deflection_flag;
  uint8_t egress_metadata_bypass;
  uint32_t i2e_metadata_ingress_tstamp;
  uint16_t i2e_metadata_ingress_tstamp_hi;
  uint16_t i2e_metadata_mirror_session_id;
  uint8_t eg_intr_md_for_oport_drop_ctl;
  uint16_t eg_intr_md_for_mb_egress_mirror_id;
  uint16_t eg_intr_md_egress_rid;
  uint8_t l3_metadata_outer_routed;
  uint16_t ingress_metadata_outer_bd;
  uint8_t l3_metadata_routed;
  uint16_t egress_metadata_same_bd_check;
  uint16_t l3_metadata_nexthop_index;
  uint16_t l3_metadata_vrf;
  uint8_t eg_intr_md_from_parser_aux_clone_digest_id;
  uint8_t tunnel_metadata_tunnel_terminate;
  uint8_t eg_intr_md__pad0;
  uint8_t eg_intr_md__pad7;
  uint8_t eg_intr_md_egress_cos;
  uint8_t eg_intr_md__pad8;
  uint8_t eg_intr_md_for_mb__pad1;
  uint8_t __md_egress___init_0;
  uint8_t __md_egress___init_1;
  uint8_t __md_egress___init_2;
  uint8_t __md_egress___init_3;
  uint8_t __md_egress___init_4;
  uint16_t __md_egress___init_5;
  uint16_t __md_egress___init_6;
  uint8_t _selector_CLONE_E2E_DIGEST_RCVR;
  /* POV fields */
  uint8_t icmp_valid;
  uint8_t tcp_valid;
  uint8_t udp_valid;
  uint8_t inner_icmp_valid;
  uint8_t inner_tcp_valid;
  uint8_t inner_udp_valid;
  uint8_t mpls_2__valid;
  uint8_t mpls_1__valid;
  uint8_t mpls_0__valid;
  uint8_t vlan_tag__0__valid;
  uint8_t ethernet_valid;
  uint8_t llc_header_valid;
  uint8_t snap_header_valid;
  uint8_t ipv4_valid;
  uint8_t ipv4_option_32b_valid;
  uint8_t ipv6_valid;
  uint8_t igmp_valid;
  uint8_t gre_valid;
  uint8_t nvgre_valid;
  uint8_t erspan_t3_header_valid;
  uint8_t fabric_header_valid;
  uint8_t fabric_header_timestamp_valid;
  uint8_t vlan_tag__1__valid;
  uint8_t fabric_header_cpu_valid;
  uint8_t fabric_payload_header_valid;
  uint8_t vxlan_valid;
  uint8_t genv_valid;
  uint8_t inner_ipv4_valid;
  uint8_t inner_ipv6_valid;
  uint8_t inner_ethernet_valid;

} p4_pd_dc_eg_snapshot_trig_spec_t;


typedef struct __attribute__((__packed__)) p4_pd_dc_snapshot_trig_spec {
    union {
        p4_pd_dc_ig_snapshot_trig_spec_t ig;
        p4_pd_dc_eg_snapshot_trig_spec_t eg;
    } u;
}  p4_pd_dc_snapshot_trig_spec_t;


typedef p4_pd_dc_ig_snapshot_trig_spec_t p4_pd_dc_ig_snapshot_capture_data_t;
typedef p4_pd_dc_eg_snapshot_trig_spec_t p4_pd_dc_eg_snapshot_capture_data_t;


typedef struct __attribute__ ((__packed__)) p4_pd_dc_snapshot_capture {
     p4_pd_snapshot_capture_ctrl_info_t ctrl;
     union {
         p4_pd_dc_ig_snapshot_capture_data_t ig;
         p4_pd_dc_eg_snapshot_capture_data_t eg;
     } u;
} p4_pd_dc_snapshot_capture_t;

/* Array of snapshot captures if start and en stage are different */
typedef struct p4_pd_dc_snapshot_capture_arr {
    p4_pd_dc_snapshot_capture_t captures[P4_PD_MAX_SNAPSHOT_CAPTURES];
} p4_pd_dc_snapshot_capture_arr_t;


/**
 * @brief Set snapshot trigger.
 * @param hdl Snapshot handle.
 * @param trig_spec Trigger spec.
 * @param trig_mask Trigger mask.
 * @return status.
*/
p4_pd_status_t
p4_pd_dc_snapshot_capture_trigger_set(
              p4_pd_snapshot_hdl_t hdl,
              p4_pd_dc_snapshot_trig_spec_t *trig_spec,
              p4_pd_dc_snapshot_trig_spec_t *trig_mask);

/**
 * @brief Get snapshot capture data.
 * @param hdl Snapshot handle.
 * @param pipe Pipe.
 * @param capture Captured data
 * @param num_captures Num of captures
 * @return status.
*/
p4_pd_status_t
p4_pd_dc_snapshot_capture_data_get(
              p4_pd_snapshot_hdl_t hdl,
              uint16_t dev_pipe_id,
              p4_pd_dc_snapshot_capture_arr_t *capture,
              int *num_captures);

/**
 * @brief Create a snapshot.
 * @param dev_tgt Device information.
 * @param start_stage_id Start stage.
 * @param end_stage_id End stage.
 * @param direction Ingress or egress
 * @param hdl Snapshot handle.
 * @return status.
*/
p4_pd_status_t
p4_pd_dc_snapshot_create(
            p4_pd_dev_target_t dev_tgt,
            uint8_t start_stage_id, uint8_t end_stage_id,
            p4_pd_snapshot_dir_t direction,
            p4_pd_snapshot_hdl_t *hdl);

/**
 * @brief Delete snapshot.
 * @param hdl Snapshot handle.
 * @return status.
*/
p4_pd_status_t
p4_pd_dc_snapshot_delete(
            p4_pd_snapshot_hdl_t hdl);





typedef enum p4_pd_dc_input_fields_lkp_non_ip_hash1_fields_1{
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_1_L2_METADATA_LKP_MAC_DA = 0,
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_1_INGRESS_METADATA_IFINDEX = 1,
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_1_L2_METADATA_LKP_MAC_SA = 2,
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_1_L2_METADATA_LKP_MAC_TYPE = 3,
} p4_pd_dc_input_fields_lkp_non_ip_hash1_fields_1_t;

typedef enum p4_pd_dc_input_fields_lkp_ipv6_hash1_fields_1{
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_1_IPV6_METADATA_LKP_IPV6_DA = 0,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_1_L3_METADATA_LKP_L4_SPORT = 1,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_1_IPV6_METADATA_LKP_IPV6_SA = 2,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_1_L3_METADATA_LKP_L4_DPORT = 3,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_1_L3_METADATA_LKP_IP_PROTO = 4,
} p4_pd_dc_input_fields_lkp_ipv6_hash1_fields_1_t;

typedef enum p4_pd_dc_input_fields_lkp_ipv6_hash1_fields{
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_L3_METADATA_LKP_L4_DPORT = 0,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_L3_METADATA_LKP_L4_SPORT = 1,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_L3_METADATA_LKP_IP_PROTO = 2,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_IPV6_METADATA_LKP_IPV6_DA = 3,
  P4_PD_INPUT_FIELD_LKP_IPV6_HASH1_FIELDS_IPV6_METADATA_LKP_IPV6_SA = 4,
} p4_pd_dc_input_fields_lkp_ipv6_hash1_fields_t;

typedef enum p4_pd_dc_input_fields_lag_hash_fields{
  P4_PD_INPUT_FIELD_LAG_HASH_FIELDS_HASH_METADATA_HASH2 = 0,
} p4_pd_dc_input_fields_lag_hash_fields_t;

typedef enum p4_pd_dc_input_fields_lkp_ipv4_hash1_fields{
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_L3_METADATA_LKP_L4_DPORT = 0,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_L3_METADATA_LKP_L4_SPORT = 1,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_L3_METADATA_LKP_IP_PROTO = 2,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_IPV4_METADATA_LKP_IPV4_DA = 3,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_IPV4_METADATA_LKP_IPV4_SA = 4,
} p4_pd_dc_input_fields_lkp_ipv4_hash1_fields_t;

typedef enum p4_pd_dc_input_fields_l3_hash_fields{
  P4_PD_INPUT_FIELD_L3_HASH_FIELDS_HASH_METADATA_HASH1 = 0,
} p4_pd_dc_input_fields_l3_hash_fields_t;

typedef enum p4_pd_dc_input_fields_lkp_ipv4_hash1_fields_1{
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_1_IPV4_METADATA_LKP_IPV4_SA = 0,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_1_L3_METADATA_LKP_L4_SPORT = 1,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_1_IPV4_METADATA_LKP_IPV4_DA = 2,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_1_L3_METADATA_LKP_L4_DPORT = 3,
  P4_PD_INPUT_FIELD_LKP_IPV4_HASH1_FIELDS_1_L3_METADATA_LKP_IP_PROTO = 4,
} p4_pd_dc_input_fields_lkp_ipv4_hash1_fields_1_t;

typedef enum p4_pd_dc_input_fields_lkp_non_ip_hash1_fields{
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_L2_METADATA_LKP_MAC_TYPE = 0,
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_L2_METADATA_LKP_MAC_DA = 1,
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_L2_METADATA_LKP_MAC_SA = 2,
  P4_PD_INPUT_FIELD_LKP_NON_IP_HASH1_FIELDS_INGRESS_METADATA_IFINDEX = 3,
} p4_pd_dc_input_fields_lkp_non_ip_hash1_fields_t;

typedef enum p4_pd_dc_input_field_attr_type {
  P4_PD_INPUT_FIELD_ATTR_TYPE_MASK,
} p4_pd_dc_input_field_attr_type_t;

typedef enum p4_pd_dc_input_field_attr_value_mask {
  P4_PD_INPUT_FIELD_INCLUDED,
  P4_PD_INPUT_FIELD_EXCLUDED
} p4_pd_dc_input_field_attr_value_mask_t;


typedef enum p4_pd_dc_lkp_ipv6_hash1_input{
  P4_PD_DC_LKP_IPV6_HASH1_INPUT_LKP_IPV6_HASH1_FIELDS,
  P4_PD_DC_LKP_IPV6_HASH1_INPUT_LKP_IPV6_HASH1_FIELDS_1,
} p4_pd_dc_lkp_ipv6_hash1_input_t;

typedef struct p4_pd_dc_lkp_ipv6_hash1_input_field_attribute{
  union {
    p4_pd_dc_input_fields_lkp_ipv6_hash1_fields_t lkp_ipv6_hash1_fields;
    p4_pd_dc_input_fields_lkp_ipv6_hash1_fields_1_t lkp_ipv6_hash1_fields_1;
    uint32_t id;
  } input_field;
  p4_pd_dc_input_field_attr_type_t type;
  union {
    p4_pd_dc_input_field_attr_value_mask_t mask;
    uint64_t val;
  } value;
} p4_pd_dc_lkp_ipv6_hash1_input_field_attribute_t;

typedef enum p4_pd_dc_lkp_ipv6_hash1_algo {
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_DECT,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC16,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_GENIBUS,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_DNP,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_TELEDISK,
} p4_pd_dc_lkp_ipv6_hash1_algo_t;

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_input_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv6_hash1_input_t input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_input_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv6_hash1_input_t *input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_algorithm_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv6_hash1_algo_t algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_algorithm_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv6_hash1_algo_t *algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_seed_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_seed_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t *seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_input_field_attribute_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv6_hash1_input_t input,
 uint32_t attr_count,
 p4_pd_dc_lkp_ipv6_hash1_input_field_attribute_t *array_of_attrs
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_input_field_attribute_count_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv6_hash1_input_t input,
 uint32_t *attr_count
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv6_hash1_input_field_attribute_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv6_hash1_input_t input,
 uint32_t max_attr_count,
 p4_pd_dc_lkp_ipv6_hash1_input_field_attribute_t *array_of_attrs,
 uint32_t *num_attr_filled
);

typedef enum p4_pd_dc_lag_hash_input{
  P4_PD_DC_LAG_HASH_INPUT_LAG_HASH_FIELDS,
} p4_pd_dc_lag_hash_input_t;

typedef struct p4_pd_dc_lag_hash_input_field_attribute{
  union {
    p4_pd_dc_input_fields_lag_hash_fields_t lag_hash_fields;
    uint32_t id;
  } input_field;
  p4_pd_dc_input_field_attr_type_t type;
  union {
    p4_pd_dc_input_field_attr_value_mask_t mask;
    uint64_t val;
  } value;
} p4_pd_dc_lag_hash_input_field_attribute_t;

typedef enum p4_pd_dc_lag_hash_algo {
  P4_PD_DC_LAG_HASH_ALGORITHM_IDENTITY,
  P4_PD_DC_LAG_HASH_ALGORITHM_CRC_16_DECT,
} p4_pd_dc_lag_hash_algo_t;

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_input_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lag_hash_input_t input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_input_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lag_hash_input_t *input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_algorithm_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lag_hash_algo_t algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_algorithm_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lag_hash_algo_t *algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_seed_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_seed_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t *seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_input_field_attribute_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lag_hash_input_t input,
 uint32_t attr_count,
 p4_pd_dc_lag_hash_input_field_attribute_t *array_of_attrs
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_input_field_attribute_count_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lag_hash_input_t input,
 uint32_t *attr_count
);

p4_pd_status_t
p4_pd_dc_hash_calc_lag_hash_input_field_attribute_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lag_hash_input_t input,
 uint32_t max_attr_count,
 p4_pd_dc_lag_hash_input_field_attribute_t *array_of_attrs,
 uint32_t *num_attr_filled
);

typedef enum p4_pd_dc_lkp_ipv4_hash1_input{
  P4_PD_DC_LKP_IPV4_HASH1_INPUT_LKP_IPV4_HASH1_FIELDS,
  P4_PD_DC_LKP_IPV4_HASH1_INPUT_LKP_IPV4_HASH1_FIELDS_1,
} p4_pd_dc_lkp_ipv4_hash1_input_t;

typedef struct p4_pd_dc_lkp_ipv4_hash1_input_field_attribute{
  union {
    p4_pd_dc_input_fields_lkp_ipv4_hash1_fields_t lkp_ipv4_hash1_fields;
    p4_pd_dc_input_fields_lkp_ipv4_hash1_fields_1_t lkp_ipv4_hash1_fields_1;
    uint32_t id;
  } input_field;
  p4_pd_dc_input_field_attr_type_t type;
  union {
    p4_pd_dc_input_field_attr_value_mask_t mask;
    uint64_t val;
  } value;
} p4_pd_dc_lkp_ipv4_hash1_input_field_attribute_t;

typedef enum p4_pd_dc_lkp_ipv4_hash1_algo {
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_DECT,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC16,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_GENIBUS,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_DNP,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_TELEDISK,
} p4_pd_dc_lkp_ipv4_hash1_algo_t;

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_input_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv4_hash1_input_t input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_input_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv4_hash1_input_t *input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_algorithm_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv4_hash1_algo_t algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_algorithm_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv4_hash1_algo_t *algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_seed_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_seed_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t *seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_input_field_attribute_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv4_hash1_input_t input,
 uint32_t attr_count,
 p4_pd_dc_lkp_ipv4_hash1_input_field_attribute_t *array_of_attrs
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_input_field_attribute_count_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv4_hash1_input_t input,
 uint32_t *attr_count
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_ipv4_hash1_input_field_attribute_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_ipv4_hash1_input_t input,
 uint32_t max_attr_count,
 p4_pd_dc_lkp_ipv4_hash1_input_field_attribute_t *array_of_attrs,
 uint32_t *num_attr_filled
);

typedef enum p4_pd_dc_lkp_non_ip_hash1_input{
  P4_PD_DC_LKP_NON_IP_HASH1_INPUT_LKP_NON_IP_HASH1_FIELDS,
  P4_PD_DC_LKP_NON_IP_HASH1_INPUT_LKP_NON_IP_HASH1_FIELDS_1,
} p4_pd_dc_lkp_non_ip_hash1_input_t;

typedef struct p4_pd_dc_lkp_non_ip_hash1_input_field_attribute{
  union {
    p4_pd_dc_input_fields_lkp_non_ip_hash1_fields_t lkp_non_ip_hash1_fields;
    p4_pd_dc_input_fields_lkp_non_ip_hash1_fields_1_t lkp_non_ip_hash1_fields_1;
    uint32_t id;
  } input_field;
  p4_pd_dc_input_field_attr_type_t type;
  union {
    p4_pd_dc_input_field_attr_value_mask_t mask;
    uint64_t val;
  } value;
} p4_pd_dc_lkp_non_ip_hash1_input_field_attribute_t;

typedef enum p4_pd_dc_lkp_non_ip_hash1_algo {
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_DECT,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC16,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_GENIBUS,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_DNP,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_TELEDISK,
} p4_pd_dc_lkp_non_ip_hash1_algo_t;

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_input_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_non_ip_hash1_input_t input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_input_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_non_ip_hash1_input_t *input
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_algorithm_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_non_ip_hash1_algo_t algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_algorithm_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_non_ip_hash1_algo_t *algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_seed_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_seed_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t *seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_input_field_attribute_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_non_ip_hash1_input_t input,
 uint32_t attr_count,
 p4_pd_dc_lkp_non_ip_hash1_input_field_attribute_t *array_of_attrs
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_input_field_attribute_count_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_non_ip_hash1_input_t input,
 uint32_t *attr_count
);

p4_pd_status_t
p4_pd_dc_hash_calc_lkp_non_ip_hash1_input_field_attribute_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_lkp_non_ip_hash1_input_t input,
 uint32_t max_attr_count,
 p4_pd_dc_lkp_non_ip_hash1_input_field_attribute_t *array_of_attrs,
 uint32_t *num_attr_filled
);

typedef enum p4_pd_dc_ecmp_hash_input{
  P4_PD_DC_ECMP_HASH_INPUT_L3_HASH_FIELDS,
} p4_pd_dc_ecmp_hash_input_t;

typedef struct p4_pd_dc_ecmp_hash_input_field_attribute{
  union {
    p4_pd_dc_input_fields_l3_hash_fields_t l3_hash_fields;
    uint32_t id;
  } input_field;
  p4_pd_dc_input_field_attr_type_t type;
  union {
    p4_pd_dc_input_field_attr_value_mask_t mask;
    uint64_t val;
  } value;
} p4_pd_dc_ecmp_hash_input_field_attribute_t;

typedef enum p4_pd_dc_ecmp_hash_algo {
  P4_PD_DC_ECMP_HASH_ALGORITHM_IDENTITY,
  P4_PD_DC_ECMP_HASH_ALGORITHM_CRC_16_DECT,
} p4_pd_dc_ecmp_hash_algo_t;

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_input_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_ecmp_hash_input_t input
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_input_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_ecmp_hash_input_t *input
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_algorithm_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_ecmp_hash_algo_t algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_algorithm_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_ecmp_hash_algo_t *algo
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_seed_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_seed_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 uint64_t *seed
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_input_field_attribute_set
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_ecmp_hash_input_t input,
 uint32_t attr_count,
 p4_pd_dc_ecmp_hash_input_field_attribute_t *array_of_attrs
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_input_field_attribute_count_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_ecmp_hash_input_t input,
 uint32_t *attr_count
);

p4_pd_status_t
p4_pd_dc_hash_calc_ecmp_hash_input_field_attribute_get
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_dc_ecmp_hash_input_t input,
 uint32_t max_attr_count,
 p4_pd_dc_ecmp_hash_input_field_attribute_t *array_of_attrs,
 uint32_t *num_attr_filled
);

#endif
