# BFN Thrift RPC Input

include "res.thrift"


namespace py p4_pd_rpc
namespace cpp p4_pd_rpc
namespace c_glib p4_pd_rpc

typedef i32 EntryHandle_t
typedef i32 MemberHandle_t
typedef i32 GroupHandle_t
typedef string MacAddr_t
typedef string IPv6_t
typedef i32 SnapshotHandle_t
typedef i32 PvsHandle_t

struct dc_counter_value_t {
  1: required i64 packets;
  2: required i64 bytes;
}

struct dc_packets_meter_spec_t {
  1: required i64 cir_pps;
  2: required i64 cburst_pkts;
  3: required i64 pir_pps;
  4: required i64 pburst_pkts;
  5: required bool color_aware;
  6: optional bool is_set = 1;
}

struct dc_bytes_meter_spec_t {
  1: required i64 cir_kbps;
  2: required i64 cburst_kbits;
  3: required i64 pir_kbps;
  4: required i64 pburst_kbits;
  5: required bool color_aware;
  6: optional bool is_set = 1;
}

enum dc_lpf_type {
  TYPE_RATE = 0,
  TYPE_SAMPLE = 1
}

struct dc_lpf_spec_t {
  1: required bool gain_decay_separate_time_constant;
  2: required double gain_time_constant;
  3: required double decay_time_constant;
  4: required double time_constant;
  5: required i32 output_scale_down_factor;
  6: required dc_lpf_type lpf_type;
  7: optional bool is_set = 1;
}

struct dc_wred_spec_t {
  1: required double time_constant;
  2: required i32 red_min_threshold;
  3: required i32 red_max_threshold;
  4: required double max_probability;
  5: optional bool is_set = 1;
}


enum dc_idle_time_mode {
  POLL_MODE = 0,
  NOTIFY_MODE = 1
}

enum dc_idle_time_hit_state {
  ENTRY_IDLE = 0,
  ENTRY_ACTIVE = 1
}

struct dc_idle_time_params_t {
  1: required dc_idle_time_mode mode;
  2: optional i32 ttl_query_interval;
  3: optional i32 max_ttl;
  4: optional i32 min_ttl;
  5: optional i32 cookie;
}

struct dc_idle_tmo_expired_t {
  1: required i32 dev_id;
  2: required EntryHandle_t entry;
  3: required i32 cookie;
}

struct dc_sel_update_t {
  1: required res.SessionHandle_t  sess_hdl;
  2: required res.DevTarget_t      dev_tgt;
  3: required i32                  cookie;
  4: required i32                  grp_hdl;
  5: required i32                  mbr_hdl;
  6: required i32                  index;
  7: required bool                 is_add;
}

enum dc_grp_mbr_state {
  MBR_ACTIVE = 0,
  MBR_INACTIVE = 1
}


enum tbl_property_t
{
   TBL_PROP_TBL_ENTRY_SCOPE = 1,
   TBL_PROP_TERN_TABLE_ENTRY_PLACEMENT = 2,
   TBL_PROP_DUPLICATE_ENTRY_CHECK = 3,
   TBL_PROP_IDLETIME_REPEATED_NOTIFICATION = 4
}

enum tbl_property_value_t
{
   ENTRY_SCOPE_ALL_PIPELINES=0,
   ENTRY_SCOPE_SINGLE_PIPELINE=1,
   ENTRY_SCOPE_USER_DEFINED=2,
   TERN_ENTRY_PLACEMENT_DRV_MANAGED=0,
   TERN_ENTRY_PLACEMENT_APP_MANAGED=1,
   DUPLICATE_ENTRY_CHECK_DISABLE=0,
   DUPLICATE_ENTRY_CHECK_ENABLE=1,
   IDLETIME_REPEATED_NOTIFICATION_DISABLE = 0,
   IDLETIME_REPEATED_NOTIFICATION_ENABLE = 1
}

struct tbl_property_value_args_t
{
  1: required tbl_property_value_t value;
  2: required i32                  scope_args;
}

enum pvs_gress_t
{
   PVS_GRESS_INGRESS = 0,
   PVS_GRESS_EGRESS = 1,
   PVS_GRESS_ALL = 0xff
}

enum pvs_property_t {
  PVS_PROP_NONE = 0,
  PVS_GRESS_SCOPE,
  PVS_PIPE_SCOPE,
  PVS_PARSER_SCOPE
}

enum pvs_property_value_t {
  PVS_SCOPE_ALL_GRESS = 0,
  PVS_SCOPE_SINGLE_GRESS = 1,
  PVS_SCOPE_ALL_PIPELINES = 0,
  PVS_SCOPE_SINGLE_PIPELINE = 1,
  PVS_SCOPE_ALL_PARSERS = 0,
  PVS_SCOPE_SINGLE_PARSER = 1
}  

# not very space efficient but convenient
struct dc_counter_flags_t {
  1: required bool read_hw_sync;
}

struct dc_register_flags_t {
  1: required bool read_hw_sync;
}

struct dc_snapshot_trig_spec_t {
  1: required string field_name;
  2: required i64 field_value;
  3: required i64 field_mask;
}

struct dc_snapshot_tbl_data_t {
  1: required bool hit;
  2: required bool inhibited;
  3: required bool executed;
  4: required i32 hit_entry_handle;
}


enum dc_input_fields_lkp_non_ip_hash1_fields_1_t {
  LKP_NON_IP_HASH1_FIELDS_1_L2_METADATA_LKP_MAC_DA = 0,
  LKP_NON_IP_HASH1_FIELDS_1_INGRESS_METADATA_IFINDEX = 1,
  LKP_NON_IP_HASH1_FIELDS_1_L2_METADATA_LKP_MAC_SA = 2,
  LKP_NON_IP_HASH1_FIELDS_1_L2_METADATA_LKP_MAC_TYPE = 3,
}

enum dc_input_fields_lkp_ipv6_hash1_fields_1_t {
  LKP_IPV6_HASH1_FIELDS_1_IPV6_METADATA_LKP_IPV6_DA = 0,
  LKP_IPV6_HASH1_FIELDS_1_L3_METADATA_LKP_L4_SPORT = 1,
  LKP_IPV6_HASH1_FIELDS_1_IPV6_METADATA_LKP_IPV6_SA = 2,
  LKP_IPV6_HASH1_FIELDS_1_L3_METADATA_LKP_L4_DPORT = 3,
  LKP_IPV6_HASH1_FIELDS_1_L3_METADATA_LKP_IP_PROTO = 4,
}

enum dc_input_fields_lkp_ipv6_hash1_fields_t {
  LKP_IPV6_HASH1_FIELDS_L3_METADATA_LKP_L4_DPORT = 0,
  LKP_IPV6_HASH1_FIELDS_L3_METADATA_LKP_L4_SPORT = 1,
  LKP_IPV6_HASH1_FIELDS_L3_METADATA_LKP_IP_PROTO = 2,
  LKP_IPV6_HASH1_FIELDS_IPV6_METADATA_LKP_IPV6_DA = 3,
  LKP_IPV6_HASH1_FIELDS_IPV6_METADATA_LKP_IPV6_SA = 4,
}

enum dc_input_fields_lag_hash_fields_t {
  LAG_HASH_FIELDS_HASH_METADATA_HASH2 = 0,
}

enum dc_input_fields_lkp_ipv4_hash1_fields_t {
  LKP_IPV4_HASH1_FIELDS_L3_METADATA_LKP_L4_DPORT = 0,
  LKP_IPV4_HASH1_FIELDS_L3_METADATA_LKP_L4_SPORT = 1,
  LKP_IPV4_HASH1_FIELDS_L3_METADATA_LKP_IP_PROTO = 2,
  LKP_IPV4_HASH1_FIELDS_IPV4_METADATA_LKP_IPV4_DA = 3,
  LKP_IPV4_HASH1_FIELDS_IPV4_METADATA_LKP_IPV4_SA = 4,
}

enum dc_input_fields_l3_hash_fields_t {
  L3_HASH_FIELDS_HASH_METADATA_HASH1 = 0,
}

enum dc_input_fields_lkp_ipv4_hash1_fields_1_t {
  LKP_IPV4_HASH1_FIELDS_1_IPV4_METADATA_LKP_IPV4_SA = 0,
  LKP_IPV4_HASH1_FIELDS_1_L3_METADATA_LKP_L4_SPORT = 1,
  LKP_IPV4_HASH1_FIELDS_1_IPV4_METADATA_LKP_IPV4_DA = 2,
  LKP_IPV4_HASH1_FIELDS_1_L3_METADATA_LKP_L4_DPORT = 3,
  LKP_IPV4_HASH1_FIELDS_1_L3_METADATA_LKP_IP_PROTO = 4,
}

enum dc_input_fields_lkp_non_ip_hash1_fields_t {
  LKP_NON_IP_HASH1_FIELDS_L2_METADATA_LKP_MAC_TYPE = 0,
  LKP_NON_IP_HASH1_FIELDS_L2_METADATA_LKP_MAC_DA = 1,
  LKP_NON_IP_HASH1_FIELDS_L2_METADATA_LKP_MAC_SA = 2,
  LKP_NON_IP_HASH1_FIELDS_INGRESS_METADATA_IFINDEX = 3,
}

enum dc_input_field_attr_type_t {
  INPUT_FIELD_ATTR_TYPE_MASK
}

enum dc_input_field_attr_value_mask_t {
  INPUT_FIELD_INCLUDED = 0,
  INPUT_FIELD_EXCLUDED
}

enum dc_lkp_ipv6_hash1_input_t {
  P4_PD_DC_LKP_IPV6_HASH1_INPUT_LKP_IPV6_HASH1_FIELDS,
  P4_PD_DC_LKP_IPV6_HASH1_INPUT_LKP_IPV6_HASH1_FIELDS_1,
}

union dc_lkp_ipv6_hash1_input_fields_union_t {
  1: dc_input_fields_lkp_ipv6_hash1_fields_t lkp_ipv6_hash1_fields
  2: dc_input_fields_lkp_ipv6_hash1_fields_1_t lkp_ipv6_hash1_fields_1
  3: i32 id
}

union dc_lkp_ipv6_hash1_input_field_attr_value_union_t {
  1: dc_input_field_attr_value_mask_t mask
  2: i64 attr_val
}

struct dc_lkp_ipv6_hash1_input_field_attribute_t {
  1: required i32 input_field;
  2: required dc_input_field_attr_type_t type;
  3: required i64 value;
}

enum  dc_lkp_ipv6_hash1_algo_t {
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_DECT,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC16,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_GENIBUS,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_DNP,
  P4_PD_DC_LKP_IPV6_HASH1_ALGORITHM_CRC_16_TELEDISK,
}
enum dc_lag_hash_input_t {
  P4_PD_DC_LAG_HASH_INPUT_LAG_HASH_FIELDS,
}

union dc_lag_hash_input_fields_union_t {
  1: dc_input_fields_lag_hash_fields_t lag_hash_fields
  2: i32 id
}

union dc_lag_hash_input_field_attr_value_union_t {
  1: dc_input_field_attr_value_mask_t mask
  2: i64 attr_val
}

struct dc_lag_hash_input_field_attribute_t {
  1: required i32 input_field;
  2: required dc_input_field_attr_type_t type;
  3: required i64 value;
}

enum  dc_lag_hash_algo_t {
  P4_PD_DC_LAG_HASH_ALGORITHM_IDENTITY,
  P4_PD_DC_LAG_HASH_ALGORITHM_CRC_16_DECT,
}
enum dc_lkp_ipv4_hash1_input_t {
  P4_PD_DC_LKP_IPV4_HASH1_INPUT_LKP_IPV4_HASH1_FIELDS,
  P4_PD_DC_LKP_IPV4_HASH1_INPUT_LKP_IPV4_HASH1_FIELDS_1,
}

union dc_lkp_ipv4_hash1_input_fields_union_t {
  1: dc_input_fields_lkp_ipv4_hash1_fields_t lkp_ipv4_hash1_fields
  2: dc_input_fields_lkp_ipv4_hash1_fields_1_t lkp_ipv4_hash1_fields_1
  3: i32 id
}

union dc_lkp_ipv4_hash1_input_field_attr_value_union_t {
  1: dc_input_field_attr_value_mask_t mask
  2: i64 attr_val
}

struct dc_lkp_ipv4_hash1_input_field_attribute_t {
  1: required i32 input_field;
  2: required dc_input_field_attr_type_t type;
  3: required i64 value;
}

enum  dc_lkp_ipv4_hash1_algo_t {
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_DECT,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC16,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_GENIBUS,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_DNP,
  P4_PD_DC_LKP_IPV4_HASH1_ALGORITHM_CRC_16_TELEDISK,
}
enum dc_lkp_non_ip_hash1_input_t {
  P4_PD_DC_LKP_NON_IP_HASH1_INPUT_LKP_NON_IP_HASH1_FIELDS,
  P4_PD_DC_LKP_NON_IP_HASH1_INPUT_LKP_NON_IP_HASH1_FIELDS_1,
}

union dc_lkp_non_ip_hash1_input_fields_union_t {
  1: dc_input_fields_lkp_non_ip_hash1_fields_t lkp_non_ip_hash1_fields
  2: dc_input_fields_lkp_non_ip_hash1_fields_1_t lkp_non_ip_hash1_fields_1
  3: i32 id
}

union dc_lkp_non_ip_hash1_input_field_attr_value_union_t {
  1: dc_input_field_attr_value_mask_t mask
  2: i64 attr_val
}

struct dc_lkp_non_ip_hash1_input_field_attribute_t {
  1: required i32 input_field;
  2: required dc_input_field_attr_type_t type;
  3: required i64 value;
}

enum  dc_lkp_non_ip_hash1_algo_t {
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_DECT,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC16,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_GENIBUS,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_DNP,
  P4_PD_DC_LKP_NON_IP_HASH1_ALGORITHM_CRC_16_TELEDISK,
}
enum dc_ecmp_hash_input_t {
  P4_PD_DC_ECMP_HASH_INPUT_L3_HASH_FIELDS,
}

union dc_ecmp_hash_input_fields_union_t {
  1: dc_input_fields_l3_hash_fields_t l3_hash_fields
  2: i32 id
}

union dc_ecmp_hash_input_field_attr_value_union_t {
  1: dc_input_field_attr_value_mask_t mask
  2: i64 attr_val
}

struct dc_ecmp_hash_input_field_attribute_t {
  1: required i32 input_field;
  2: required dc_input_field_attr_type_t type;
  3: required i64 value;
}

enum  dc_ecmp_hash_algo_t {
  P4_PD_DC_ECMP_HASH_ALGORITHM_IDENTITY,
  P4_PD_DC_ECMP_HASH_ALGORITHM_CRC_16_DECT,
}


# Match structs

struct dc_validate_outer_ethernet_match_spec_t {
  1: required MacAddr_t ethernet_srcAddr;
  2: required MacAddr_t ethernet_srcAddr_mask;
  3: required MacAddr_t ethernet_dstAddr;
  4: required MacAddr_t ethernet_dstAddr_mask;
  5: required byte vlan_tag__0__valid;
  6: required byte vlan_tag__0__valid_mask;
}

struct dc_ingress_port_mapping_match_spec_t {
  1: required i16 ig_intr_md_ingress_port;
}

struct dc_ingress_port_properties_match_spec_t {
  1: required i16 ig_intr_md_ingress_port;
}

struct dc_port_vlan_to_bd_mapping_match_spec_t {
  1: required i16 ingress_metadata_port_lag_index;
  2: required byte vlan_tag__0__valid;
  3: required i16 vlan_tag__0__vid;
}

struct dc_port_vlan_to_ifindex_mapping_match_spec_t {
  1: required i16 ingress_metadata_port_lag_index;
  2: required byte vlan_tag__0__valid;
  3: required i16 vlan_tag__0__vid;
}

struct dc_cpu_packet_transform_match_spec_t {
  1: required i16 fabric_header_cpu_ingressBd;
}

struct dc_lag_group_match_spec_t {
  1: required i16 ingress_metadata_egress_port_lag_index;
}

struct dc_egress_port_mapping_match_spec_t {
  1: required i16 eg_intr_md_egress_port;
}

struct dc_egress_vlan_xlate_match_spec_t {
  1: required i16 ingress_metadata_egress_ifindex;
  2: required i16 egress_metadata_outer_bd;
}

struct dc_spanning_tree_match_spec_t {
  1: required i16 ingress_metadata_ifindex;
  2: required i16 l2_metadata_stp_group;
}

struct dc_smac_match_spec_t {
  1: required i16 ingress_metadata_bd;
  2: required MacAddr_t l2_metadata_lkp_mac_sa;
}

struct dc_dmac_match_spec_t {
  1: required i16 ingress_metadata_bd;
  2: required MacAddr_t l2_metadata_lkp_mac_da;
}

struct dc_learn_notify_match_spec_t {
  1: required byte l2_metadata_l2_src_miss;
  2: required byte l2_metadata_l2_src_miss_mask;
  3: required i16 l2_metadata_l2_src_move;
  4: required i16 l2_metadata_l2_src_move_mask;
  5: required byte l2_metadata_stp_state;
  6: required byte l2_metadata_stp_state_mask;
}

struct dc_validate_packet_match_spec_t {
  1: required MacAddr_t l2_metadata_lkp_mac_sa;
  2: required MacAddr_t l2_metadata_lkp_mac_sa_mask;
  3: required MacAddr_t l2_metadata_lkp_mac_da;
  4: required MacAddr_t l2_metadata_lkp_mac_da_mask;
  5: required byte l3_metadata_lkp_ip_type;
  6: required byte l3_metadata_lkp_ip_type_mask;
  7: required byte l3_metadata_lkp_ip_ttl;
  8: required byte l3_metadata_lkp_ip_ttl_mask;
  9: required byte l3_metadata_lkp_ip_version;
  10: required byte l3_metadata_lkp_ip_version_mask;
  11: required byte tunnel_metadata_tunnel_terminate;
  12: required byte tunnel_metadata_tunnel_terminate_mask;
  13: required byte inner_ipv4_ihl;
  14: required byte inner_ipv4_ihl_mask;
  15: required i32 ipv4_metadata_lkp_ipv4_sa;
  16: required i32 ipv4_metadata_lkp_ipv4_sa_mask;
  17: required IPv6_t ipv6_metadata_lkp_ipv6_sa;
  18: required IPv6_t ipv6_metadata_lkp_ipv6_sa_mask;
}

struct dc_egress_bd_stats_match_spec_t {
  1: required i16 egress_metadata_bd;
  2: required byte l2_metadata_lkp_pkt_type;
}

struct dc_egress_bd_map_match_spec_t {
  1: required i16 egress_metadata_bd;
}

struct dc_egress_outer_bd_map_match_spec_t {
  1: required i16 egress_metadata_outer_bd;
}

struct dc_vlan_decap_match_spec_t {
  1: required byte vlan_tag__0__valid;
}

struct dc_rmac_match_spec_t {
  1: required i16 l3_metadata_rmac_group;
  2: required MacAddr_t l2_metadata_lkp_mac_da;
}

struct dc_urpf_bd_match_spec_t {
  1: required i16 l3_metadata_urpf_bd_group;
  2: required i16 ingress_metadata_bd;
}

struct dc_smac_rewrite_match_spec_t {
  1: required i16 egress_metadata_smac_idx;
}

struct dc_l3_rewrite_match_spec_t {
  1: required byte ipv4_valid;
  2: required byte ipv6_valid;
  3: required byte mpls_0__valid;
  4: required i32 ipv4_dstAddr;
  5: required i32 ipv4_dstAddr_mask;
  6: required IPv6_t ipv6_dstAddr;
  7: required IPv6_t ipv6_dstAddr_mask;
}

struct dc_mtu_match_spec_t {
  1: required byte l3_metadata_mtu_index;
  2: required byte ipv4_valid;
  3: required byte ipv6_valid;
}

struct dc_validate_outer_ipv4_packet_match_spec_t {
  1: required i16 ig_intr_md_from_parser_aux_ingress_parser_err;
  2: required i16 ig_intr_md_from_parser_aux_ingress_parser_err_mask;
  3: required byte ipv4_version;
  4: required byte ipv4_version_mask;
  5: required byte ipv4_ihl;
  6: required byte ipv4_ihl_mask;
  7: required byte ipv4_ttl;
  8: required byte ipv4_ttl_mask;
  9: required i32 ipv4_srcAddr;
  10: required i32 ipv4_srcAddr_mask;
  11: required i32 ipv4_dstAddr;
  12: required i32 ipv4_dstAddr_mask;
}

struct dc_ipv4_fib_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_metadata_lkp_ipv4_da;
}

struct dc_ipv4_fib_lpm_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_metadata_lkp_ipv4_da;
  3: required i16 ipv4_metadata_lkp_ipv4_da_prefix_length;
}

struct dc_ipv4_urpf_lpm_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_metadata_lkp_ipv4_sa;
  3: required i16 ipv4_metadata_lkp_ipv4_sa_prefix_length;
}

struct dc_ipv4_urpf_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_metadata_lkp_ipv4_sa;
}

struct dc_validate_outer_ipv6_packet_match_spec_t {
  1: required byte ipv6_version;
  2: required byte ipv6_version_mask;
  3: required byte ipv6_hopLimit;
  4: required byte ipv6_hopLimit_mask;
  5: required IPv6_t ipv6_srcAddr;
  6: required IPv6_t ipv6_srcAddr_mask;
  7: required IPv6_t ipv6_dstAddr;
  8: required IPv6_t ipv6_dstAddr_mask;
}

struct dc_ipv6_fib_lpm_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_da;
  3: required i16 ipv6_metadata_lkp_ipv6_da_prefix_length;
}

struct dc_ipv6_fib_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_da;
}

struct dc_ipv6_urpf_lpm_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_sa;
  3: required i16 ipv6_metadata_lkp_ipv6_sa_prefix_length;
}

struct dc_ipv6_urpf_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_sa;
}

struct dc_outer_rmac_match_spec_t {
  1: required i16 l3_metadata_rmac_group;
  2: required MacAddr_t ethernet_dstAddr;
}

struct dc_ipv4_dest_vtep_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_dstAddr;
  3: required byte tunnel_metadata_ingress_tunnel_type;
}

struct dc_ipv4_src_vtep_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_srcAddr;
  3: required byte tunnel_metadata_ingress_tunnel_type;
}

struct dc_ipv6_dest_vtep_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_dstAddr;
  3: required byte tunnel_metadata_ingress_tunnel_type;
}

struct dc_ipv6_src_vtep_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_srcAddr;
  3: required byte tunnel_metadata_ingress_tunnel_type;
}

struct dc_tunnel_match_spec_t {
  1: required i32 tunnel_metadata_tunnel_vni;
  2: required byte mpls_0__valid;
  3: required byte inner_ipv4_valid;
  4: required byte inner_ipv6_valid;
}

struct dc_adjust_lkp_fields_match_spec_t {
  1: required byte ipv4_valid;
  2: required byte ipv6_valid;
}

struct dc_tunnel_lookup_miss_match_spec_t {
  1: required byte ipv4_valid;
  2: required byte ipv6_valid;
}

struct dc_tunnel_check_match_spec_t {
  1: required byte tunnel_metadata_ingress_tunnel_type;
  2: required byte tunnel_metadata_ingress_tunnel_type_mask;
  3: required byte tunnel_metadata_tunnel_lookup;
  4: required byte tunnel_metadata_tunnel_lookup_mask;
  5: required byte tunnel_metadata_src_vtep_hit;
  6: required byte tunnel_metadata_src_vtep_hit_mask;
  7: required byte tunnel_metadata_tunnel_term_type;
  8: required byte tunnel_metadata_tunnel_term_type_mask;
}

struct dc_validate_mpls_packet_match_spec_t {
  1: required byte mpls_0__valid;
}

struct dc_tunnel_decap_process_outer_match_spec_t {
  1: required byte tunnel_metadata_ingress_tunnel_type;
  2: required byte inner_ipv4_valid;
  3: required byte inner_ipv6_valid;
}

struct dc_tunnel_decap_process_inner_match_spec_t {
  1: required byte inner_tcp_valid;
  2: required byte inner_udp_valid;
  3: required byte inner_icmp_valid;
}

struct dc_egress_vni_match_spec_t {
  1: required i16 egress_metadata_bd;
}

struct dc_tunnel_encap_process_inner_match_spec_t {
  1: required byte ipv4_valid;
  2: required byte ipv6_valid;
  3: required byte tcp_valid;
  4: required byte udp_valid;
  5: required byte icmp_valid;
}

struct dc_tunnel_encap_process_outer_match_spec_t {
  1: required byte tunnel_metadata_egress_tunnel_type;
  2: required byte tunnel_metadata_egress_header_count;
  3: required byte multicast_metadata_replica;
}

struct dc_tunnel_rewrite_match_spec_t {
  1: required i16 tunnel_metadata_tunnel_index;
}

struct dc_tunnel_dst_rewrite_match_spec_t {
  1: required i16 tunnel_metadata_tunnel_dst_index;
}

struct dc_tunnel_smac_rewrite_match_spec_t {
  1: required byte tunnel_metadata_tunnel_smac_index;
}

struct dc_tunnel_dmac_rewrite_match_spec_t {
  1: required i16 tunnel_metadata_tunnel_dmac_index;
}

struct dc_tunnel_to_mgid_mapping_match_spec_t {
  1: required i16 tunnel_metadata_tunnel_dst_index;
}

struct dc_ingress_l4_src_port_match_spec_t {
  1: required i16 l3_metadata_lkp_l4_sport_start;
  2: required i16 l3_metadata_lkp_l4_sport_end;
}

struct dc_ingress_l4_dst_port_match_spec_t {
  1: required i16 l3_metadata_lkp_l4_dport_start;
  2: required i16 l3_metadata_lkp_l4_dport_end;
}

struct dc_mac_acl_match_spec_t {
  1: required i16 acl_metadata_port_lag_label;
  2: required i16 acl_metadata_port_lag_label_mask;
  3: required i16 acl_metadata_bd_label;
  4: required i16 acl_metadata_bd_label_mask;
  5: required MacAddr_t l2_metadata_lkp_mac_sa;
  6: required MacAddr_t l2_metadata_lkp_mac_sa_mask;
  7: required MacAddr_t l2_metadata_lkp_mac_da;
  8: required MacAddr_t l2_metadata_lkp_mac_da_mask;
  9: required i16 l2_metadata_lkp_mac_type;
  10: required i16 l2_metadata_lkp_mac_type_mask;
}

struct dc_ip_acl_match_spec_t {
  1: required i16 acl_metadata_port_lag_label;
  2: required i16 acl_metadata_port_lag_label_mask;
  3: required i16 acl_metadata_bd_label;
  4: required i16 acl_metadata_bd_label_mask;
  5: required i32 ipv4_metadata_lkp_ipv4_sa;
  6: required i32 ipv4_metadata_lkp_ipv4_sa_mask;
  7: required i32 ipv4_metadata_lkp_ipv4_da;
  8: required i32 ipv4_metadata_lkp_ipv4_da_mask;
  9: required byte l3_metadata_lkp_ip_proto;
  10: required byte l3_metadata_lkp_ip_proto_mask;
  11: required byte l3_metadata_lkp_ip_ttl;
  12: required byte l3_metadata_lkp_ip_ttl_mask;
  13: required byte l3_metadata_lkp_tcp_flags;
  14: required byte l3_metadata_lkp_tcp_flags_mask;
  15: required byte acl_metadata_ingress_src_port_range_id;
  16: required byte acl_metadata_ingress_src_port_range_id_mask;
  17: required byte acl_metadata_ingress_dst_port_range_id;
  18: required byte acl_metadata_ingress_dst_port_range_id_mask;
  19: required byte l3_metadata_rmac_hit;
  20: required byte l3_metadata_rmac_hit_mask;
}

struct dc_ipv6_acl_match_spec_t {
  1: required i16 acl_metadata_port_lag_label;
  2: required i16 acl_metadata_port_lag_label_mask;
  3: required i16 acl_metadata_bd_label;
  4: required i16 acl_metadata_bd_label_mask;
  5: required IPv6_t ipv6_metadata_lkp_ipv6_sa;
  6: required IPv6_t ipv6_metadata_lkp_ipv6_sa_mask;
  7: required IPv6_t ipv6_metadata_lkp_ipv6_da;
  8: required IPv6_t ipv6_metadata_lkp_ipv6_da_mask;
  9: required byte l3_metadata_lkp_ip_proto;
  10: required byte l3_metadata_lkp_ip_proto_mask;
  11: required byte l3_metadata_lkp_ip_ttl;
  12: required byte l3_metadata_lkp_ip_ttl_mask;
  13: required byte l3_metadata_lkp_tcp_flags;
  14: required byte l3_metadata_lkp_tcp_flags_mask;
  15: required byte acl_metadata_ingress_src_port_range_id;
  16: required byte acl_metadata_ingress_src_port_range_id_mask;
  17: required byte acl_metadata_ingress_dst_port_range_id;
  18: required byte acl_metadata_ingress_dst_port_range_id_mask;
  19: required byte l3_metadata_rmac_hit;
  20: required byte l3_metadata_rmac_hit_mask;
}

struct dc_ipv4_racl_match_spec_t {
  1: required i16 acl_metadata_port_lag_label;
  2: required i16 acl_metadata_port_lag_label_mask;
  3: required i16 acl_metadata_bd_label;
  4: required i16 acl_metadata_bd_label_mask;
  5: required i32 ipv4_metadata_lkp_ipv4_sa;
  6: required i32 ipv4_metadata_lkp_ipv4_sa_mask;
  7: required i32 ipv4_metadata_lkp_ipv4_da;
  8: required i32 ipv4_metadata_lkp_ipv4_da_mask;
  9: required byte l3_metadata_lkp_ip_proto;
  10: required byte l3_metadata_lkp_ip_proto_mask;
  11: required byte l3_metadata_lkp_ip_ttl;
  12: required byte l3_metadata_lkp_ip_ttl_mask;
  13: required byte l3_metadata_lkp_tcp_flags;
  14: required byte l3_metadata_lkp_tcp_flags_mask;
  15: required byte acl_metadata_ingress_src_port_range_id;
  16: required byte acl_metadata_ingress_src_port_range_id_mask;
  17: required byte acl_metadata_ingress_dst_port_range_id;
  18: required byte acl_metadata_ingress_dst_port_range_id_mask;
  19: required byte l3_metadata_rmac_hit;
  20: required byte l3_metadata_rmac_hit_mask;
}

struct dc_ipv6_racl_match_spec_t {
  1: required i16 acl_metadata_port_lag_label;
  2: required i16 acl_metadata_port_lag_label_mask;
  3: required i16 acl_metadata_bd_label;
  4: required i16 acl_metadata_bd_label_mask;
  5: required IPv6_t ipv6_metadata_lkp_ipv6_sa;
  6: required IPv6_t ipv6_metadata_lkp_ipv6_sa_mask;
  7: required IPv6_t ipv6_metadata_lkp_ipv6_da;
  8: required IPv6_t ipv6_metadata_lkp_ipv6_da_mask;
  9: required byte l3_metadata_lkp_ip_proto;
  10: required byte l3_metadata_lkp_ip_proto_mask;
  11: required byte l3_metadata_lkp_ip_ttl;
  12: required byte l3_metadata_lkp_ip_ttl_mask;
  13: required byte l3_metadata_lkp_tcp_flags;
  14: required byte l3_metadata_lkp_tcp_flags_mask;
  15: required byte acl_metadata_ingress_src_port_range_id;
  16: required byte acl_metadata_ingress_src_port_range_id_mask;
  17: required byte acl_metadata_ingress_dst_port_range_id;
  18: required byte acl_metadata_ingress_dst_port_range_id_mask;
  19: required byte l3_metadata_rmac_hit;
  20: required byte l3_metadata_rmac_hit_mask;
}

struct dc_system_acl_match_spec_t {
  1: required i16 acl_metadata_port_lag_label;
  2: required i16 acl_metadata_port_lag_label_mask;
  3: required i16 acl_metadata_bd_label;
  4: required i16 acl_metadata_bd_label_mask;
  5: required i16 ingress_metadata_ifindex;
  6: required i16 ingress_metadata_ifindex_mask;
  7: required i16 l2_metadata_lkp_mac_type;
  8: required i16 l2_metadata_lkp_mac_type_mask;
  9: required byte l2_metadata_port_vlan_mapping_miss;
  10: required byte l2_metadata_port_vlan_mapping_miss_mask;
  11: required byte acl_metadata_acl_deny;
  12: required byte acl_metadata_acl_deny_mask;
  13: required byte acl_metadata_racl_deny;
  14: required byte acl_metadata_racl_deny_mask;
  15: required byte l3_metadata_urpf_check_fail;
  16: required byte l3_metadata_urpf_check_fail_mask;
  17: required byte meter_metadata_storm_control_color;
  18: required byte meter_metadata_storm_control_color_mask;
  19: required byte ingress_metadata_drop_flag;
  20: required byte ingress_metadata_drop_flag_mask;
  21: required byte l3_metadata_l3_copy;
  22: required byte l3_metadata_l3_copy_mask;
  23: required byte l3_metadata_rmac_hit;
  24: required byte l3_metadata_rmac_hit_mask;
  25: required byte l3_metadata_fib_hit_myip;
  26: required byte l3_metadata_fib_hit_myip_mask;
  27: required byte nexthop_metadata_nexthop_glean;
  28: required byte nexthop_metadata_nexthop_glean_mask;
  29: required byte multicast_metadata_mcast_route_hit;
  30: required byte multicast_metadata_mcast_route_hit_mask;
  31: required byte multicast_metadata_mcast_route_s_g_hit;
  32: required byte multicast_metadata_mcast_route_s_g_hit_mask;
  33: required byte multicast_metadata_mcast_copy_to_cpu;
  34: required byte multicast_metadata_mcast_copy_to_cpu_mask;
  35: required byte multicast_metadata_mcast_rpf_fail;
  36: required byte multicast_metadata_mcast_rpf_fail_mask;
  37: required byte l3_metadata_routed;
  38: required byte l3_metadata_routed_mask;
  39: required byte ipv6_metadata_ipv6_src_is_link_local;
  40: required byte ipv6_metadata_ipv6_src_is_link_local_mask;
  41: required i16 l2_metadata_same_if_check;
  42: required i16 l2_metadata_same_if_check_mask;
  43: required byte tunnel_metadata_tunnel_if_check;
  44: required byte tunnel_metadata_tunnel_if_check_mask;
  45: required i16 l3_metadata_same_bd_check;
  46: required i16 l3_metadata_same_bd_check_mask;
  47: required byte l3_metadata_lkp_ip_ttl;
  48: required byte l3_metadata_lkp_ip_ttl_mask;
  49: required byte l2_metadata_stp_state;
  50: required byte l2_metadata_stp_state_mask;
  51: required byte l2_metadata_l2_src_miss;
  52: required byte l2_metadata_l2_src_miss_mask;
  53: required i16 l2_metadata_l2_src_move;
  54: required i16 l2_metadata_l2_src_move_mask;
  55: required byte ipv4_metadata_ipv4_unicast_enabled;
  56: required byte ipv4_metadata_ipv4_unicast_enabled_mask;
  57: required byte ipv6_metadata_ipv6_unicast_enabled;
  58: required byte ipv6_metadata_ipv6_unicast_enabled_mask;
  59: required byte l2_metadata_l2_dst_miss;
  60: required byte l2_metadata_l2_dst_miss_mask;
  61: required byte l2_metadata_lkp_pkt_type;
  62: required byte l2_metadata_lkp_pkt_type_mask;
  63: required byte l2_metadata_arp_opcode;
  64: required byte l2_metadata_arp_opcode_mask;
  65: required i16 ingress_metadata_egress_ifindex;
  66: required i16 ingress_metadata_egress_ifindex_mask;
  67: required i16 fabric_metadata_reason_code;
  68: required i16 fabric_metadata_reason_code_mask;
}

struct dc_egress_system_acl_match_spec_t {
  1: required i16 fabric_metadata_reason_code;
  2: required i16 fabric_metadata_reason_code_mask;
  3: required byte ig_intr_md_for_tm_packet_color;
  4: required byte ig_intr_md_for_tm_packet_color_mask;
  5: required i16 eg_intr_md_egress_port;
  6: required i16 eg_intr_md_egress_port_mask;
  7: required byte eg_intr_md_deflection_flag;
  8: required byte eg_intr_md_deflection_flag_mask;
  9: required i16 l3_metadata_l3_mtu_check;
  10: required i16 l3_metadata_l3_mtu_check_mask;
}

struct dc_ipv4_multicast_bridge_star_g_match_spec_t {
  1: required i16 ingress_metadata_bd;
  2: required i32 ipv4_metadata_lkp_ipv4_da;
}

struct dc_ipv4_multicast_bridge_match_spec_t {
  1: required i16 ingress_metadata_bd;
  2: required i32 ipv4_metadata_lkp_ipv4_sa;
  3: required i32 ipv4_metadata_lkp_ipv4_da;
}

struct dc_ipv4_multicast_route_star_g_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_metadata_lkp_ipv4_da;
}

struct dc_ipv4_multicast_route_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required i32 ipv4_metadata_lkp_ipv4_sa;
  3: required i32 ipv4_metadata_lkp_ipv4_da;
}

struct dc_ipv6_multicast_bridge_star_g_match_spec_t {
  1: required i16 ingress_metadata_bd;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_da;
}

struct dc_ipv6_multicast_bridge_match_spec_t {
  1: required i16 ingress_metadata_bd;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_sa;
  3: required IPv6_t ipv6_metadata_lkp_ipv6_da;
}

struct dc_ipv6_multicast_route_star_g_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_da;
}

struct dc_ipv6_multicast_route_match_spec_t {
  1: required i16 l3_metadata_vrf;
  2: required IPv6_t ipv6_metadata_lkp_ipv6_sa;
  3: required IPv6_t ipv6_metadata_lkp_ipv6_da;
}

struct dc_bd_flood_match_spec_t {
  1: required i16 ingress_metadata_bd;
  2: required byte l2_metadata_lkp_pkt_type;
  3: required byte multicast_metadata_flood_to_mrouters;
}

struct dc_rid_match_spec_t {
  1: required i16 eg_intr_md_egress_rid;
}

struct dc_mcast_egress_ifindex_match_spec_t {
  1: required i16 eg_intr_md_egress_rid;
}

struct dc_replica_type_match_spec_t {
  1: required byte multicast_metadata_replica;
  2: required i16 egress_metadata_same_bd_check;
  3: required i16 egress_metadata_same_bd_check_mask;
}

struct dc_fwd_result_match_spec_t {
  1: required byte l2_metadata_l2_redirect;
  2: required byte l2_metadata_l2_redirect_mask;
  3: required byte acl_metadata_acl_redirect;
  4: required byte acl_metadata_acl_redirect_mask;
  5: required byte acl_metadata_racl_redirect;
  6: required byte acl_metadata_racl_redirect_mask;
  7: required byte l3_metadata_rmac_hit;
  8: required byte l3_metadata_rmac_hit_mask;
  9: required byte l3_metadata_fib_hit;
  10: required byte l3_metadata_fib_hit_mask;
  11: required byte l2_metadata_lkp_pkt_type;
  12: required byte l2_metadata_lkp_pkt_type_mask;
  13: required byte l3_metadata_lkp_ip_type;
  14: required byte l3_metadata_lkp_ip_type_mask;
  15: required byte multicast_metadata_igmp_snooping_enabled;
  16: required byte multicast_metadata_igmp_snooping_enabled_mask;
  17: required byte multicast_metadata_mld_snooping_enabled;
  18: required byte multicast_metadata_mld_snooping_enabled_mask;
  19: required byte multicast_metadata_mcast_route_hit;
  20: required byte multicast_metadata_mcast_route_hit_mask;
  21: required byte multicast_metadata_mcast_bridge_hit;
  22: required byte multicast_metadata_mcast_bridge_hit_mask;
  23: required i16 multicast_metadata_mcast_rpf_group;
  24: required i16 multicast_metadata_mcast_rpf_group_mask;
  25: required byte multicast_metadata_mcast_mode;
  26: required byte multicast_metadata_mcast_mode_mask;
  27: required byte nexthop_metadata_nexthop_type;
  28: required byte nexthop_metadata_nexthop_type_mask;
  29: required byte l3_metadata_lkp_ip_llmc;
  30: required byte l3_metadata_lkp_ip_llmc_mask;
  31: required byte l3_metadata_lkp_ip_mc;
  32: required byte l3_metadata_lkp_ip_mc_mask;
}

struct dc_ecmp_group_match_spec_t {
  1: required i16 l3_metadata_nexthop_index;
}

struct dc_nexthop_match_spec_t {
  1: required i16 l3_metadata_nexthop_index;
}

struct dc_rewrite_match_spec_t {
  1: required i16 l3_metadata_nexthop_index;
}

struct dc_storm_control_stats_match_spec_t {
  1: required byte meter_metadata_storm_control_color;
  2: required byte l2_metadata_lkp_pkt_type;
  3: required byte l2_metadata_lkp_pkt_type_mask;
  4: required i16 ig_intr_md_ingress_port;
}

struct dc_storm_control_match_spec_t {
  1: required i16 ig_intr_md_ingress_port;
  2: required byte l2_metadata_lkp_pkt_type;
  3: required byte l2_metadata_lkp_pkt_type_mask;
}

struct dc_fabric_ingress_dst_lkp_match_spec_t {
  1: required byte fabric_header_dstDevice;
}

struct dc_mirror_match_spec_t {
  1: required i16 i2e_metadata_mirror_session_id;
}

struct dc_compute_ipv4_hashes_match_spec_t {
  1: required byte ethernet_valid;
}

struct dc_compute_ipv6_hashes_match_spec_t {
  1: required byte ethernet_valid;
}

struct dc_compute_non_ip_hashes_match_spec_t {
  1: required byte ethernet_valid;
}

struct dc_compute_other_hashes_match_spec_t {
  1: required byte ethernet_valid;
}


# Match struct for Dynamic Key Mask Exm Table.


# Action structs

struct dc_set_config_parameters_action_spec_t {
  1: required i32 action_enable_flowlet;
  2: required i32 action_switch_id;
}

struct dc_malformed_outer_ethernet_packet_action_spec_t {
  1: required byte action_drop_reason;
}

struct dc_set_port_lag_index_action_spec_t {
  1: required i16 action_port_lag_index;
  2: required byte action_port_type;
}

struct dc_set_ingress_port_properties_action_spec_t {
  1: required i16 action_port_lag_label;
  2: required i16 action_exclusion_id;
  3: required byte action_qos_group;
  4: required i32 action_tc_qos_group;
  5: required byte action_tc;
  6: required byte action_color;
  7: required byte action_learning_enabled;
  8: required byte action_trust_dscp;
  9: required byte action_trust_pcp;
}

struct dc_set_bd_properties_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_vrf;
  3: required i16 action_stp_group;
  4: required byte action_learning_enabled;
  5: required i16 action_bd_label;
  6: required i16 action_stats_idx;
  7: required i16 action_rmac_group;
  8: required byte action_ipv4_unicast_enabled;
  9: required byte action_ipv6_unicast_enabled;
  10: required byte action_ipv4_urpf_mode;
  11: required byte action_ipv6_urpf_mode;
  12: required byte action_igmp_snooping_enabled;
  13: required byte action_mld_snooping_enabled;
  14: required byte action_ipv4_multicast_enabled;
  15: required byte action_ipv6_multicast_enabled;
  16: required i16 action_mrpf_group;
  17: required i32 action_ipv4_mcast_key;
  18: required i32 action_ipv4_mcast_key_type;
  19: required i32 action_ipv6_mcast_key;
  20: required i32 action_ipv6_mcast_key_type;
}

struct dc_set_ingress_interface_properties_action_spec_t {
  1: required i16 action_ingress_rid;
  2: required i16 action_ifindex;
  3: required i32 action_if_label;
}

struct dc_set_lag_port_action_spec_t {
  1: required i16 action_port;
}

struct dc_egress_port_type_normal_action_spec_t {
  1: required byte action_qos_group;
  2: required i16 action_port_lag_label;
  3: required i32 action_mlag_member;
}

struct dc_set_egress_if_params_tagged_action_spec_t {
  1: required i16 action_vlan_id;
  2: required i32 action_egress_if_label;
}

struct dc_set_stp_state_action_spec_t {
  1: required byte action_stp_state;
}

struct dc_smac_hit_action_spec_t {
  1: required i16 action_ifindex;
}

struct dc_dmac_hit_action_spec_t {
  1: required i16 action_ifindex;
  2: required i16 action_port_lag_index;
}

struct dc_dmac_multicast_hit_action_spec_t {
  1: required i16 action_mc_index;
}

struct dc_dmac_redirect_nexthop_action_spec_t {
  1: required i16 action_nexthop_index;
}

struct dc_dmac_redirect_ecmp_action_spec_t {
  1: required i16 action_ecmp_index;
}

struct dc_set_malformed_packet_action_spec_t {
  1: required byte action_drop_reason;
}

struct dc_set_egress_bd_properties_action_spec_t {
  1: required i16 action_smac_idx;
  2: required byte action_mtu_index;
  3: required byte action_nat_mode;
  4: required i16 action_bd_label;
}

struct dc_set_egress_outer_bd_properties_action_spec_t {
  1: required byte action_smac_idx;
  2: required byte action_sip_idx;
  3: required i32 action_mtu_index;
  4: required i32 action_outer_bd_label;
}

struct dc_rewrite_smac_action_spec_t {
  1: required MacAddr_t action_smac;
}

struct dc_ipv4_mtu_check_action_spec_t {
  1: required i16 action_l3_mtu;
}

struct dc_ipv6_mtu_check_action_spec_t {
  1: required i16 action_l3_mtu;
}

struct dc_set_malformed_outer_ipv4_packet_action_spec_t {
  1: required byte action_drop_reason;
}

struct dc_fib_hit_nexthop_action_spec_t {
  1: required i16 action_nexthop_index;
  2: required i32 action_acl_label;
}

struct dc_fib_hit_myip_action_spec_t {
  1: required i16 action_nexthop_index;
  2: required i32 action_acl_label;
}

struct dc_fib_hit_ecmp_action_spec_t {
  1: required i16 action_ecmp_index;
  2: required i32 action_acl_label;
}

struct dc_ipv4_urpf_hit_action_spec_t {
  1: required i16 action_urpf_bd_group;
}

struct dc_set_malformed_outer_ipv6_packet_action_spec_t {
  1: required byte action_drop_reason;
}

struct dc_ipv6_urpf_hit_action_spec_t {
  1: required i16 action_urpf_bd_group;
}

struct dc_set_tunnel_lookup_flag_action_spec_t {
  1: required byte action_term_type;
}

struct dc_set_tunnel_vni_and_lookup_flag_action_spec_t {
  1: required i32 action_tunnel_vni;
  2: required byte action_term_type;
}

struct dc_src_vtep_hit_action_spec_t {
  1: required i16 action_ifindex;
}

struct dc_terminate_tunnel_inner_non_ip_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_bd_label;
  3: required i16 action_stats_idx;
  4: required i16 action_exclusion_id;
  5: required i16 action_ingress_rid;
}

struct dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_vrf;
  3: required i16 action_rmac_group;
  4: required i16 action_bd_label;
  5: required byte action_ipv4_unicast_enabled;
  6: required byte action_ipv4_urpf_mode;
  7: required byte action_igmp_snooping_enabled;
  8: required i16 action_stats_idx;
  9: required byte action_ipv4_multicast_enabled;
  10: required i16 action_mrpf_group;
  11: required i16 action_exclusion_id;
  12: required i16 action_ingress_rid;
}

struct dc_terminate_tunnel_inner_ipv4_action_spec_t {
  1: required i16 action_vrf;
  2: required i16 action_rmac_group;
  3: required byte action_ipv4_urpf_mode;
  4: required byte action_ipv4_unicast_enabled;
  5: required byte action_ipv4_multicast_enabled;
  6: required i16 action_mrpf_group;
}

struct dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_vrf;
  3: required i16 action_rmac_group;
  4: required i16 action_bd_label;
  5: required byte action_ipv6_unicast_enabled;
  6: required byte action_ipv6_urpf_mode;
  7: required byte action_mld_snooping_enabled;
  8: required i16 action_stats_idx;
  9: required byte action_ipv6_multicast_enabled;
  10: required i16 action_mrpf_group;
  11: required i16 action_exclusion_id;
  12: required i16 action_ingress_rid;
}

struct dc_terminate_tunnel_inner_ipv6_action_spec_t {
  1: required i16 action_vrf;
  2: required i16 action_rmac_group;
  3: required byte action_ipv6_unicast_enabled;
  4: required byte action_ipv6_urpf_mode;
  5: required byte action_ipv6_multicast_enabled;
  6: required i16 action_mrpf_group;
}

struct dc_terminate_eompls_action_spec_t {
  1: required i16 action_bd;
  2: required byte action_tunnel_type;
}

struct dc_terminate_vpls_action_spec_t {
  1: required i16 action_bd;
  2: required byte action_tunnel_type;
}

struct dc_terminate_ipv4_over_mpls_action_spec_t {
  1: required i16 action_vrf;
  2: required byte action_tunnel_type;
}

struct dc_terminate_ipv6_over_mpls_action_spec_t {
  1: required i16 action_vrf;
  2: required byte action_tunnel_type;
}

struct dc_terminate_pw_action_spec_t {
  1: required i16 action_ifindex;
}

struct dc_forward_mpls_action_spec_t {
  1: required i16 action_nexthop_index;
}

struct dc_set_egress_tunnel_vni_action_spec_t {
  1: required i32 action_vnid;
}

struct dc_set_ipv4_tunnel_rewrite_details_action_spec_t {
  1: required i32 action_ipv4_sa;
}

struct dc_set_ipv6_tunnel_rewrite_details_action_spec_t {
  1: required IPv6_t action_ipv6_sa;
}

struct dc_set_mpls_rewrite_push1_action_spec_t {
  1: required i32 action_label1;
  2: required byte action_exp1;
  3: required byte action_ttl1;
  4: required i32 action_smac_idx;
  5: required i32 action_dmac_idx;
  6: required byte action_bos;
}

struct dc_set_mpls_rewrite_push2_action_spec_t {
  1: required i32 action_label1;
  2: required byte action_exp1;
  3: required byte action_ttl1;
  4: required i32 action_label2;
  5: required byte action_exp2;
  6: required byte action_ttl2;
  7: required i32 action_smac_idx;
  8: required i32 action_dmac_idx;
  9: required byte action_bos;
}

struct dc_set_mpls_rewrite_push3_action_spec_t {
  1: required i32 action_label1;
  2: required byte action_exp1;
  3: required byte action_ttl1;
  4: required i32 action_label2;
  5: required byte action_exp2;
  6: required byte action_ttl2;
  7: required i32 action_label3;
  8: required byte action_exp3;
  9: required byte action_ttl3;
  10: required i32 action_smac_idx;
  11: required i32 action_dmac_idx;
  12: required byte action_bos;
}

struct dc_rewrite_tunnel_ipv4_dst_action_spec_t {
  1: required i32 action_ip;
}

struct dc_rewrite_tunnel_ipv6_dst_action_spec_t {
  1: required IPv6_t action_ip;
}

struct dc_rewrite_tunnel_smac_action_spec_t {
  1: required MacAddr_t action_smac;
}

struct dc_rewrite_tunnel_dmac_action_spec_t {
  1: required MacAddr_t action_dmac;
}

struct dc_set_tunnel_mgid_action_spec_t {
  1: required i16 action_mc_index;
}

struct dc_set_ingress_src_port_range_id_action_spec_t {
  1: required byte action_range_id;
}

struct dc_set_ingress_dst_port_range_id_action_spec_t {
  1: required byte action_range_id;
}

struct dc_acl_deny_action_spec_t {
  1: required i16 action_acl_stats_index;
  2: required i32 action_acl_meter_index;
  3: required i16 action_acl_copy_reason;
  4: required byte action_nat_mode;
  5: required i32 action_ingress_cos;
  6: required i32 action_tc;
  7: required i32 action_color;
}

struct dc_acl_permit_action_spec_t {
  1: required i16 action_acl_stats_index;
  2: required i32 action_acl_meter_index;
  3: required i16 action_acl_copy_reason;
  4: required byte action_nat_mode;
  5: required i32 action_ingress_cos;
  6: required i32 action_tc;
  7: required i32 action_color;
}

struct dc_acl_redirect_nexthop_action_spec_t {
  1: required i16 action_nexthop_index;
  2: required i16 action_acl_stats_index;
  3: required i32 action_acl_meter_index;
  4: required i16 action_acl_copy_reason;
  5: required byte action_nat_mode;
  6: required i32 action_ingress_cos;
  7: required i32 action_tc;
  8: required i32 action_color;
}

struct dc_acl_redirect_ecmp_action_spec_t {
  1: required i16 action_ecmp_index;
  2: required i16 action_acl_stats_index;
  3: required i32 action_acl_meter_index;
  4: required i16 action_acl_copy_reason;
  5: required byte action_nat_mode;
  6: required i32 action_ingress_cos;
  7: required i32 action_tc;
  8: required i32 action_color;
}

struct dc_acl_mirror_action_spec_t {
  1: required i32 action_session_id;
  2: required i16 action_acl_stats_index;
  3: required i32 action_acl_meter_index;
  4: required byte action_nat_mode;
  5: required i32 action_ingress_cos;
  6: required i32 action_tc;
  7: required i32 action_color;
}

struct dc_racl_deny_action_spec_t {
  1: required i16 action_acl_stats_index;
  2: required i32 action_acl_copy_reason;
  3: required i32 action_ingress_cos;
  4: required i32 action_tc;
  5: required i32 action_color;
}

struct dc_racl_permit_action_spec_t {
  1: required i16 action_acl_stats_index;
  2: required i32 action_acl_copy_reason;
  3: required i32 action_ingress_cos;
  4: required i32 action_tc;
  5: required i32 action_color;
}

struct dc_racl_redirect_nexthop_action_spec_t {
  1: required i16 action_nexthop_index;
  2: required i16 action_acl_stats_index;
  3: required i32 action_acl_copy_reason;
  4: required i32 action_ingress_cos;
  5: required i32 action_tc;
  6: required i32 action_color;
}

struct dc_racl_redirect_ecmp_action_spec_t {
  1: required i16 action_ecmp_index;
  2: required i16 action_acl_stats_index;
  3: required i32 action_acl_copy_reason;
  4: required i32 action_ingress_cos;
  5: required i32 action_tc;
  6: required i32 action_color;
}

struct dc_drop_packet_with_reason_action_spec_t {
  1: required i32 action_drop_reason;
}

struct dc_redirect_to_cpu_action_spec_t {
  1: required byte action_qid;
  2: required i32 action_meter_id;
  3: required byte action_icos;
}

struct dc_redirect_to_cpu_with_reason_action_spec_t {
  1: required i16 action_reason_code;
  2: required byte action_qid;
  3: required i32 action_meter_id;
  4: required byte action_icos;
}

struct dc_copy_to_cpu_action_spec_t {
  1: required byte action_qid;
  2: required i32 action_meter_id;
  3: required byte action_icos;
}

struct dc_copy_to_cpu_with_reason_action_spec_t {
  1: required i16 action_reason_code;
  2: required byte action_qid;
  3: required i32 action_meter_id;
  4: required byte action_icos;
}

struct dc_egress_copy_to_cpu_with_reason_action_spec_t {
  1: required i16 action_reason_code;
}

struct dc_egress_redirect_to_cpu_with_reason_action_spec_t {
  1: required i16 action_reason_code;
}

struct dc_egress_mirror_coal_hdr_action_spec_t {
  1: required i32 action_session_id;
  2: required i32 action_id;
}

struct dc_egress_mirror_action_spec_t {
  1: required i32 action_session_id;
}

struct dc_egress_mirror_and_drop_action_spec_t {
  1: required i32 action_reason_code;
}

struct dc_multicast_bridge_star_g_hit_action_spec_t {
  1: required i16 action_mc_index;
  2: required byte action_copy_to_cpu;
}

struct dc_multicast_bridge_s_g_hit_action_spec_t {
  1: required i16 action_mc_index;
  2: required byte action_copy_to_cpu;
}

struct dc_multicast_route_sm_star_g_hit_action_spec_t {
  1: required i16 action_mc_index;
  2: required i16 action_mcast_rpf_group;
  3: required byte action_copy_to_cpu;
}

struct dc_multicast_route_bidir_star_g_hit_action_spec_t {
  1: required i16 action_mc_index;
  2: required i16 action_mcast_rpf_group;
  3: required byte action_copy_to_cpu;
}

struct dc_multicast_route_s_g_hit_action_spec_t {
  1: required i16 action_mc_index;
  2: required i16 action_mcast_rpf_group;
  3: required byte action_copy_to_cpu;
}

struct dc_set_bd_flood_mc_index_action_spec_t {
  1: required i16 action_mc_index;
}

struct dc_outer_replica_from_rid_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_dmac_idx;
  3: required i16 action_tunnel_index;
  4: required byte action_tunnel_type;
  5: required byte action_header_count;
}

struct dc_encap_replica_from_rid_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_dmac_idx;
  3: required i16 action_tunnel_index;
  4: required byte action_tunnel_type;
  5: required byte action_header_count;
  6: required i16 action_outer_bd;
}

struct dc_inner_replica_from_rid_action_spec_t {
  1: required i16 action_bd;
}

struct dc_unicast_replica_from_rid_action_spec_t {
  1: required i16 action_outer_bd;
  2: required i16 action_dmac_idx;
}

struct dc_set_egress_ifindex_from_rid_action_spec_t {
  1: required i16 action_egress_ifindex;
}

struct dc_set_cpu_redirect_action_spec_t {
  1: required i16 action_cpu_ifindex;
}

struct dc_set_ecmp_nexthop_details_action_spec_t {
  1: required i16 action_ifindex;
  2: required i16 action_port_lag_index;
  3: required i16 action_bd;
  4: required i16 action_nhop_index;
  5: required byte action_tunnel;
}

struct dc_set_ecmp_nexthop_details_with_tunnel_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_tunnel_dst_index;
  3: required byte action_tunnel;
}

struct dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_uuc_mc_index;
  3: required i16 action_nhop_index;
}

struct dc_set_nexthop_details_action_spec_t {
  1: required i16 action_ifindex;
  2: required i16 action_port_lag_index;
  3: required i16 action_bd;
  4: required byte action_tunnel;
}

struct dc_set_nexthop_details_with_tunnel_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_tunnel_dst_index;
  3: required byte action_tunnel;
}

struct dc_set_nexthop_details_for_post_routed_flood_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_uuc_mc_index;
}

struct dc_set_nexthop_details_for_glean_action_spec_t {
  1: required i16 action_ifindex;
}

struct dc_set_l2_rewrite_with_tunnel_action_spec_t {
  1: required i16 action_tunnel_index;
  2: required byte action_tunnel_type;
}

struct dc_set_l3_rewrite_with_tunnel_action_spec_t {
  1: required i16 action_bd;
  2: required MacAddr_t action_dmac;
  3: required i16 action_tunnel_index;
  4: required byte action_tunnel_type;
}

struct dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t {
  1: required MacAddr_t action_dmac;
  2: required i16 action_tunnel_index;
  3: required byte action_tunnel_type;
  4: required i32 action_vnid;
}

struct dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t {
  1: required MacAddr_t action_dmac;
  2: required i16 action_tunnel_index;
  3: required byte action_tunnel_type;
}

struct dc_set_l3_rewrite_action_spec_t {
  1: required i16 action_bd;
  2: required MacAddr_t action_dmac;
}

struct dc_set_mpls_push_rewrite_l2_action_spec_t {
  1: required i16 action_tunnel_index;
  2: required byte action_header_count;
  3: required i16 action_dmac_idx;
}

struct dc_set_mpls_swap_push_rewrite_l3_action_spec_t {
  1: required i16 action_bd;
  2: required MacAddr_t action_dmac;
  3: required i32 action_label;
  4: required i16 action_tunnel_index;
  5: required byte action_header_count;
  6: required i16 action_dmac_idx;
}

struct dc_set_mpls_push_rewrite_l3_action_spec_t {
  1: required i16 action_bd;
  2: required MacAddr_t action_dmac;
  3: required i16 action_tunnel_index;
  4: required byte action_header_count;
  5: required i16 action_dmac_idx;
}

struct dc_set_storm_control_meter_action_spec_t {
  1: required i32 action_meter_idx;
}

struct dc_set_mirror_bd_action_spec_t {
  1: required i16 action_bd;
  2: required i16 action_session_id;
}

struct dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t {
  1: required MacAddr_t action_smac;
  2: required MacAddr_t action_dmac;
  3: required i32 action_sip;
  4: required i32 action_dip;
  5: required byte action_tos;
  6: required byte action_ttl;
}

struct dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t {
  1: required MacAddr_t action_smac;
  2: required MacAddr_t action_dmac;
  3: required i32 action_sip;
  4: required i32 action_dip;
  5: required byte action_tos;
  6: required byte action_ttl;
  7: required i16 action_vlan_tpid;
  8: required i16 action_vlan_id;
  9: required byte action_cos;
}

union dc_action_specs_t {
  1: dc_set_config_parameters_action_spec_t dc_set_config_parameters;
  2: dc_malformed_outer_ethernet_packet_action_spec_t dc_malformed_outer_ethernet_packet;
  3: dc_set_port_lag_index_action_spec_t dc_set_port_lag_index;
  4: dc_set_ingress_port_properties_action_spec_t dc_set_ingress_port_properties;
  5: dc_set_bd_properties_action_spec_t dc_set_bd_properties;
  6: dc_set_ingress_interface_properties_action_spec_t dc_set_ingress_interface_properties;
  7: dc_set_lag_port_action_spec_t dc_set_lag_port;
  8: dc_egress_port_type_normal_action_spec_t dc_egress_port_type_normal;
  9: dc_set_egress_if_params_tagged_action_spec_t dc_set_egress_if_params_tagged;
  10: dc_set_stp_state_action_spec_t dc_set_stp_state;
  11: dc_smac_hit_action_spec_t dc_smac_hit;
  12: dc_dmac_hit_action_spec_t dc_dmac_hit;
  13: dc_dmac_multicast_hit_action_spec_t dc_dmac_multicast_hit;
  14: dc_dmac_redirect_nexthop_action_spec_t dc_dmac_redirect_nexthop;
  15: dc_dmac_redirect_ecmp_action_spec_t dc_dmac_redirect_ecmp;
  16: dc_set_malformed_packet_action_spec_t dc_set_malformed_packet;
  17: dc_set_egress_bd_properties_action_spec_t dc_set_egress_bd_properties;
  18: dc_set_egress_outer_bd_properties_action_spec_t dc_set_egress_outer_bd_properties;
  19: dc_rewrite_smac_action_spec_t dc_rewrite_smac;
  20: dc_ipv4_mtu_check_action_spec_t dc_ipv4_mtu_check;
  21: dc_ipv6_mtu_check_action_spec_t dc_ipv6_mtu_check;
  22: dc_set_malformed_outer_ipv4_packet_action_spec_t dc_set_malformed_outer_ipv4_packet;
  23: dc_fib_hit_nexthop_action_spec_t dc_fib_hit_nexthop;
  24: dc_fib_hit_myip_action_spec_t dc_fib_hit_myip;
  25: dc_fib_hit_ecmp_action_spec_t dc_fib_hit_ecmp;
  26: dc_ipv4_urpf_hit_action_spec_t dc_ipv4_urpf_hit;
  27: dc_set_malformed_outer_ipv6_packet_action_spec_t dc_set_malformed_outer_ipv6_packet;
  28: dc_ipv6_urpf_hit_action_spec_t dc_ipv6_urpf_hit;
  29: dc_set_tunnel_lookup_flag_action_spec_t dc_set_tunnel_lookup_flag;
  30: dc_set_tunnel_vni_and_lookup_flag_action_spec_t dc_set_tunnel_vni_and_lookup_flag;
  31: dc_src_vtep_hit_action_spec_t dc_src_vtep_hit;
  32: dc_terminate_tunnel_inner_non_ip_action_spec_t dc_terminate_tunnel_inner_non_ip;
  33: dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t dc_terminate_tunnel_inner_ethernet_ipv4;
  34: dc_terminate_tunnel_inner_ipv4_action_spec_t dc_terminate_tunnel_inner_ipv4;
  35: dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t dc_terminate_tunnel_inner_ethernet_ipv6;
  36: dc_terminate_tunnel_inner_ipv6_action_spec_t dc_terminate_tunnel_inner_ipv6;
  37: dc_terminate_eompls_action_spec_t dc_terminate_eompls;
  38: dc_terminate_vpls_action_spec_t dc_terminate_vpls;
  39: dc_terminate_ipv4_over_mpls_action_spec_t dc_terminate_ipv4_over_mpls;
  40: dc_terminate_ipv6_over_mpls_action_spec_t dc_terminate_ipv6_over_mpls;
  41: dc_terminate_pw_action_spec_t dc_terminate_pw;
  42: dc_forward_mpls_action_spec_t dc_forward_mpls;
  43: dc_set_egress_tunnel_vni_action_spec_t dc_set_egress_tunnel_vni;
  44: dc_set_ipv4_tunnel_rewrite_details_action_spec_t dc_set_ipv4_tunnel_rewrite_details;
  45: dc_set_ipv6_tunnel_rewrite_details_action_spec_t dc_set_ipv6_tunnel_rewrite_details;
  46: dc_set_mpls_rewrite_push1_action_spec_t dc_set_mpls_rewrite_push1;
  47: dc_set_mpls_rewrite_push2_action_spec_t dc_set_mpls_rewrite_push2;
  48: dc_set_mpls_rewrite_push3_action_spec_t dc_set_mpls_rewrite_push3;
  49: dc_rewrite_tunnel_ipv4_dst_action_spec_t dc_rewrite_tunnel_ipv4_dst;
  50: dc_rewrite_tunnel_ipv6_dst_action_spec_t dc_rewrite_tunnel_ipv6_dst;
  51: dc_rewrite_tunnel_smac_action_spec_t dc_rewrite_tunnel_smac;
  52: dc_rewrite_tunnel_dmac_action_spec_t dc_rewrite_tunnel_dmac;
  53: dc_set_tunnel_mgid_action_spec_t dc_set_tunnel_mgid;
  54: dc_set_ingress_src_port_range_id_action_spec_t dc_set_ingress_src_port_range_id;
  55: dc_set_ingress_dst_port_range_id_action_spec_t dc_set_ingress_dst_port_range_id;
  56: dc_acl_deny_action_spec_t dc_acl_deny;
  57: dc_acl_permit_action_spec_t dc_acl_permit;
  58: dc_acl_redirect_nexthop_action_spec_t dc_acl_redirect_nexthop;
  59: dc_acl_redirect_ecmp_action_spec_t dc_acl_redirect_ecmp;
  60: dc_acl_mirror_action_spec_t dc_acl_mirror;
  61: dc_racl_deny_action_spec_t dc_racl_deny;
  62: dc_racl_permit_action_spec_t dc_racl_permit;
  63: dc_racl_redirect_nexthop_action_spec_t dc_racl_redirect_nexthop;
  64: dc_racl_redirect_ecmp_action_spec_t dc_racl_redirect_ecmp;
  65: dc_drop_packet_with_reason_action_spec_t dc_drop_packet_with_reason;
  66: dc_redirect_to_cpu_action_spec_t dc_redirect_to_cpu;
  67: dc_redirect_to_cpu_with_reason_action_spec_t dc_redirect_to_cpu_with_reason;
  68: dc_copy_to_cpu_action_spec_t dc_copy_to_cpu;
  69: dc_copy_to_cpu_with_reason_action_spec_t dc_copy_to_cpu_with_reason;
  70: dc_egress_copy_to_cpu_with_reason_action_spec_t dc_egress_copy_to_cpu_with_reason;
  71: dc_egress_redirect_to_cpu_with_reason_action_spec_t dc_egress_redirect_to_cpu_with_reason;
  72: dc_egress_mirror_coal_hdr_action_spec_t dc_egress_mirror_coal_hdr;
  73: dc_egress_mirror_action_spec_t dc_egress_mirror;
  74: dc_egress_mirror_and_drop_action_spec_t dc_egress_mirror_and_drop;
  75: dc_multicast_bridge_star_g_hit_action_spec_t dc_multicast_bridge_star_g_hit;
  76: dc_multicast_bridge_s_g_hit_action_spec_t dc_multicast_bridge_s_g_hit;
  77: dc_multicast_route_sm_star_g_hit_action_spec_t dc_multicast_route_sm_star_g_hit;
  78: dc_multicast_route_bidir_star_g_hit_action_spec_t dc_multicast_route_bidir_star_g_hit;
  79: dc_multicast_route_s_g_hit_action_spec_t dc_multicast_route_s_g_hit;
  80: dc_set_bd_flood_mc_index_action_spec_t dc_set_bd_flood_mc_index;
  81: dc_outer_replica_from_rid_action_spec_t dc_outer_replica_from_rid;
  82: dc_encap_replica_from_rid_action_spec_t dc_encap_replica_from_rid;
  83: dc_inner_replica_from_rid_action_spec_t dc_inner_replica_from_rid;
  84: dc_unicast_replica_from_rid_action_spec_t dc_unicast_replica_from_rid;
  85: dc_set_egress_ifindex_from_rid_action_spec_t dc_set_egress_ifindex_from_rid;
  86: dc_set_cpu_redirect_action_spec_t dc_set_cpu_redirect;
  87: dc_set_ecmp_nexthop_details_action_spec_t dc_set_ecmp_nexthop_details;
  88: dc_set_ecmp_nexthop_details_with_tunnel_action_spec_t dc_set_ecmp_nexthop_details_with_tunnel;
  89: dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec_t dc_set_ecmp_nexthop_details_for_post_routed_flood;
  90: dc_set_nexthop_details_action_spec_t dc_set_nexthop_details;
  91: dc_set_nexthop_details_with_tunnel_action_spec_t dc_set_nexthop_details_with_tunnel;
  92: dc_set_nexthop_details_for_post_routed_flood_action_spec_t dc_set_nexthop_details_for_post_routed_flood;
  93: dc_set_nexthop_details_for_glean_action_spec_t dc_set_nexthop_details_for_glean;
  94: dc_set_l2_rewrite_with_tunnel_action_spec_t dc_set_l2_rewrite_with_tunnel;
  95: dc_set_l3_rewrite_with_tunnel_action_spec_t dc_set_l3_rewrite_with_tunnel;
  96: dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t dc_set_l3_rewrite_with_tunnel_vnid;
  97: dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t dc_set_l3_rewrite_with_tunnel_and_ingress_vrf;
  98: dc_set_l3_rewrite_action_spec_t dc_set_l3_rewrite;
  99: dc_set_mpls_push_rewrite_l2_action_spec_t dc_set_mpls_push_rewrite_l2;
  100: dc_set_mpls_swap_push_rewrite_l3_action_spec_t dc_set_mpls_swap_push_rewrite_l3;
  101: dc_set_mpls_push_rewrite_l3_action_spec_t dc_set_mpls_push_rewrite_l3;
  102: dc_set_storm_control_meter_action_spec_t dc_set_storm_control_meter;
  103: dc_set_mirror_bd_action_spec_t dc_set_mirror_bd;
  104: dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t dc_ipv4_erspan_t3_rewrite_with_eth_hdr;
  105: dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag;
}

struct dc_action_desc_t {
  1: required string name;
  2: required dc_action_specs_t data;
}


# Register values


# Entry Descriptions

struct dc_switch_config_params_entry_desc_t {
  1: required dc_action_desc_t action_desc;
}

struct dc_validate_outer_ethernet_entry_desc_t {
  1: required dc_validate_outer_ethernet_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ingress_port_mapping_entry_desc_t {
  1: required dc_ingress_port_mapping_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ingress_port_properties_entry_desc_t {
  1: required dc_ingress_port_properties_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_port_vlan_to_bd_mapping_entry_desc_t {
  1: required dc_port_vlan_to_bd_mapping_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required list<MemberHandle_t> members;
}

struct dc_port_vlan_to_ifindex_mapping_entry_desc_t {
  1: required dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_cpu_packet_transform_entry_desc_t {
  1: required dc_cpu_packet_transform_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required list<MemberHandle_t> members;
}

struct dc_ingress_bd_stats_entry_desc_t {
  1: required dc_action_desc_t action_desc;
}

struct dc_lag_group_entry_desc_t {
  1: required dc_lag_group_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required list<MemberHandle_t> members;
}

struct dc_egress_port_mapping_entry_desc_t {
  1: required dc_egress_port_mapping_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_egress_vlan_xlate_entry_desc_t {
  1: required dc_egress_vlan_xlate_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_capture_tstamp_entry_desc_t {
  1: required dc_action_desc_t action_desc;
}

struct dc_spanning_tree_entry_desc_t {
  1: required dc_spanning_tree_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_smac_entry_desc_t {
  1: required dc_smac_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_dmac_entry_desc_t {
  1: required dc_dmac_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_learn_notify_entry_desc_t {
  1: required dc_learn_notify_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_validate_packet_entry_desc_t {
  1: required dc_validate_packet_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_egress_bd_stats_entry_desc_t {
  1: required dc_egress_bd_stats_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_egress_bd_map_entry_desc_t {
  1: required dc_egress_bd_map_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_egress_outer_bd_map_entry_desc_t {
  1: required dc_egress_outer_bd_map_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_vlan_decap_entry_desc_t {
  1: required dc_vlan_decap_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_rmac_entry_desc_t {
  1: required dc_rmac_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_urpf_bd_entry_desc_t {
  1: required dc_urpf_bd_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_smac_rewrite_entry_desc_t {
  1: required dc_smac_rewrite_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_l3_rewrite_entry_desc_t {
  1: required dc_l3_rewrite_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_mtu_entry_desc_t {
  1: required dc_mtu_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_validate_outer_ipv4_packet_entry_desc_t {
  1: required dc_validate_outer_ipv4_packet_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ipv4_fib_entry_desc_t {
  1: required dc_ipv4_fib_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_fib_lpm_entry_desc_t {
  1: required dc_ipv4_fib_lpm_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_urpf_lpm_entry_desc_t {
  1: required dc_ipv4_urpf_lpm_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_urpf_entry_desc_t {
  1: required dc_ipv4_urpf_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_validate_outer_ipv6_packet_entry_desc_t {
  1: required dc_validate_outer_ipv6_packet_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ipv6_fib_lpm_entry_desc_t {
  1: required dc_ipv6_fib_lpm_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_fib_entry_desc_t {
  1: required dc_ipv6_fib_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_urpf_lpm_entry_desc_t {
  1: required dc_ipv6_urpf_lpm_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_urpf_entry_desc_t {
  1: required dc_ipv6_urpf_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_outer_rmac_entry_desc_t {
  1: required dc_outer_rmac_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_dest_vtep_entry_desc_t {
  1: required dc_ipv4_dest_vtep_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_src_vtep_entry_desc_t {
  1: required dc_ipv4_src_vtep_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_dest_vtep_entry_desc_t {
  1: required dc_ipv6_dest_vtep_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_src_vtep_entry_desc_t {
  1: required dc_ipv6_src_vtep_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_entry_desc_t {
  1: required dc_tunnel_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_adjust_lkp_fields_entry_desc_t {
  1: required dc_adjust_lkp_fields_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_lookup_miss_entry_desc_t {
  1: required dc_tunnel_lookup_miss_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_check_entry_desc_t {
  1: required dc_tunnel_check_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_validate_mpls_packet_entry_desc_t {
  1: required dc_validate_mpls_packet_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_decap_process_outer_entry_desc_t {
  1: required dc_tunnel_decap_process_outer_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_decap_process_inner_entry_desc_t {
  1: required dc_tunnel_decap_process_inner_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_egress_vni_entry_desc_t {
  1: required dc_egress_vni_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_encap_process_inner_entry_desc_t {
  1: required dc_tunnel_encap_process_inner_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_encap_process_outer_entry_desc_t {
  1: required dc_tunnel_encap_process_outer_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_rewrite_entry_desc_t {
  1: required dc_tunnel_rewrite_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_dst_rewrite_entry_desc_t {
  1: required dc_tunnel_dst_rewrite_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_smac_rewrite_entry_desc_t {
  1: required dc_tunnel_smac_rewrite_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_dmac_rewrite_entry_desc_t {
  1: required dc_tunnel_dmac_rewrite_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_tunnel_to_mgid_mapping_entry_desc_t {
  1: required dc_tunnel_to_mgid_mapping_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ingress_l4_src_port_entry_desc_t {
  1: required dc_ingress_l4_src_port_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ingress_l4_dst_port_entry_desc_t {
  1: required dc_ingress_l4_dst_port_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_mac_acl_entry_desc_t {
  1: required dc_mac_acl_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ip_acl_entry_desc_t {
  1: required dc_ip_acl_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ipv6_acl_entry_desc_t {
  1: required dc_ipv6_acl_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ipv4_racl_entry_desc_t {
  1: required dc_ipv4_racl_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ipv6_racl_entry_desc_t {
  1: required dc_ipv6_racl_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_acl_stats_entry_desc_t {
  1: required dc_action_desc_t action_desc;
}

struct dc_racl_stats_entry_desc_t {
  1: required dc_action_desc_t action_desc;
}

struct dc_system_acl_entry_desc_t {
  1: required dc_system_acl_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_drop_stats_entry_desc_t {
  1: required dc_action_desc_t action_desc;
}

struct dc_egress_system_acl_entry_desc_t {
  1: required dc_egress_system_acl_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ipv4_multicast_bridge_star_g_entry_desc_t {
  1: required dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_multicast_bridge_entry_desc_t {
  1: required dc_ipv4_multicast_bridge_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_multicast_route_star_g_entry_desc_t {
  1: required dc_ipv4_multicast_route_star_g_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv4_multicast_route_entry_desc_t {
  1: required dc_ipv4_multicast_route_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_multicast_bridge_star_g_entry_desc_t {
  1: required dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_multicast_bridge_entry_desc_t {
  1: required dc_ipv6_multicast_bridge_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_multicast_route_star_g_entry_desc_t {
  1: required dc_ipv6_multicast_route_star_g_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_ipv6_multicast_route_entry_desc_t {
  1: required dc_ipv6_multicast_route_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_bd_flood_entry_desc_t {
  1: required dc_bd_flood_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_rid_entry_desc_t {
  1: required dc_rid_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_mcast_egress_ifindex_entry_desc_t {
  1: required dc_mcast_egress_ifindex_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_replica_type_entry_desc_t {
  1: required dc_replica_type_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_fwd_result_entry_desc_t {
  1: required dc_fwd_result_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_ecmp_group_entry_desc_t {
  1: required dc_ecmp_group_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required list<MemberHandle_t> members;
}

struct dc_nexthop_entry_desc_t {
  1: required dc_nexthop_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_rewrite_entry_desc_t {
  1: required dc_rewrite_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_storm_control_stats_entry_desc_t {
  1: required dc_storm_control_stats_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_storm_control_entry_desc_t {
  1: required dc_storm_control_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required i32 priority;
  7: required dc_action_desc_t action_desc;
}

struct dc_fabric_ingress_dst_lkp_entry_desc_t {
  1: required dc_fabric_ingress_dst_lkp_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_mirror_entry_desc_t {
  1: required dc_mirror_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_compute_ipv4_hashes_entry_desc_t {
  1: required dc_compute_ipv4_hashes_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_compute_ipv6_hashes_entry_desc_t {
  1: required dc_compute_ipv6_hashes_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_compute_non_ip_hashes_entry_desc_t {
  1: required dc_compute_non_ip_hashes_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}

struct dc_compute_other_hashes_entry_desc_t {
  1: required dc_compute_other_hashes_match_spec_t match_spec;
  2: required bool has_mbr_hdl;
  3: required bool has_grp_hdl;
  4: required MemberHandle_t selector_grp_hdl;
  5: required MemberHandle_t action_mbr_hdl;
  6: required dc_action_desc_t action_desc;
}


struct dc_mac_learn_digest_digest_entry_t {
  1: required i16 ingress_metadata_ifindex;
  2: required list<byte> l2_metadata_lkp_mac_sa;
  3: required i16 ingress_metadata_bd;
}

struct dc_mac_learn_digest_digest_msg_t {
  1: required res.DevTarget_t             dev_tgt;
  2: required list<dc_mac_learn_digest_digest_entry_t> msg;
  3: required i64                     msg_ptr;
}


exception InvalidTableOperation {
 1:i32 code
}

exception InvalidLearnOperation {
 1:i32 code
}

exception InvalidDbgOperation {
 1:i32 code
}

exception InvalidSnapshotOperation {
 1:i32 code
}

exception InvalidCounterOperation {
 1:i32 code
}

exception InvalidRegisterOperation {
 1:i32 code
}

exception InvalidMeterOperation {
 1:i32 code
}

exception InvalidLPFOperation {
 1:i32 code
}

exception InvalidWREDOperation {
 1:i32 code
}


service dc {

    # Idle time config

    void smac_idle_tmo_enable(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_idle_time_params_t params) throws (1:InvalidTableOperation ouch),

    void smac_idle_register_tmo_cb(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:i32 cookie) throws (1:InvalidTableOperation ouch),

    list<dc_idle_tmo_expired_t> smac_idle_tmo_get_expired(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void smac_idle_tmo_disable(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void smac_set_ttl(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:i32 ttl) throws (1:InvalidTableOperation ouch),

    i32 smac_get_ttl(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),

    void smac_update_hit_state(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    dc_idle_time_hit_state smac_get_hit_state(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),



    EntryHandle_t validate_outer_ethernet_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_port_mapping_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_port_properties_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_properties_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_bd_mapping_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_bd_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t cpu_packet_transform_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_cpu_packet_transform_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t lag_group_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_lag_group_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vlan_xlate_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vlan_xlate_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t spanning_tree_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_spanning_tree_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t learn_notify_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_learn_notify_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_stats_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_stats_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t vlan_decap_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_vlan_decap_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t urpf_bd_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_urpf_bd_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_rewrite_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_lpm_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_lpm_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t outer_rmac_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_outer_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_src_vtep_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_src_vtep_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_check_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_check_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_mpls_packet_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_mpls_packet_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vni_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vni_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dst_rewrite_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_smac_rewrite_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_smac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dmac_rewrite_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dmac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_to_mgid_mapping_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_to_mgid_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_src_port_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_src_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_dst_port_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_dst_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_star_g_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_star_g_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t bd_flood_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_bd_flood_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mcast_egress_ifindex_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mcast_egress_ifindex_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t replica_type_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_replica_type_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ecmp_group_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ecmp_group_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_stats_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_stats_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fabric_ingress_dst_lkp_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fabric_ingress_dst_lkp_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv4_hashes_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv4_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv6_hashes_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv6_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_non_ip_hashes_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_non_ip_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_other_hashes_match_spec_to_entry_hdl(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_other_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),


    # Dynamic Key Mask Exm Table.
      # set API

    # Table entry add functions

    EntryHandle_t validate_outer_ethernet_table_add_with_malformed_outer_ethernet_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority, 5:dc_malformed_outer_ethernet_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_port_mapping_table_add_with_set_port_lag_index(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_mapping_match_spec_t match_spec, 4:dc_set_port_lag_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_port_properties_table_add_with_set_ingress_port_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_properties_match_spec_t match_spec, 4:dc_set_ingress_port_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_table_add_with_set_ingress_interface_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec, 4:dc_set_ingress_interface_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_table_add_with___meta_init_miss_action_port_vlan_to_ifindex_mapping__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_table_add_with_egress_port_type_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_table_add_with___meta_init_miss_action_egress_port_mapping__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_table_add_with_egress_port_type_normal(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec, 4:dc_egress_port_type_normal_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vlan_xlate_table_add_with_set_egress_if_params_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vlan_xlate_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vlan_xlate_table_add_with_set_egress_if_params_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vlan_xlate_match_spec_t match_spec, 4:dc_set_egress_if_params_tagged_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t spanning_tree_table_add_with_set_stp_state(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_spanning_tree_match_spec_t match_spec, 4:dc_set_stp_state_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec, 4:i32 ttl) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_table_add_with_smac_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec, 4:i32 ttl) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_table_add_with_smac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec, 4:dc_smac_hit_action_spec_t action_spec, 5:i32 ttl) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_add_with_dmac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_add_with_dmac_multicast_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_multicast_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_add_with_dmac_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_add_with_dmac_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_add_with_dmac_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_add_with_dmac_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t learn_notify_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_learn_notify_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t learn_notify_table_add_with_generate_learn_notify(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_learn_notify_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_add_with_set_unicast(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_add_with_set_unicast_and_ipv6_src_is_link_local(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_add_with_set_multicast(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_add_with_set_multicast_and_ipv6_src_is_link_local(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_add_with_set_broadcast(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_add_with_set_malformed_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority, 5:dc_set_malformed_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_stats_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_stats_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_table_add_with_set_egress_bd_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec, 4:dc_set_egress_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_table_add_with___meta_init_miss_action_egress_bd_map__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_table_add_with_set_egress_outer_bd_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec, 4:dc_set_egress_outer_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_table_add_with___meta_init_miss_action_egress_outer_bd_map__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t vlan_decap_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_vlan_decap_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t vlan_decap_table_add_with_remove_vlan_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_vlan_decap_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_table_add_with_rmac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_table_add_with___meta_init_miss_action_rmac__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_table_add_with_rmac_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t urpf_bd_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_urpf_bd_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t urpf_bd_table_add_with_urpf_bd_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_urpf_bd_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_rewrite_table_add_with_rewrite_smac(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_rewrite_match_spec_t match_spec, 4:dc_rewrite_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_table_add_with_ipv4_unicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_table_add_with_ipv4_multicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_table_add_with_ipv6_unicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_table_add_with_ipv6_multicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_table_add_with_mpls_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_table_add_with_mtu_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_table_add_with_ipv4_mtu_check(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec, 4:dc_ipv4_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_table_add_with_ipv6_mtu_check(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec, 4:dc_ipv6_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_table_add_with_set_malformed_outer_ipv4_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority, 5:dc_set_malformed_outer_ipv4_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_llmc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_mc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_table_add_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_table_add_with_fib_hit_myip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec, 4:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_table_add_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_table_add_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_table_add_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_lpm_table_add_with_ipv4_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_lpm_match_spec_t match_spec, 4:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_lpm_table_add_with_urpf_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_table_add_with_ipv4_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_match_spec_t match_spec, 4:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_table_add_with_set_malformed_outer_ipv6_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority, 5:dc_set_malformed_outer_ipv6_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_llmc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_mc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_table_add_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_table_add_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_table_add_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_table_add_with_fib_hit_myip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec, 4:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_table_add_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_lpm_table_add_with_ipv6_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_lpm_match_spec_t match_spec, 4:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_lpm_table_add_with_urpf_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_table_add_with_ipv6_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_match_spec_t match_spec, 4:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t outer_rmac_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_outer_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t outer_rmac_table_add_with_outer_rmac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_outer_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_table_add_with_set_tunnel_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_table_add_with_set_tunnel_vni_and_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_src_vtep_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_src_vtep_table_add_with_src_vtep_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_src_vtep_match_spec_t match_spec, 4:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_table_add_with_set_tunnel_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_table_add_with_set_tunnel_vni_and_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_src_vtep_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_src_vtep_table_add_with_src_vtep_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_src_vtep_match_spec_t match_spec, 4:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_tunnel_lookup_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_tunnel_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_non_ip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_tunnel_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_tunnel_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_eompls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_eompls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_vpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_vpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_ipv4_over_mpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_ipv4_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_ipv6_over_mpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_ipv6_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_terminate_pw(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_pw_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_add_with_forward_mpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_forward_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_table_add_with_non_ip_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_table_add_with_ipv4_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_table_add_with_ipv6_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_table_add_with_non_ip_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_table_add_with_ipv4_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_table_add_with_ipv6_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_check_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_check_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_check_table_add_with_tunnel_check_pass(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_check_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_mpls_packet_table_add_with_set_valid_mpls_label(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_mpls_packet_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_genv_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_gre_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_gre_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_ip_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_gre_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_ip_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_table_add_with_decap_inner_udp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_table_add_with_decap_inner_tcp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_table_add_with_decap_inner_icmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_table_add_with_decap_inner_unknown(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vni_table_add_with_set_egress_tunnel_vni(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vni_match_spec_t match_spec, 4:dc_set_egress_tunnel_vni_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv4_udp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv4_tcp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv4_icmp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv4_unknown_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv6_udp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv6_tcp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv6_icmp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_ipv6_unknown_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_add_with_inner_non_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv4_nvgre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv4_gre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv4_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv6_gre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv6_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv6_nvgre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_mpls_ethernet_push1_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_mpls_ip_push1_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_mpls_ethernet_push2_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_mpls_ip_push2_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_mpls_ethernet_push3_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_mpls_ip_push3_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv4_vxlan_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv4_genv_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv6_vxlan_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_add_with_ipv6_genv_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_table_add_with_set_ipv4_tunnel_rewrite_details(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_ipv4_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_table_add_with_set_ipv6_tunnel_rewrite_details(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_ipv6_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_table_add_with_set_mpls_rewrite_push1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_mpls_rewrite_push1_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_table_add_with_set_mpls_rewrite_push2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_mpls_rewrite_push2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_table_add_with_set_mpls_rewrite_push3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_mpls_rewrite_push3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dst_rewrite_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_ipv4_dst_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv6_dst(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_ipv6_dst_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_smac_rewrite_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_smac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_smac_rewrite_table_add_with_rewrite_tunnel_smac(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_smac_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dmac_rewrite_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dmac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dmac_rewrite_table_add_with_rewrite_tunnel_dmac(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dmac_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_dmac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_to_mgid_mapping_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_to_mgid_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_to_mgid_mapping_table_add_with_set_tunnel_mgid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_to_mgid_mapping_match_spec_t match_spec, 4:dc_set_tunnel_mgid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_src_port_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_src_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_src_port_table_add_with_set_ingress_src_port_range_id(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_src_port_match_spec_t match_spec, 4:i32 priority, 5:dc_set_ingress_src_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_dst_port_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_dst_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_dst_port_table_add_with_set_ingress_dst_port_range_id(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_dst_port_match_spec_t match_spec, 4:i32 priority, 5:dc_set_ingress_dst_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_table_add_with_acl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_table_add_with_acl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_table_add_with_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_table_add_with_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_table_add_with_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_table_add_with_acl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_table_add_with_acl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_table_add_with_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_table_add_with_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_table_add_with_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_table_add_with_acl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_table_add_with_acl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_table_add_with_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_table_add_with_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_table_add_with_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_table_add_with_racl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_table_add_with_racl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_table_add_with_racl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_table_add_with_racl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_table_add_with_racl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_table_add_with_racl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_table_add_with_racl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_table_add_with_racl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_add_with_drop_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_add_with_drop_packet_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_drop_packet_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_add_with_redirect_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_redirect_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_add_with_redirect_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_add_with_copy_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_copy_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_add_with_copy_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_drop_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_copy_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_redirect_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_copy_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_redirect_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_mirror_coal_hdr(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_mirror_coal_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_insert_cpu_timestamp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_add_with_egress_mirror_and_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_mirror_and_drop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_star_g_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec, 4:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_table_add_with_multicast_bridge_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_match_spec_t match_spec, 4:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_table_add_with_multicast_route_star_g_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_table_add_with_multicast_route_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_match_spec_t match_spec, 4:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_star_g_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec, 4:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_table_add_with_multicast_bridge_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_match_spec_t match_spec, 4:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_table_add_with_multicast_route_star_g_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_table_add_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_table_add_with_multicast_route_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_match_spec_t match_spec, 4:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t bd_flood_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_bd_flood_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t bd_flood_table_add_with_set_bd_flood_mc_index(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_bd_flood_match_spec_t match_spec, 4:dc_set_bd_flood_mc_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_table_add_with_outer_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_outer_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_table_add_with_encap_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_encap_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_table_add_with_inner_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_inner_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_table_add_with_unicast_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_unicast_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mcast_egress_ifindex_table_add_with_set_egress_ifindex_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mcast_egress_ifindex_match_spec_t match_spec, 4:dc_set_egress_ifindex_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t replica_type_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_replica_type_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t replica_type_table_add_with_set_replica_copy_bridged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_replica_type_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_l2_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_fib_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_cpu_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority, 5:dc_set_cpu_redirect_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_acl_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_racl_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_rmac_non_ip_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_multicast_route(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_multicast_rpf_fail_bridge(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_multicast_rpf_fail_flood_to_mrouters(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_multicast_bridge(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_multicast_miss_flood(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_multicast_miss_flood_to_mrouters(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_add_with_set_multicast_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_table_add_with_set_nexthop_details(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_table_add_with_set_nexthop_details_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_table_add_with_set_nexthop_details_for_post_routed_flood(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_for_post_routed_flood_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_table_add_with_set_nexthop_details_for_glean(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_for_glean_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_table_add_with_set_nexthop_details_for_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_l2_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_l2_rewrite_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l2_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_l3_rewrite_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_l3_rewrite_with_tunnel_vnid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_l3_rewrite_with_tunnel_and_ingress_vrf(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_l3_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_mpls_push_rewrite_l2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_mpls_push_rewrite_l2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_mpls_swap_push_rewrite_l3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_mpls_swap_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_add_with_set_mpls_push_rewrite_l3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_mpls_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_stats_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_stats_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_stats_table_add_with___meta_init_miss_action_storm_control_stats__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_stats_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_table_add_with_set_storm_control_meter(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_match_spec_t match_spec, 4:i32 priority, 5:dc_set_storm_control_meter_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fabric_ingress_dst_lkp_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fabric_ingress_dst_lkp_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fabric_ingress_dst_lkp_table_add_with_terminate_cpu_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fabric_ingress_dst_lkp_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_table_add_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_table_add_with_set_mirror_bd(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec, 4:dc_set_mirror_bd_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_table_add_with_ipv4_erspan_t3_rewrite_with_eth_hdr(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec, 4:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_table_add_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec, 4:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv4_hashes_table_add_with_compute_lkp_ipv4_hash(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv4_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv4_hashes_table_add_with___meta_init_miss_action_compute_ipv4_hashes__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv4_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv6_hashes_table_add_with_compute_lkp_ipv6_hash(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv6_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv6_hashes_table_add_with___meta_init_miss_action_compute_ipv6_hashes__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv6_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_non_ip_hashes_table_add_with_compute_lkp_non_ip_hash(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_non_ip_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_non_ip_hashes_table_add_with___meta_init_miss_action_compute_non_ip_hashes__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_non_ip_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_other_hashes_table_add_with_compute_other_hashes(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_other_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),

    # Table entry modify functions
    void validate_outer_ethernet_table_modify_with_malformed_outer_ethernet_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_malformed_outer_ethernet_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_malformed_outer_ethernet_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority, 5:dc_malformed_outer_ethernet_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_untagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_untagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_untagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_single_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_unicast_packet_qinq_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_single_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_multicast_packet_qinq_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_single_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_modify_with_set_valid_outer_broadcast_packet_qinq_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ingress_port_mapping_table_modify_with_set_port_lag_index(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_port_lag_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ingress_port_mapping_table_modify_with_set_port_lag_index_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_mapping_match_spec_t match_spec, 4:dc_set_port_lag_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ingress_port_properties_table_modify_with_set_ingress_port_properties(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_ingress_port_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ingress_port_properties_table_modify_with_set_ingress_port_properties_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_properties_match_spec_t match_spec, 4:dc_set_ingress_port_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_ifindex_mapping_table_modify_with_set_ingress_interface_properties(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_ingress_interface_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_ifindex_mapping_table_modify_with_set_ingress_interface_properties_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec, 4:dc_set_ingress_interface_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_ifindex_mapping_table_modify_with___meta_init_miss_action_port_vlan_to_ifindex_mapping__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_ifindex_mapping_table_modify_with___meta_init_miss_action_port_vlan_to_ifindex_mapping___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_ifindex_mapping_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_ifindex_mapping_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_port_mapping_table_modify_with_egress_port_type_cpu(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_port_mapping_table_modify_with_egress_port_type_cpu_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_port_mapping_table_modify_with___meta_init_miss_action_egress_port_mapping__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_port_mapping_table_modify_with___meta_init_miss_action_egress_port_mapping___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_port_mapping_table_modify_with_egress_port_type_normal(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_egress_port_type_normal_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_port_mapping_table_modify_with_egress_port_type_normal_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec, 4:dc_egress_port_type_normal_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_vlan_xlate_table_modify_with_set_egress_if_params_untagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_vlan_xlate_table_modify_with_set_egress_if_params_untagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vlan_xlate_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_vlan_xlate_table_modify_with_set_egress_if_params_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_egress_if_params_tagged_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_vlan_xlate_table_modify_with_set_egress_if_params_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vlan_xlate_match_spec_t match_spec, 4:dc_set_egress_if_params_tagged_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void spanning_tree_table_modify_with_set_stp_state(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_stp_state_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void spanning_tree_table_modify_with_set_stp_state_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_spanning_tree_match_spec_t match_spec, 4:dc_set_stp_state_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void smac_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void smac_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void smac_table_modify_with_smac_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void smac_table_modify_with_smac_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void smac_table_modify_with_smac_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_smac_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void smac_table_modify_with_smac_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec, 4:dc_smac_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_dmac_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_multicast_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_dmac_multicast_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_multicast_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_multicast_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_dmac_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_redirect_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_dmac_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_redirect_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec, 4:dc_dmac_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_drop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void dmac_table_modify_with_dmac_drop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void learn_notify_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void learn_notify_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_learn_notify_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void learn_notify_table_modify_with_generate_learn_notify(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void learn_notify_table_modify_with_generate_learn_notify_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_learn_notify_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_unicast(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_unicast_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_unicast_and_ipv6_src_is_link_local(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_unicast_and_ipv6_src_is_link_local_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_multicast(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_multicast_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_multicast_and_ipv6_src_is_link_local(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_multicast_and_ipv6_src_is_link_local_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_broadcast(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_broadcast_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_malformed_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_malformed_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_modify_with_set_malformed_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority, 5:dc_set_malformed_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_bd_stats_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_bd_stats_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_stats_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_bd_map_table_modify_with_set_egress_bd_properties(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_egress_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_bd_map_table_modify_with_set_egress_bd_properties_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec, 4:dc_set_egress_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_bd_map_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_bd_map_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_bd_map_table_modify_with___meta_init_miss_action_egress_bd_map__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_bd_map_table_modify_with___meta_init_miss_action_egress_bd_map___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_outer_bd_map_table_modify_with_set_egress_outer_bd_properties(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_egress_outer_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_outer_bd_map_table_modify_with_set_egress_outer_bd_properties_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec, 4:dc_set_egress_outer_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_outer_bd_map_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_outer_bd_map_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_outer_bd_map_table_modify_with___meta_init_miss_action_egress_outer_bd_map__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_outer_bd_map_table_modify_with___meta_init_miss_action_egress_outer_bd_map___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void vlan_decap_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void vlan_decap_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_vlan_decap_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void vlan_decap_table_modify_with_remove_vlan_single_tagged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void vlan_decap_table_modify_with_remove_vlan_single_tagged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_vlan_decap_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void rmac_table_modify_with_rmac_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rmac_table_modify_with_rmac_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void rmac_table_modify_with___meta_init_miss_action_rmac__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rmac_table_modify_with___meta_init_miss_action_rmac___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void rmac_table_modify_with_rmac_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rmac_table_modify_with_rmac_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void urpf_bd_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void urpf_bd_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_urpf_bd_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void urpf_bd_table_modify_with_urpf_bd_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void urpf_bd_table_modify_with_urpf_bd_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_urpf_bd_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void smac_rewrite_table_modify_with_rewrite_smac(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_rewrite_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void smac_rewrite_table_modify_with_rewrite_smac_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_rewrite_match_spec_t match_spec, 4:dc_rewrite_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv4_unicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv4_unicast_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv4_multicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv4_multicast_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv6_unicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv6_unicast_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv6_multicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_ipv6_multicast_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_mpls_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_modify_with_mpls_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void mtu_table_modify_with_mtu_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void mtu_table_modify_with_mtu_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void mtu_table_modify_with_ipv4_mtu_check(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv4_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mtu_table_modify_with_ipv4_mtu_check_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec, 4:dc_ipv4_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mtu_table_modify_with_ipv6_mtu_check(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv6_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mtu_table_modify_with_ipv6_mtu_check_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec, 4:dc_ipv6_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_malformed_outer_ipv4_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_malformed_outer_ipv4_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_malformed_outer_ipv4_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority, 5:dc_set_malformed_outer_ipv4_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_llmc_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_llmc_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_mc_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_modify_with_set_valid_outer_ipv4_mc_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_fib_hit_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_fib_hit_myip(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_fib_hit_myip_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec, 4:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_modify_with_fib_hit_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_lpm_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_lpm_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_lpm_table_modify_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_lpm_table_modify_with_fib_hit_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_lpm_table_modify_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_lpm_table_modify_with_fib_hit_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_lpm_table_modify_with_ipv4_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_lpm_table_modify_with_ipv4_urpf_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_lpm_match_spec_t match_spec, 4:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_lpm_table_modify_with_urpf_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_lpm_table_modify_with_urpf_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_table_modify_with_ipv4_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_table_modify_with_ipv4_urpf_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_match_spec_t match_spec, 4:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_malformed_outer_ipv6_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_malformed_outer_ipv6_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_malformed_outer_ipv6_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority, 5:dc_set_malformed_outer_ipv6_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_llmc_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_llmc_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_mc_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_modify_with_set_valid_outer_ipv6_mc_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_lpm_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_lpm_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_lpm_table_modify_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_lpm_table_modify_with_fib_hit_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_lpm_table_modify_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_lpm_table_modify_with_fib_hit_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_fib_hit_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec, 4:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_fib_hit_myip(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_fib_hit_myip_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec, 4:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_modify_with_fib_hit_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec, 4:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_lpm_table_modify_with_ipv6_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_lpm_table_modify_with_ipv6_urpf_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_lpm_match_spec_t match_spec, 4:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_lpm_table_modify_with_urpf_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_lpm_table_modify_with_urpf_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_table_modify_with_ipv6_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_table_modify_with_ipv6_urpf_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_match_spec_t match_spec, 4:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void outer_rmac_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void outer_rmac_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_outer_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void outer_rmac_table_modify_with_outer_rmac_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void outer_rmac_table_modify_with_outer_rmac_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_outer_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_dest_vtep_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_dest_vtep_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_dest_vtep_table_modify_with_set_tunnel_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_dest_vtep_table_modify_with_set_tunnel_lookup_flag_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_src_vtep_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_src_vtep_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_src_vtep_table_modify_with_src_vtep_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_src_vtep_table_modify_with_src_vtep_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_src_vtep_match_spec_t match_spec, 4:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_dest_vtep_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_dest_vtep_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_dest_vtep_table_modify_with_set_tunnel_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_dest_vtep_table_modify_with_set_tunnel_lookup_flag_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_dest_vtep_table_modify_with_set_tunnel_vni_and_lookup_flag_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec, 4:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_src_vtep_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_src_vtep_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_src_vtep_table_modify_with_src_vtep_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_src_vtep_table_modify_with_src_vtep_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_src_vtep_match_spec_t match_spec, 4:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_tunnel_lookup_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_tunnel_lookup_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_tunnel_inner_non_ip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_non_ip_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_non_ip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv4(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv4_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_tunnel_inner_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ipv4_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv6(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ethernet_ipv6_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_tunnel_inner_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_tunnel_inner_ipv6_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_tunnel_inner_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_eompls(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_eompls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_eompls_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_eompls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_vpls(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_vpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_vpls_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_vpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_ipv4_over_mpls(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_ipv4_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_ipv4_over_mpls_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_ipv4_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_ipv6_over_mpls(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_ipv6_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_ipv6_over_mpls_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_ipv6_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_pw(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_terminate_pw_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_terminate_pw_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_terminate_pw_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_forward_mpls(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_forward_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_table_modify_with_forward_mpls_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec, 4:dc_forward_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void adjust_lkp_fields_table_modify_with_non_ip_lkp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void adjust_lkp_fields_table_modify_with_non_ip_lkp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void adjust_lkp_fields_table_modify_with_ipv4_lkp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void adjust_lkp_fields_table_modify_with_ipv4_lkp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void adjust_lkp_fields_table_modify_with_ipv6_lkp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void adjust_lkp_fields_table_modify_with_ipv6_lkp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_lookup_miss_table_modify_with_non_ip_lkp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_lookup_miss_table_modify_with_non_ip_lkp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_lookup_miss_table_modify_with_ipv4_lkp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_lookup_miss_table_modify_with_ipv4_lkp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_lookup_miss_table_modify_with_ipv6_lkp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_lookup_miss_table_modify_with_ipv6_lkp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_check_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_check_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_check_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void tunnel_check_table_modify_with_tunnel_check_pass(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_check_table_modify_with_tunnel_check_pass_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_check_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void validate_mpls_packet_table_modify_with_set_valid_mpls_label(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_mpls_packet_table_modify_with_set_valid_mpls_label_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_mpls_packet_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv4_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_non_ip_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv4_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_genv_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_genv_inner_non_ip_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv4_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_gre_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_gre_inner_non_ip_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv4_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_vxlan_inner_ipv6_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_genv_inner_ipv6_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_gre_inner_ipv6_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_ip_inner_ipv6_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv4_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_non_ip_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_nvgre_inner_ipv6_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop1(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop1_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop1(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop1_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop1(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop1_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop2(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop2_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop2(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop2_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop2(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop2_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv4_pop3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv4_pop3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_non_ip_pop3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop1(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop1_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop1(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop1_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop2(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop2_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop2(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop2_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ipv6_pop3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_modify_with_decap_mpls_inner_ethernet_ipv6_pop3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_udp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_udp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_tcp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_tcp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_icmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_icmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_unknown(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_modify_with_decap_inner_unknown_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void egress_vni_table_modify_with_set_egress_tunnel_vni(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_egress_tunnel_vni_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_vni_table_modify_with_set_egress_tunnel_vni_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vni_match_spec_t match_spec, 4:dc_set_egress_tunnel_vni_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_udp_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_udp_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_tcp_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_tcp_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_icmp_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_icmp_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_unknown_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv4_unknown_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_udp_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_udp_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_tcp_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_tcp_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_icmp_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_icmp_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_unknown_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_ipv6_unknown_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_non_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_modify_with_inner_non_ip_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_nvgre_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_nvgre_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_gre_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_gre_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_ip_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_gre_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_gre_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_ip_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_nvgre_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_nvgre_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push1_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push1_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ip_push1_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ip_push1_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push2_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push2_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ip_push2_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ip_push2_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push3_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ethernet_push3_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ip_push3_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_mpls_ip_push3_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_vxlan_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_vxlan_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_genv_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv4_genv_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_vxlan_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_vxlan_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_genv_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_modify_with_ipv6_genv_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_ipv4_tunnel_rewrite_details(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_ipv4_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_ipv4_tunnel_rewrite_details_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_ipv4_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_ipv6_tunnel_rewrite_details(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_ipv6_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_ipv6_tunnel_rewrite_details_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_ipv6_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_mpls_rewrite_push1(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_mpls_rewrite_push1_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_mpls_rewrite_push1_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_mpls_rewrite_push1_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_mpls_rewrite_push2(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_mpls_rewrite_push2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_mpls_rewrite_push2_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_mpls_rewrite_push2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_mpls_rewrite_push3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_mpls_rewrite_push3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_modify_with_set_mpls_rewrite_push3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec, 4:dc_set_mpls_rewrite_push3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dst_rewrite_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_dst_rewrite_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv4_dst(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_rewrite_tunnel_ipv4_dst_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv4_dst_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_ipv4_dst_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv6_dst(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_rewrite_tunnel_ipv6_dst_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dst_rewrite_table_modify_with_rewrite_tunnel_ipv6_dst_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_ipv6_dst_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_smac_rewrite_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_smac_rewrite_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_smac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_smac_rewrite_table_modify_with_rewrite_tunnel_smac(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_rewrite_tunnel_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_smac_rewrite_table_modify_with_rewrite_tunnel_smac_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_smac_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dmac_rewrite_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_dmac_rewrite_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dmac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dmac_rewrite_table_modify_with_rewrite_tunnel_dmac(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_rewrite_tunnel_dmac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_dmac_rewrite_table_modify_with_rewrite_tunnel_dmac_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dmac_rewrite_match_spec_t match_spec, 4:dc_rewrite_tunnel_dmac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_to_mgid_mapping_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_to_mgid_mapping_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_to_mgid_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_to_mgid_mapping_table_modify_with_set_tunnel_mgid(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_tunnel_mgid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void tunnel_to_mgid_mapping_table_modify_with_set_tunnel_mgid_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_to_mgid_mapping_match_spec_t match_spec, 4:dc_set_tunnel_mgid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ingress_l4_src_port_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ingress_l4_src_port_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_src_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ingress_l4_src_port_table_modify_with_set_ingress_src_port_range_id(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_ingress_src_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ingress_l4_src_port_table_modify_with_set_ingress_src_port_range_id_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_src_port_match_spec_t match_spec, 4:i32 priority, 5:dc_set_ingress_src_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ingress_l4_dst_port_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ingress_l4_dst_port_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_dst_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ingress_l4_dst_port_table_modify_with_set_ingress_dst_port_range_id(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_ingress_dst_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ingress_l4_dst_port_table_modify_with_set_ingress_dst_port_range_id_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_dst_port_match_spec_t match_spec, 4:i32 priority, 5:dc_set_ingress_dst_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_deny(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_deny_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_permit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_permit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_redirect_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_redirect_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_modify_with_acl_mirror_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_deny(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_deny_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_permit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_permit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_redirect_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_redirect_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_modify_with_acl_mirror_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_deny(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_deny_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_permit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_permit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_redirect_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_redirect_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_modify_with_acl_mirror_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_deny(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_deny_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_permit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_permit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_redirect_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_modify_with_racl_redirect_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_deny(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_deny_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_permit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_permit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_redirect_nexthop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_modify_with_racl_redirect_ecmp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority, 5:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_drop_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_drop_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_drop_packet_with_reason(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_drop_packet_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_drop_packet_with_reason_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_drop_packet_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_redirect_to_cpu(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_redirect_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_redirect_to_cpu_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_redirect_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_redirect_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_redirect_to_cpu_with_reason_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_copy_to_cpu(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_copy_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_copy_to_cpu_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_copy_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_copy_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void system_acl_table_modify_with_copy_to_cpu_with_reason_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_drop_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_drop_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_copy_to_cpu(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_copy_to_cpu_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_redirect_to_cpu(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_redirect_to_cpu_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_copy_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_egress_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_copy_to_cpu_with_reason_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_redirect_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_egress_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_redirect_to_cpu_with_reason_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_mirror_coal_hdr(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_egress_mirror_coal_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_mirror_coal_hdr_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_mirror_coal_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_insert_cpu_timestamp(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_insert_cpu_timestamp_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_mirror(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_egress_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_mirror_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_mirror_and_drop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_egress_mirror_and_drop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_modify_with_egress_mirror_and_drop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority, 5:dc_egress_mirror_and_drop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_star_g_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_star_g_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec, 4:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_match_spec_t match_spec, 4:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_table_modify_with_multicast_route_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_table_modify_with_multicast_route_s_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_match_spec_t match_spec, 4:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_star_g_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_star_g_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_star_g_table_modify_with_multicast_bridge_star_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec, 4:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_table_modify_with_multicast_bridge_s_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_match_spec_t match_spec, 4:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_star_g_table_modify_with_multicast_route_star_g_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_star_g_table_modify_with_multicast_route_sm_star_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_star_g_table_modify_with_multicast_route_bidir_star_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec, 4:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_table_modify_with_on_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_table_modify_with_on_miss_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_table_modify_with_multicast_route_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_table_modify_with_multicast_route_s_g_hit_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_match_spec_t match_spec, 4:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void bd_flood_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void bd_flood_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_bd_flood_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void bd_flood_table_modify_with_set_bd_flood_mc_index(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_bd_flood_mc_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void bd_flood_table_modify_with_set_bd_flood_mc_index_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_bd_flood_match_spec_t match_spec, 4:dc_set_bd_flood_mc_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_outer_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_outer_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_outer_replica_from_rid_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_outer_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_encap_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_encap_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_encap_replica_from_rid_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_encap_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_inner_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_inner_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_inner_replica_from_rid_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_inner_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_unicast_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_unicast_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rid_table_modify_with_unicast_replica_from_rid_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec, 4:dc_unicast_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mcast_egress_ifindex_table_modify_with_set_egress_ifindex_from_rid(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_egress_ifindex_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mcast_egress_ifindex_table_modify_with_set_egress_ifindex_from_rid_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mcast_egress_ifindex_match_spec_t match_spec, 4:dc_set_egress_ifindex_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void replica_type_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void replica_type_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_replica_type_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void replica_type_table_modify_with_set_replica_copy_bridged(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void replica_type_table_modify_with_set_replica_copy_bridged_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_replica_type_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_l2_redirect(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_l2_redirect_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_fib_redirect(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_fib_redirect_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_cpu_redirect(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_cpu_redirect_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_cpu_redirect_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority, 5:dc_set_cpu_redirect_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_acl_redirect(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_acl_redirect_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_racl_redirect(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_racl_redirect_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_rmac_non_ip_drop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_rmac_non_ip_drop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_route(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_route_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_rpf_fail_bridge(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_rpf_fail_bridge_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_rpf_fail_flood_to_mrouters(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_rpf_fail_flood_to_mrouters_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_bridge(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_bridge_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_miss_flood(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_miss_flood_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_miss_flood_to_mrouters(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_miss_flood_to_mrouters_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_drop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_modify_with_set_multicast_drop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_nexthop_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_nexthop_details_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_with_tunnel_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_for_post_routed_flood(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_nexthop_details_for_post_routed_flood_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_for_post_routed_flood_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_for_post_routed_flood_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_for_glean(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_nexthop_details_for_glean_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_for_glean_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec, 4:dc_set_nexthop_details_for_glean_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_for_drop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void nexthop_table_modify_with_set_nexthop_details_for_drop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l2_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l2_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l2_rewrite_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_l2_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l2_rewrite_with_tunnel_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l2_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_l3_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite_with_tunnel_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite_with_tunnel_vnid(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite_with_tunnel_vnid_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite_with_tunnel_and_ingress_vrf(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite_with_tunnel_and_ingress_vrf_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_l3_rewrite_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_l3_rewrite_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_l3_rewrite_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_mpls_push_rewrite_l2(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_mpls_push_rewrite_l2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_mpls_push_rewrite_l2_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_mpls_push_rewrite_l2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_mpls_swap_push_rewrite_l3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_mpls_swap_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_mpls_swap_push_rewrite_l3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_mpls_swap_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_mpls_push_rewrite_l3(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_mpls_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void rewrite_table_modify_with_set_mpls_push_rewrite_l3_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec, 4:dc_set_mpls_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void storm_control_stats_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void storm_control_stats_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_stats_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void storm_control_stats_table_modify_with___meta_init_miss_action_storm_control_stats__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void storm_control_stats_table_modify_with___meta_init_miss_action_storm_control_stats___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_stats_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void storm_control_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void storm_control_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
    void storm_control_table_modify_with_set_storm_control_meter(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_storm_control_meter_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void storm_control_table_modify_with_set_storm_control_meter_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_match_spec_t match_spec, 4:i32 priority, 5:dc_set_storm_control_meter_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void fabric_ingress_dst_lkp_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fabric_ingress_dst_lkp_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fabric_ingress_dst_lkp_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void fabric_ingress_dst_lkp_table_modify_with_terminate_cpu_packet(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fabric_ingress_dst_lkp_table_modify_with_terminate_cpu_packet_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fabric_ingress_dst_lkp_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_nop_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_set_mirror_bd(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_set_mirror_bd_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_set_mirror_bd_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec, 4:dc_set_mirror_bd_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec, 4:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void mirror_table_modify_with_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec, 4:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void compute_ipv4_hashes_table_modify_with_compute_lkp_ipv4_hash(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_ipv4_hashes_table_modify_with_compute_lkp_ipv4_hash_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv4_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void compute_ipv4_hashes_table_modify_with___meta_init_miss_action_compute_ipv4_hashes__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_ipv4_hashes_table_modify_with___meta_init_miss_action_compute_ipv4_hashes___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv4_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void compute_ipv6_hashes_table_modify_with_compute_lkp_ipv6_hash(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_ipv6_hashes_table_modify_with_compute_lkp_ipv6_hash_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv6_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void compute_ipv6_hashes_table_modify_with___meta_init_miss_action_compute_ipv6_hashes__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_ipv6_hashes_table_modify_with___meta_init_miss_action_compute_ipv6_hashes___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv6_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void compute_non_ip_hashes_table_modify_with_compute_lkp_non_ip_hash(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_non_ip_hashes_table_modify_with_compute_lkp_non_ip_hash_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_non_ip_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void compute_non_ip_hashes_table_modify_with___meta_init_miss_action_compute_non_ip_hashes__(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_non_ip_hashes_table_modify_with___meta_init_miss_action_compute_non_ip_hashes___by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_non_ip_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
    void compute_other_hashes_table_modify_with_compute_other_hashes(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_other_hashes_table_modify_with_compute_other_hashes_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_other_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),

    # Table entry delete functions
# //::   if action_table_hdl: continue
# //::   if action_table_hdl: continue
    void validate_outer_ethernet_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ethernet_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ethernet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_port_mapping_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ingress_port_mapping_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_port_properties_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ingress_port_properties_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_port_properties_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void port_vlan_to_bd_mapping_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_bd_mapping_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_bd_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void port_vlan_to_ifindex_mapping_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_ifindex_mapping_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_ifindex_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void cpu_packet_transform_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void cpu_packet_transform_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_cpu_packet_transform_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
# //::   if action_table_hdl: continue
    void lag_group_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void lag_group_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_lag_group_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_port_mapping_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_port_mapping_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_vlan_xlate_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_vlan_xlate_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vlan_xlate_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
# //::   if action_table_hdl: continue
    void spanning_tree_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void spanning_tree_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_spanning_tree_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void smac_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void smac_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void dmac_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void dmac_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void learn_notify_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void learn_notify_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_learn_notify_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_packet_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_packet_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_bd_stats_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_bd_stats_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_stats_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_bd_map_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_bd_map_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_outer_bd_map_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_outer_bd_map_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_outer_bd_map_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void vlan_decap_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void vlan_decap_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_vlan_decap_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rmac_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rmac_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void urpf_bd_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void urpf_bd_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_urpf_bd_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void smac_rewrite_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void smac_rewrite_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void l3_rewrite_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void l3_rewrite_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_l3_rewrite_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mtu_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void mtu_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mtu_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ipv4_packet_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv4_packet_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv4_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_fib_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_fib_lpm_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_fib_lpm_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_urpf_lpm_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_lpm_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_urpf_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_urpf_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ipv6_packet_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_outer_ipv6_packet_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_outer_ipv6_packet_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_fib_lpm_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_lpm_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_fib_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_fib_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_fib_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_urpf_lpm_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_lpm_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_lpm_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_urpf_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_urpf_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void outer_rmac_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void outer_rmac_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_outer_rmac_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_dest_vtep_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_dest_vtep_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_src_vtep_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_src_vtep_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_dest_vtep_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_dest_vtep_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_dest_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_src_vtep_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_src_vtep_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_src_vtep_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void adjust_lkp_fields_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void adjust_lkp_fields_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_adjust_lkp_fields_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_lookup_miss_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_lookup_miss_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_lookup_miss_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_check_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_check_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_check_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_mpls_packet_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void validate_mpls_packet_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_validate_mpls_packet_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_decap_process_outer_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_outer_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_decap_process_inner_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_decap_process_inner_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_decap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_vni_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_vni_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_vni_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_encap_process_inner_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_inner_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_inner_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_encap_process_outer_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_encap_process_outer_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_encap_process_outer_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_rewrite_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_rewrite_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_dst_rewrite_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_dst_rewrite_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dst_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_smac_rewrite_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_smac_rewrite_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_smac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_dmac_rewrite_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_dmac_rewrite_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_dmac_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_to_mgid_mapping_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void tunnel_to_mgid_mapping_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_tunnel_to_mgid_mapping_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_l4_src_port_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ingress_l4_src_port_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_src_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_l4_dst_port_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ingress_l4_dst_port_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ingress_l4_dst_port_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mac_acl_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void mac_acl_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mac_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ip_acl_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ip_acl_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ip_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_acl_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_acl_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_racl_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_racl_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_racl_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_racl_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_racl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
# //::   if action_table_hdl: continue
# //::   if action_table_hdl: continue
    void system_acl_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void system_acl_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
# //::   if action_table_hdl: continue
    void egress_system_acl_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void egress_system_acl_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_system_acl_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_bridge_star_g_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_star_g_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_bridge_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_bridge_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_route_star_g_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_star_g_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_route_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv4_multicast_route_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_bridge_star_g_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_star_g_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_bridge_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_bridge_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_bridge_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_route_star_g_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_star_g_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_star_g_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_route_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ipv6_multicast_route_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_multicast_route_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void bd_flood_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void bd_flood_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_bd_flood_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rid_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rid_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rid_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mcast_egress_ifindex_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void mcast_egress_ifindex_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mcast_egress_ifindex_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void replica_type_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void replica_type_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_replica_type_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void fwd_result_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fwd_result_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fwd_result_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ecmp_group_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void ecmp_group_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ecmp_group_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void nexthop_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void nexthop_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_nexthop_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rewrite_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void rewrite_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void storm_control_stats_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void storm_control_stats_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_stats_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void storm_control_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void storm_control_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_storm_control_match_spec_t match_spec, 4:i32 priority) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void fabric_ingress_dst_lkp_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void fabric_ingress_dst_lkp_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fabric_ingress_dst_lkp_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mirror_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void mirror_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_mirror_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_ipv4_hashes_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_ipv4_hashes_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv4_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_ipv6_hashes_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_ipv6_hashes_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_ipv6_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_non_ip_hashes_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_non_ip_hashes_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_non_ip_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_other_hashes_table_delete(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry) throws (1:InvalidTableOperation ouch),
    void compute_other_hashes_table_delete_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_compute_other_hashes_match_spec_t match_spec) throws (1:InvalidTableOperation ouch),

    # Table default entry get handle functions
    EntryHandle_t switch_config_params_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_port_mapping_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_port_properties_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_bd_mapping_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t cpu_packet_transform_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_bd_stats_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t lag_group_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vlan_xlate_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t capture_tstamp_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t spanning_tree_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t learn_notify_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_stats_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t vlan_decap_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t urpf_bd_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_rewrite_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_lpm_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_lpm_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t outer_rmac_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_src_vtep_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_src_vtep_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_check_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_mpls_packet_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vni_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dst_rewrite_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_smac_rewrite_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dmac_rewrite_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_to_mgid_mapping_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_src_port_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_dst_port_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t acl_stats_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t racl_stats_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t drop_stats_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_star_g_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_star_g_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t bd_flood_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mcast_egress_ifindex_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t replica_type_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ecmp_group_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_stats_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fabric_ingress_dst_lkp_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv4_hashes_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv6_hashes_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_non_ip_hashes_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_other_hashes_table_get_default_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    # Table default entry clear functions
# //::   if action_table_hdl: continue
    void switch_config_params_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ethernet_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_port_mapping_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_port_properties_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void port_vlan_to_bd_mapping_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void port_vlan_to_ifindex_mapping_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void cpu_packet_transform_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_bd_stats_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void lag_group_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_port_mapping_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_vlan_xlate_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void capture_tstamp_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void spanning_tree_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void smac_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void dmac_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void learn_notify_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_packet_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_bd_stats_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_bd_map_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_outer_bd_map_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void vlan_decap_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rmac_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void urpf_bd_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void smac_rewrite_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void l3_rewrite_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mtu_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ipv4_packet_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_fib_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_fib_lpm_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_urpf_lpm_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_urpf_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ipv6_packet_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_fib_lpm_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_fib_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_urpf_lpm_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_urpf_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void outer_rmac_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_dest_vtep_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_src_vtep_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_dest_vtep_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_src_vtep_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void adjust_lkp_fields_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_lookup_miss_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_check_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_mpls_packet_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_decap_process_outer_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_decap_process_inner_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_vni_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_encap_process_inner_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_encap_process_outer_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_rewrite_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_dst_rewrite_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_smac_rewrite_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_dmac_rewrite_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_to_mgid_mapping_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_l4_src_port_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_l4_dst_port_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mac_acl_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ip_acl_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_acl_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_racl_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_racl_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void acl_stats_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void racl_stats_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void system_acl_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void drop_stats_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_system_acl_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_bridge_star_g_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_bridge_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_route_star_g_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_route_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_bridge_star_g_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_bridge_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_route_star_g_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_route_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void bd_flood_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rid_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mcast_egress_ifindex_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void replica_type_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void fwd_result_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ecmp_group_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void nexthop_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rewrite_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void storm_control_stats_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void storm_control_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void fabric_ingress_dst_lkp_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mirror_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_ipv4_hashes_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_ipv6_hashes_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_non_ip_hashes_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_other_hashes_table_reset_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    i32 switch_config_params_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 validate_outer_ethernet_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ingress_port_mapping_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ingress_port_properties_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 port_vlan_to_bd_mapping_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 port_vlan_to_ifindex_mapping_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 cpu_packet_transform_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ingress_bd_stats_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 lag_group_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 egress_port_mapping_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 egress_vlan_xlate_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 capture_tstamp_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 spanning_tree_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 smac_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 dmac_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 learn_notify_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 validate_packet_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 egress_bd_stats_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 egress_bd_map_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 egress_outer_bd_map_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 vlan_decap_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 rmac_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 urpf_bd_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 smac_rewrite_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 l3_rewrite_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 mtu_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 validate_outer_ipv4_packet_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_fib_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_fib_lpm_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_urpf_lpm_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_urpf_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 validate_outer_ipv6_packet_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_fib_lpm_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_fib_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_urpf_lpm_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_urpf_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 outer_rmac_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_dest_vtep_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_src_vtep_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_dest_vtep_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_src_vtep_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 adjust_lkp_fields_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_lookup_miss_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_check_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 validate_mpls_packet_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_decap_process_outer_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_decap_process_inner_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 egress_vni_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_encap_process_inner_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_encap_process_outer_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_rewrite_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_dst_rewrite_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_smac_rewrite_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_dmac_rewrite_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 tunnel_to_mgid_mapping_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ingress_l4_src_port_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ingress_l4_dst_port_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 mac_acl_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ip_acl_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_acl_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_racl_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_racl_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 acl_stats_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 racl_stats_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 system_acl_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 drop_stats_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 egress_system_acl_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_multicast_bridge_star_g_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_multicast_bridge_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_multicast_route_star_g_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv4_multicast_route_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_multicast_bridge_star_g_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_multicast_bridge_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_multicast_route_star_g_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ipv6_multicast_route_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 bd_flood_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 rid_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 mcast_egress_ifindex_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 replica_type_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 fwd_result_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ecmp_group_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 nexthop_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 rewrite_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 storm_control_stats_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 storm_control_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 fabric_ingress_dst_lkp_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 mirror_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 compute_ipv4_hashes_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 compute_ipv6_hashes_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 compute_non_ip_hashes_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 compute_other_hashes_get_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    i32 bd_action_profile_get_act_prof_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 lag_action_profile_get_act_prof_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 lag_action_profile_get_selector_group_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ecmp_action_profile_get_act_prof_entry_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    i32 ecmp_action_profile_get_selector_group_count(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    # Get first entry handle functions
    i32 switch_config_params_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> switch_config_params_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_switch_config_params_entry_desc_t switch_config_params_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 validate_outer_ethernet_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> validate_outer_ethernet_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_validate_outer_ethernet_entry_desc_t validate_outer_ethernet_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ingress_port_mapping_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ingress_port_mapping_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ingress_port_mapping_entry_desc_t ingress_port_mapping_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ingress_port_properties_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ingress_port_properties_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ingress_port_properties_entry_desc_t ingress_port_properties_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 port_vlan_to_bd_mapping_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> port_vlan_to_bd_mapping_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_port_vlan_to_bd_mapping_entry_desc_t port_vlan_to_bd_mapping_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 port_vlan_to_ifindex_mapping_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> port_vlan_to_ifindex_mapping_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_port_vlan_to_ifindex_mapping_entry_desc_t port_vlan_to_ifindex_mapping_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 cpu_packet_transform_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> cpu_packet_transform_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_cpu_packet_transform_entry_desc_t cpu_packet_transform_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ingress_bd_stats_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ingress_bd_stats_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ingress_bd_stats_entry_desc_t ingress_bd_stats_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 lag_group_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> lag_group_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_lag_group_entry_desc_t lag_group_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 egress_port_mapping_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> egress_port_mapping_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_egress_port_mapping_entry_desc_t egress_port_mapping_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 egress_vlan_xlate_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> egress_vlan_xlate_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_egress_vlan_xlate_entry_desc_t egress_vlan_xlate_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 capture_tstamp_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> capture_tstamp_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_capture_tstamp_entry_desc_t capture_tstamp_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 spanning_tree_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> spanning_tree_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_spanning_tree_entry_desc_t spanning_tree_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 smac_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> smac_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_smac_entry_desc_t smac_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 dmac_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> dmac_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_dmac_entry_desc_t dmac_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 learn_notify_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> learn_notify_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_learn_notify_entry_desc_t learn_notify_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 validate_packet_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> validate_packet_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_validate_packet_entry_desc_t validate_packet_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 egress_bd_stats_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> egress_bd_stats_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_egress_bd_stats_entry_desc_t egress_bd_stats_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 egress_bd_map_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> egress_bd_map_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_egress_bd_map_entry_desc_t egress_bd_map_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 egress_outer_bd_map_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> egress_outer_bd_map_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_egress_outer_bd_map_entry_desc_t egress_outer_bd_map_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 vlan_decap_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> vlan_decap_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_vlan_decap_entry_desc_t vlan_decap_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 rmac_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> rmac_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_rmac_entry_desc_t rmac_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 urpf_bd_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> urpf_bd_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_urpf_bd_entry_desc_t urpf_bd_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 smac_rewrite_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> smac_rewrite_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_smac_rewrite_entry_desc_t smac_rewrite_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 l3_rewrite_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> l3_rewrite_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_l3_rewrite_entry_desc_t l3_rewrite_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 mtu_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> mtu_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_mtu_entry_desc_t mtu_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 validate_outer_ipv4_packet_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> validate_outer_ipv4_packet_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_validate_outer_ipv4_packet_entry_desc_t validate_outer_ipv4_packet_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_fib_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_fib_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_fib_entry_desc_t ipv4_fib_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_fib_lpm_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_fib_lpm_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_fib_lpm_entry_desc_t ipv4_fib_lpm_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_urpf_lpm_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_urpf_lpm_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_urpf_lpm_entry_desc_t ipv4_urpf_lpm_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_urpf_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_urpf_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_urpf_entry_desc_t ipv4_urpf_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 validate_outer_ipv6_packet_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> validate_outer_ipv6_packet_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_validate_outer_ipv6_packet_entry_desc_t validate_outer_ipv6_packet_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_fib_lpm_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_fib_lpm_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_fib_lpm_entry_desc_t ipv6_fib_lpm_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_fib_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_fib_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_fib_entry_desc_t ipv6_fib_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_urpf_lpm_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_urpf_lpm_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_urpf_lpm_entry_desc_t ipv6_urpf_lpm_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_urpf_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_urpf_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_urpf_entry_desc_t ipv6_urpf_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 outer_rmac_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> outer_rmac_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_outer_rmac_entry_desc_t outer_rmac_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_dest_vtep_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_dest_vtep_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_dest_vtep_entry_desc_t ipv4_dest_vtep_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_src_vtep_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_src_vtep_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_src_vtep_entry_desc_t ipv4_src_vtep_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_dest_vtep_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_dest_vtep_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_dest_vtep_entry_desc_t ipv6_dest_vtep_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_src_vtep_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_src_vtep_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_src_vtep_entry_desc_t ipv6_src_vtep_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_entry_desc_t tunnel_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 adjust_lkp_fields_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> adjust_lkp_fields_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_adjust_lkp_fields_entry_desc_t adjust_lkp_fields_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_lookup_miss_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_lookup_miss_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_lookup_miss_entry_desc_t tunnel_lookup_miss_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_check_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_check_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_check_entry_desc_t tunnel_check_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 validate_mpls_packet_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> validate_mpls_packet_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_validate_mpls_packet_entry_desc_t validate_mpls_packet_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_decap_process_outer_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_decap_process_outer_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_decap_process_outer_entry_desc_t tunnel_decap_process_outer_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_decap_process_inner_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_decap_process_inner_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_decap_process_inner_entry_desc_t tunnel_decap_process_inner_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 egress_vni_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> egress_vni_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_egress_vni_entry_desc_t egress_vni_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_encap_process_inner_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_encap_process_inner_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_encap_process_inner_entry_desc_t tunnel_encap_process_inner_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_encap_process_outer_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_encap_process_outer_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_encap_process_outer_entry_desc_t tunnel_encap_process_outer_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_rewrite_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_rewrite_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_rewrite_entry_desc_t tunnel_rewrite_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_dst_rewrite_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_dst_rewrite_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_dst_rewrite_entry_desc_t tunnel_dst_rewrite_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_smac_rewrite_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_smac_rewrite_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_smac_rewrite_entry_desc_t tunnel_smac_rewrite_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_dmac_rewrite_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_dmac_rewrite_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_dmac_rewrite_entry_desc_t tunnel_dmac_rewrite_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 tunnel_to_mgid_mapping_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> tunnel_to_mgid_mapping_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_tunnel_to_mgid_mapping_entry_desc_t tunnel_to_mgid_mapping_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ingress_l4_src_port_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ingress_l4_src_port_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ingress_l4_src_port_entry_desc_t ingress_l4_src_port_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ingress_l4_dst_port_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ingress_l4_dst_port_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ingress_l4_dst_port_entry_desc_t ingress_l4_dst_port_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 mac_acl_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> mac_acl_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_mac_acl_entry_desc_t mac_acl_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ip_acl_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ip_acl_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ip_acl_entry_desc_t ip_acl_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_acl_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_acl_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_acl_entry_desc_t ipv6_acl_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_racl_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_racl_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_racl_entry_desc_t ipv4_racl_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_racl_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_racl_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_racl_entry_desc_t ipv6_racl_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 acl_stats_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> acl_stats_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_acl_stats_entry_desc_t acl_stats_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 racl_stats_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> racl_stats_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_racl_stats_entry_desc_t racl_stats_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 system_acl_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> system_acl_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_system_acl_entry_desc_t system_acl_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 drop_stats_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> drop_stats_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_drop_stats_entry_desc_t drop_stats_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 egress_system_acl_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> egress_system_acl_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_egress_system_acl_entry_desc_t egress_system_acl_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_multicast_bridge_star_g_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_multicast_bridge_star_g_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_multicast_bridge_star_g_entry_desc_t ipv4_multicast_bridge_star_g_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_multicast_bridge_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_multicast_bridge_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_multicast_bridge_entry_desc_t ipv4_multicast_bridge_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_multicast_route_star_g_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_multicast_route_star_g_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_multicast_route_star_g_entry_desc_t ipv4_multicast_route_star_g_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv4_multicast_route_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv4_multicast_route_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv4_multicast_route_entry_desc_t ipv4_multicast_route_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_multicast_bridge_star_g_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_multicast_bridge_star_g_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_multicast_bridge_star_g_entry_desc_t ipv6_multicast_bridge_star_g_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_multicast_bridge_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_multicast_bridge_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_multicast_bridge_entry_desc_t ipv6_multicast_bridge_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_multicast_route_star_g_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_multicast_route_star_g_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_multicast_route_star_g_entry_desc_t ipv6_multicast_route_star_g_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ipv6_multicast_route_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ipv6_multicast_route_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ipv6_multicast_route_entry_desc_t ipv6_multicast_route_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 bd_flood_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> bd_flood_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_bd_flood_entry_desc_t bd_flood_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 rid_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> rid_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_rid_entry_desc_t rid_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 mcast_egress_ifindex_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> mcast_egress_ifindex_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_mcast_egress_ifindex_entry_desc_t mcast_egress_ifindex_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 replica_type_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> replica_type_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_replica_type_entry_desc_t replica_type_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 fwd_result_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> fwd_result_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_fwd_result_entry_desc_t fwd_result_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 ecmp_group_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> ecmp_group_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_ecmp_group_entry_desc_t ecmp_group_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 nexthop_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> nexthop_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_nexthop_entry_desc_t nexthop_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 rewrite_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> rewrite_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_rewrite_entry_desc_t rewrite_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 storm_control_stats_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> storm_control_stats_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_storm_control_stats_entry_desc_t storm_control_stats_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 storm_control_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> storm_control_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_storm_control_entry_desc_t storm_control_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 fabric_ingress_dst_lkp_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> fabric_ingress_dst_lkp_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_fabric_ingress_dst_lkp_entry_desc_t fabric_ingress_dst_lkp_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 mirror_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> mirror_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_mirror_entry_desc_t mirror_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 compute_ipv4_hashes_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> compute_ipv4_hashes_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_compute_ipv4_hashes_entry_desc_t compute_ipv4_hashes_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 compute_ipv6_hashes_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> compute_ipv6_hashes_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_compute_ipv6_hashes_entry_desc_t compute_ipv6_hashes_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 compute_non_ip_hashes_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> compute_non_ip_hashes_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_compute_non_ip_hashes_entry_desc_t compute_non_ip_hashes_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),

    i32 compute_other_hashes_get_first_entry_handle(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<i32> compute_other_hashes_get_next_entry_handles(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),

    dc_compute_other_hashes_entry_desc_t compute_other_hashes_get_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry_hdl, 4:bool read_from_hw) throws (1:InvalidTableOperation ouch),


    dc_action_desc_t bd_action_profile_get_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr_hdl, 4:bool read_from_hw);
# Get first/next entry handles for action profile and selector tables
    i32 bd_action_profile_get_first_member(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    list<i32> bd_action_profile_get_next_members(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),
    dc_action_desc_t lag_action_profile_get_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr_hdl, 4:bool read_from_hw);
# Get first/next entry handles for action profile and selector tables
    i32 lag_action_profile_get_first_member(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    list<i32> lag_action_profile_get_next_members(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),
    i32 lag_action_profile_get_first_group(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    list<i32> lag_action_profile_get_next_groups(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),
    i32 lag_action_profile_get_first_group_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t grp_hdl) throws (1:InvalidTableOperation ouch),
    list<i32> lag_action_profile_get_next_group_members(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t grp_hdl, 4:EntryHandle_t mbr_hdl, 5:i32 n) throws (1:InvalidTableOperation ouch),
    dc_action_desc_t ecmp_action_profile_get_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr_hdl, 4:bool read_from_hw);
# Get first/next entry handles for action profile and selector tables
    i32 ecmp_action_profile_get_first_member(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    list<i32> ecmp_action_profile_get_next_members(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),
    i32 ecmp_action_profile_get_first_group(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    list<i32> ecmp_action_profile_get_next_groups(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry_hdl, 4:i32 n) throws (1:InvalidTableOperation ouch),
    i32 ecmp_action_profile_get_first_group_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t grp_hdl) throws (1:InvalidTableOperation ouch),
    list<i32> ecmp_action_profile_get_next_group_members(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t grp_hdl, 4:EntryHandle_t mbr_hdl, 5:i32 n) throws (1:InvalidTableOperation ouch),

    # Table set default action functions

    EntryHandle_t switch_config_params_set_default_action_set_config_parameters(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_config_parameters_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_malformed_outer_ethernet_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_malformed_outer_ethernet_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_multicast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ethernet_set_default_action_set_valid_outer_broadcast_packet_qinq_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_port_mapping_set_default_action_set_port_lag_index(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_port_lag_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_set_default_action_set_ingress_interface_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ingress_interface_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_set_default_action___meta_init_miss_action_port_vlan_to_ifindex_mapping__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t port_vlan_to_ifindex_mapping_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_bd_stats_set_default_action_update_ingress_bd_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_set_default_action_egress_port_type_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_set_default_action___meta_init_miss_action_egress_port_mapping__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_port_mapping_set_default_action_egress_port_type_normal(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_port_type_normal_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vlan_xlate_set_default_action_set_egress_if_params_untagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vlan_xlate_set_default_action_set_egress_if_params_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_egress_if_params_tagged_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t capture_tstamp_set_default_action_set_capture_tstamp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t spanning_tree_set_default_action_set_stp_state(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_stp_state_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_set_default_action_smac_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_set_default_action_smac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_smac_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_set_default_action_dmac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_set_default_action_dmac_multicast_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_multicast_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_set_default_action_dmac_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_set_default_action_dmac_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_set_default_action_dmac_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_dmac_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t dmac_set_default_action_dmac_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t learn_notify_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t learn_notify_set_default_action_generate_learn_notify(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_set_default_action_set_unicast(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_set_default_action_set_unicast_and_ipv6_src_is_link_local(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_set_default_action_set_multicast(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_set_default_action_set_multicast_and_ipv6_src_is_link_local(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_set_default_action_set_broadcast(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_packet_set_default_action_set_malformed_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_malformed_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_stats_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_set_default_action_set_egress_bd_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_egress_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_bd_map_set_default_action___meta_init_miss_action_egress_bd_map__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_set_default_action_set_egress_outer_bd_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_egress_outer_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_outer_bd_map_set_default_action___meta_init_miss_action_egress_outer_bd_map__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t vlan_decap_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t vlan_decap_set_default_action_remove_vlan_single_tagged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_set_default_action_rmac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_set_default_action___meta_init_miss_action_rmac__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rmac_set_default_action_rmac_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t urpf_bd_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t urpf_bd_set_default_action_urpf_bd_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t smac_rewrite_set_default_action_rewrite_smac(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_set_default_action_ipv4_unicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_set_default_action_ipv4_multicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_set_default_action_ipv6_unicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_set_default_action_ipv6_multicast_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t l3_rewrite_set_default_action_mpls_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_set_default_action_mtu_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_set_default_action_ipv4_mtu_check(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mtu_set_default_action_ipv6_mtu_check(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_mtu_check_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_set_default_action_set_malformed_outer_ipv4_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_malformed_outer_ipv4_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_llmc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_mc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_set_default_action_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_set_default_action_fib_hit_myip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_set_default_action_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_set_default_action_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_fib_lpm_set_default_action_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_lpm_set_default_action_ipv4_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_lpm_set_default_action_urpf_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_urpf_set_default_action_ipv4_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_set_default_action_set_malformed_outer_ipv6_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_malformed_outer_ipv6_packet_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_llmc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_mc_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_set_default_action_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_lpm_set_default_action_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_set_default_action_fib_hit_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_set_default_action_fib_hit_myip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_myip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_fib_set_default_action_fib_hit_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_fib_hit_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_lpm_set_default_action_ipv6_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_lpm_set_default_action_urpf_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_urpf_set_default_action_ipv6_urpf_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv6_urpf_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t outer_rmac_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t outer_rmac_set_default_action_outer_rmac_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_set_default_action_set_tunnel_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_dest_vtep_set_default_action_set_tunnel_vni_and_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_src_vtep_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_src_vtep_set_default_action_src_vtep_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_set_default_action_set_tunnel_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_tunnel_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_dest_vtep_set_default_action_set_tunnel_vni_and_lookup_flag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_tunnel_vni_and_lookup_flag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_src_vtep_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_src_vtep_set_default_action_src_vtep_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_src_vtep_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_tunnel_lookup_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_tunnel_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_tunnel_inner_non_ip_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_tunnel_inner_ethernet_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_tunnel_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_tunnel_inner_ipv4_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_tunnel_inner_ethernet_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_tunnel_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_tunnel_inner_ipv6_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_eompls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_eompls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_vpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_vpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_ipv4_over_mpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_ipv4_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_ipv6_over_mpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_ipv6_over_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_terminate_pw(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_terminate_pw_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_set_default_action_forward_mpls(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_forward_mpls_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_set_default_action_non_ip_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_set_default_action_ipv4_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t adjust_lkp_fields_set_default_action_ipv6_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_set_default_action_non_ip_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_set_default_action_ipv4_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_lookup_miss_set_default_action_ipv6_lkp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_check_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_check_set_default_action_tunnel_check_pass(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_genv_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_genv_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_gre_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_gre_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_ip_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_vxlan_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_genv_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_gre_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_ip_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_ipv4(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_non_ip(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_nvgre_inner_ipv6(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv4_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv4_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_non_ip_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ipv6_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_outer_set_default_action_decap_mpls_inner_ethernet_ipv6_pop3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_set_default_action_decap_inner_udp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_set_default_action_decap_inner_tcp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_set_default_action_decap_inner_icmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_decap_process_inner_set_default_action_decap_inner_unknown(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_vni_set_default_action_set_egress_tunnel_vni(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_egress_tunnel_vni_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv4_udp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv4_tcp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv4_icmp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv4_unknown_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv6_udp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv6_tcp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv6_icmp_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_ipv6_unknown_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_inner_set_default_action_inner_non_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv4_nvgre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv4_gre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv4_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv6_gre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv6_ip_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv6_nvgre_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_mpls_ethernet_push1_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_mpls_ip_push1_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_mpls_ethernet_push2_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_mpls_ip_push2_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_mpls_ethernet_push3_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_mpls_ip_push3_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv4_vxlan_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv4_genv_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv6_vxlan_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_encap_process_outer_set_default_action_ipv6_genv_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_set_default_action_set_ipv4_tunnel_rewrite_details(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ipv4_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_set_default_action_set_ipv6_tunnel_rewrite_details(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ipv6_tunnel_rewrite_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_set_default_action_set_mpls_rewrite_push1(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_mpls_rewrite_push1_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_set_default_action_set_mpls_rewrite_push2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_mpls_rewrite_push2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_rewrite_set_default_action_set_mpls_rewrite_push3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_mpls_rewrite_push3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dst_rewrite_set_default_action_rewrite_tunnel_ipv4_dst(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_tunnel_ipv4_dst_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_smac_rewrite_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_smac_rewrite_set_default_action_rewrite_tunnel_smac(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_tunnel_smac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dmac_rewrite_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_dmac_rewrite_set_default_action_rewrite_tunnel_dmac(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_rewrite_tunnel_dmac_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_to_mgid_mapping_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t tunnel_to_mgid_mapping_set_default_action_set_tunnel_mgid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_tunnel_mgid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_src_port_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_src_port_set_default_action_set_ingress_src_port_range_id(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ingress_src_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_dst_port_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ingress_l4_dst_port_set_default_action_set_ingress_dst_port_range_id(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ingress_dst_port_range_id_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_set_default_action_acl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_set_default_action_acl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_set_default_action_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_set_default_action_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mac_acl_set_default_action_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_set_default_action_acl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_set_default_action_acl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_set_default_action_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_set_default_action_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ip_acl_set_default_action_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_set_default_action_acl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_set_default_action_acl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_set_default_action_acl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_set_default_action_acl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_acl_set_default_action_acl_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_acl_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_set_default_action_racl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_set_default_action_racl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_set_default_action_racl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_racl_set_default_action_racl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_set_default_action_racl_deny(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_deny_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_set_default_action_racl_permit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_permit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_set_default_action_racl_redirect_nexthop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_redirect_nexthop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_racl_set_default_action_racl_redirect_ecmp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_racl_redirect_ecmp_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t acl_stats_set_default_action_acl_stats_update(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t racl_stats_set_default_action_racl_stats_update(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_set_default_action_drop_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_set_default_action_drop_packet_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_drop_packet_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_set_default_action_redirect_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_redirect_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_set_default_action_redirect_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_set_default_action_copy_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_copy_to_cpu_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t system_acl_set_default_action_copy_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t drop_stats_set_default_action_drop_stats_update(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_drop_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_copy_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_redirect_to_cpu(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_copy_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_copy_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_redirect_to_cpu_with_reason(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_redirect_to_cpu_with_reason_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_mirror_coal_hdr(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_mirror_coal_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_insert_cpu_timestamp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_mirror(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_mirror_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t egress_system_acl_set_default_action_egress_mirror_and_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_egress_mirror_and_drop_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_star_g_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_star_g_set_default_action_multicast_bridge_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_bridge_set_default_action_multicast_bridge_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_set_default_action_multicast_route_star_g_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_set_default_action_multicast_route_sm_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_star_g_set_default_action_multicast_route_bidir_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv4_multicast_route_set_default_action_multicast_route_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_star_g_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_star_g_set_default_action_multicast_bridge_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_bridge_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_bridge_set_default_action_multicast_bridge_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_bridge_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_set_default_action_multicast_route_star_g_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_set_default_action_multicast_route_sm_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_route_sm_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_star_g_set_default_action_multicast_route_bidir_star_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_set_default_action_on_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ipv6_multicast_route_set_default_action_multicast_route_s_g_hit(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_multicast_route_s_g_hit_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t bd_flood_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t bd_flood_set_default_action_set_bd_flood_mc_index(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_bd_flood_mc_index_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_set_default_action_outer_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_outer_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_set_default_action_encap_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_encap_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_set_default_action_inner_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_inner_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rid_set_default_action_unicast_replica_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_unicast_replica_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mcast_egress_ifindex_set_default_action_set_egress_ifindex_from_rid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_egress_ifindex_from_rid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t replica_type_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t replica_type_set_default_action_set_replica_copy_bridged(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_l2_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_fib_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_cpu_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_cpu_redirect_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_acl_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_racl_redirect(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_rmac_non_ip_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_multicast_route(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_multicast_rpf_fail_bridge(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_multicast_rpf_fail_flood_to_mrouters(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_multicast_bridge(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_multicast_miss_flood(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_multicast_miss_flood_to_mrouters(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fwd_result_set_default_action_set_multicast_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_set_default_action_set_nexthop_details(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_nexthop_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_set_default_action_set_nexthop_details_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_nexthop_details_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_set_default_action_set_nexthop_details_for_post_routed_flood(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_nexthop_details_for_post_routed_flood_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_set_default_action_set_nexthop_details_for_glean(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_nexthop_details_for_glean_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t nexthop_set_default_action_set_nexthop_details_for_drop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_l2_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_l2_rewrite_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_l2_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_l3_rewrite_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_l3_rewrite_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_l3_rewrite_with_tunnel_vnid(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_l3_rewrite_with_tunnel_vnid_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_l3_rewrite_with_tunnel_and_ingress_vrf(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_l3_rewrite_with_tunnel_and_ingress_vrf_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_l3_rewrite(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_l3_rewrite_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_mpls_push_rewrite_l2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_mpls_push_rewrite_l2_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_mpls_swap_push_rewrite_l3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_mpls_swap_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t rewrite_set_default_action_set_mpls_push_rewrite_l3(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_mpls_push_rewrite_l3_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_stats_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_stats_set_default_action___meta_init_miss_action_storm_control_stats__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t storm_control_set_default_action_set_storm_control_meter(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_storm_control_meter_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fabric_ingress_dst_lkp_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t fabric_ingress_dst_lkp_set_default_action_terminate_cpu_packet(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_set_default_action_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_set_default_action_set_mirror_bd(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_mirror_bd_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_set_default_action_ipv4_erspan_t3_rewrite_with_eth_hdr(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t mirror_set_default_action_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ipv4_erspan_t3_rewrite_with_eth_hdr_and_vlan_tag_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv4_hashes_set_default_action___meta_init_miss_action_compute_ipv4_hashes__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_ipv6_hashes_set_default_action___meta_init_miss_action_compute_ipv6_hashes__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_non_ip_hashes_set_default_action___meta_init_miss_action_compute_non_ip_hashes__(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    EntryHandle_t compute_other_hashes_set_default_action_compute_other_hashes(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    
     # Table set/get property
# //::   if action_table_hdl: continue
    void switch_config_params_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t switch_config_params_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ethernet_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t validate_outer_ethernet_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_port_mapping_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ingress_port_mapping_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_port_properties_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ingress_port_properties_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void port_vlan_to_bd_mapping_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t port_vlan_to_bd_mapping_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void port_vlan_to_ifindex_mapping_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t port_vlan_to_ifindex_mapping_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void cpu_packet_transform_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t cpu_packet_transform_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_bd_stats_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ingress_bd_stats_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void lag_group_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t lag_group_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_port_mapping_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t egress_port_mapping_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_vlan_xlate_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t egress_vlan_xlate_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void capture_tstamp_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t capture_tstamp_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void spanning_tree_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t spanning_tree_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void smac_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t smac_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void dmac_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t dmac_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void learn_notify_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t learn_notify_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_packet_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t validate_packet_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_bd_stats_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t egress_bd_stats_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_bd_map_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t egress_bd_map_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_outer_bd_map_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t egress_outer_bd_map_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void vlan_decap_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t vlan_decap_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rmac_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t rmac_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void urpf_bd_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t urpf_bd_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void smac_rewrite_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t smac_rewrite_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void l3_rewrite_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t l3_rewrite_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mtu_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t mtu_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ipv4_packet_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t validate_outer_ipv4_packet_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_fib_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_fib_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_fib_lpm_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_fib_lpm_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_urpf_lpm_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_urpf_lpm_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_urpf_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_urpf_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_outer_ipv6_packet_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t validate_outer_ipv6_packet_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_fib_lpm_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_fib_lpm_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_fib_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_fib_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_urpf_lpm_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_urpf_lpm_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_urpf_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_urpf_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void outer_rmac_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t outer_rmac_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_dest_vtep_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_dest_vtep_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_src_vtep_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_src_vtep_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_dest_vtep_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_dest_vtep_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_src_vtep_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_src_vtep_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void adjust_lkp_fields_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t adjust_lkp_fields_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_lookup_miss_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_lookup_miss_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_check_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_check_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void validate_mpls_packet_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t validate_mpls_packet_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_decap_process_outer_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_decap_process_outer_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_decap_process_inner_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_decap_process_inner_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_vni_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t egress_vni_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_encap_process_inner_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_encap_process_inner_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_encap_process_outer_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_encap_process_outer_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_rewrite_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_rewrite_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_dst_rewrite_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_dst_rewrite_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_smac_rewrite_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_smac_rewrite_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_dmac_rewrite_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_dmac_rewrite_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void tunnel_to_mgid_mapping_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t tunnel_to_mgid_mapping_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_l4_src_port_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ingress_l4_src_port_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ingress_l4_dst_port_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ingress_l4_dst_port_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mac_acl_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t mac_acl_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ip_acl_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ip_acl_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_acl_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_acl_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_racl_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_racl_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_racl_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_racl_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void acl_stats_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t acl_stats_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void racl_stats_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t racl_stats_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void system_acl_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t system_acl_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void drop_stats_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t drop_stats_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void egress_system_acl_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t egress_system_acl_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_bridge_star_g_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_multicast_bridge_star_g_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_bridge_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_multicast_bridge_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_route_star_g_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_multicast_route_star_g_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv4_multicast_route_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv4_multicast_route_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_bridge_star_g_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_multicast_bridge_star_g_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_bridge_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_multicast_bridge_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_route_star_g_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_multicast_route_star_g_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ipv6_multicast_route_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ipv6_multicast_route_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void bd_flood_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t bd_flood_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rid_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t rid_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mcast_egress_ifindex_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t mcast_egress_ifindex_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void replica_type_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t replica_type_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void fwd_result_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t fwd_result_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void ecmp_group_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t ecmp_group_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void nexthop_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t nexthop_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void rewrite_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t rewrite_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void storm_control_stats_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t storm_control_stats_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void storm_control_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t storm_control_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void fabric_ingress_dst_lkp_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t fabric_ingress_dst_lkp_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void mirror_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t mirror_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_ipv4_hashes_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t compute_ipv4_hashes_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_ipv6_hashes_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t compute_ipv6_hashes_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_non_ip_hashes_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t compute_non_ip_hashes_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),
# //::   if action_table_hdl: continue
    void compute_other_hashes_set_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property, 4:tbl_property_value_t value, 5:i32 prop_args) throws (1:InvalidTableOperation ouch),

    tbl_property_value_args_t compute_other_hashes_get_property(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:tbl_property_t property) throws (1:InvalidTableOperation ouch),

    # INDIRECT ACTION DATA AND MATCH SELECT

    MemberHandle_t bd_action_profile_add_member_with_set_bd_properties(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void bd_action_profile_modify_member_with_set_bd_properties(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr, 4:dc_set_bd_properties_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    MemberHandle_t bd_action_profile_add_member_with_port_vlan_mapping_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    void bd_action_profile_modify_member_with_port_vlan_mapping_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void bd_action_profile_del_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    MemberHandle_t lag_action_profile_add_member_with_set_lag_miss(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    void lag_action_profile_modify_member_with_set_lag_miss(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    MemberHandle_t lag_action_profile_add_member_with_set_lag_port(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_lag_port_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void lag_action_profile_modify_member_with_set_lag_port(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr, 4:dc_set_lag_port_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_del_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    GroupHandle_t lag_action_profile_create_group(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 max_grp_size) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_del_group(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_add_member_to_group(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_del_member_from_group(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_group_member_state_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr, 5:dc_grp_mbr_state mbr_state) throws (1:InvalidTableOperation ouch),

    dc_grp_mbr_state lag_action_profile_group_member_state_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_set_dynamic_action_selection_fallback_member(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_reset_dynamic_action_selection_fallback_member(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<dc_sel_update_t> lag_action_profile_sel_get_updates(1:byte dev_id) throws (1:InvalidTableOperation ouch),

    void lag_action_profile_sel_track_updates(1:byte dev_id, 2:i32 cookie) throws (1:InvalidTableOperation ouch),
    MemberHandle_t ecmp_action_profile_add_member_with_nop(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),
    void ecmp_action_profile_modify_member_with_nop(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    MemberHandle_t ecmp_action_profile_add_member_with_set_ecmp_nexthop_details(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ecmp_nexthop_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ecmp_action_profile_modify_member_with_set_ecmp_nexthop_details(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr, 4:dc_set_ecmp_nexthop_details_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    MemberHandle_t ecmp_action_profile_add_member_with_set_ecmp_nexthop_details_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ecmp_nexthop_details_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ecmp_action_profile_modify_member_with_set_ecmp_nexthop_details_with_tunnel(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr, 4:dc_set_ecmp_nexthop_details_with_tunnel_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    MemberHandle_t ecmp_action_profile_add_member_with_set_ecmp_nexthop_details_for_post_routed_flood(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),
    void ecmp_action_profile_modify_member_with_set_ecmp_nexthop_details_for_post_routed_flood(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr, 4:dc_set_ecmp_nexthop_details_for_post_routed_flood_action_spec_t action_spec) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_del_member(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    GroupHandle_t ecmp_action_profile_create_group(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 max_grp_size) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_del_group(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_add_member_to_group(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_del_member_from_group(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_group_member_state_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr, 5:dc_grp_mbr_state mbr_state) throws (1:InvalidTableOperation ouch),

    dc_grp_mbr_state ecmp_action_profile_group_member_state_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:GroupHandle_t grp, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_set_dynamic_action_selection_fallback_member(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_reset_dynamic_action_selection_fallback_member(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt) throws (1:InvalidTableOperation ouch),

    list<dc_sel_update_t> ecmp_action_profile_sel_get_updates(1:byte dev_id) throws (1:InvalidTableOperation ouch),

    void ecmp_action_profile_sel_track_updates(1:byte dev_id, 2:i32 cookie) throws (1:InvalidTableOperation ouch),

    EntryHandle_t port_vlan_to_bd_mapping_add_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_bd_mapping_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t cpu_packet_transform_add_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_cpu_packet_transform_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t lag_group_add_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_lag_group_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t lag_group_add_entry_with_selector(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_lag_group_match_spec_t match_spec, 4:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ecmp_group_add_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ecmp_group_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ecmp_group_add_entry_with_selector(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ecmp_group_match_spec_t match_spec, 4:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),

    void port_vlan_to_bd_mapping_modify_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void port_vlan_to_bd_mapping_modify_entry_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_port_vlan_to_bd_mapping_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void cpu_packet_transform_modify_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void cpu_packet_transform_modify_entry_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_cpu_packet_transform_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void lag_group_modify_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void lag_group_modify_entry_with_selector(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),
    void lag_group_modify_entry_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_lag_group_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void lag_group_modify_entry_with_selector_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_lag_group_match_spec_t match_spec, 4:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),
    void ecmp_group_modify_entry(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void ecmp_group_modify_entry_with_selector(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:EntryHandle_t entry, 4:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),
    void ecmp_group_modify_entry_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ecmp_group_match_spec_t match_spec, 4:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    void ecmp_group_modify_entry_with_selector_by_match_spec(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:dc_ecmp_group_match_spec_t match_spec, 4:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),

    EntryHandle_t port_vlan_to_bd_mapping_set_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t cpu_packet_transform_set_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t lag_group_set_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t lag_group_set_default_entry_with_selector(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ecmp_group_set_default_entry(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:MemberHandle_t mbr) throws (1:InvalidTableOperation ouch),
    EntryHandle_t ecmp_group_set_default_entry_with_selector(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:GroupHandle_t grp) throws (1:InvalidTableOperation ouch),

  void mac_learn_digest_register(1: res.SessionHandle_t sess_hdl, 2: byte dev_id) throws (1:InvalidLearnOperation ouch),
  void mac_learn_digest_deregister(1: res.SessionHandle_t sess_hdl, 2: byte dev_id) throws (1:InvalidLearnOperation ouch),
  dc_mac_learn_digest_digest_msg_t mac_learn_digest_get_digest(1: res.SessionHandle_t sess_hdl) throws (1:InvalidLearnOperation ouch),
  void mac_learn_digest_digest_notify_ack(1: res.SessionHandle_t sess_hdl, 2: i64 msg_ptr) throws (1:InvalidLearnOperation ouch),

    void set_learning_timeout(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:i32 usecs) throws (1:InvalidLearnOperation ouch),

    void tbl_dbg_counter_type_set(1:res.DevTarget_t dev_tgt, 2:string tbl_name, 3:i32 type) throws (1:InvalidDbgOperation ouch),

    i32 tbl_dbg_counter_get(1:res.DevTarget_t dev_tgt, 2:string tbl_name) throws (1:InvalidDbgOperation ouch),

    void tbl_dbg_counter_clear(1:res.DevTarget_t dev_tgt, 2:string tbl_name) throws (1:InvalidDbgOperation ouch),

    void tbl_dbg_counter_type_stage_set(1:res.DevTarget_t dev_tgt, 2:byte stage, 3:i32 type) throws (1:InvalidDbgOperation ouch),

    void tbl_dbg_counter_stage_clear(1:res.DevTarget_t dev_tgt, 2: byte stage) throws (1:InvalidDbgOperation ouch),

    SnapshotHandle_t snapshot_create(1:res.DevTarget_t dev_tgt, 2:byte start_stage, 3:byte end_stage, 4:byte direction) throws (1:InvalidSnapshotOperation ouch),

    void snapshot_delete(1:SnapshotHandle_t handle) throws (1:InvalidSnapshotOperation ouch),

    void snapshot_state_set(1: SnapshotHandle_t handle, 2:i32 state, 3:i32 usecs) throws (1:InvalidSnapshotOperation ouch),

    i32 snapshot_state_get(1:SnapshotHandle_t handle, 2:i16 pipe) throws (1:InvalidSnapshotOperation ouch),

    void snapshot_timer_enable(1: SnapshotHandle_t handle, 2:byte disable) throws (1:InvalidSnapshotOperation ouch),

    void snapshot_capture_trigger_set(1: SnapshotHandle_t handle,
                2:dc_snapshot_trig_spec_t trig_spec,
                3:dc_snapshot_trig_spec_t trig_spec2) throws (1:InvalidSnapshotOperation ouch),

    i64 snapshot_capture_data_get(1: SnapshotHandle_t handle, 2:i16 pipe, 3:i16 stage_id, 4:string field_name) throws (1:InvalidSnapshotOperation ouch),

    dc_snapshot_tbl_data_t snapshot_capture_tbl_data_get(1: SnapshotHandle_t handle, 2:i16 pipe, 3:string table_name) throws (1:InvalidSnapshotOperation ouch),

    void snapshot_capture_trigger_fields_clr(1:SnapshotHandle_t handle) throws (1:InvalidSnapshotOperation ouch),

    bool snapshot_field_in_scope(1:res.DevTarget_t dev_tgt, 2:byte stage,
                 3:byte direction, 4:string field_name) throws (1:InvalidSnapshotOperation ouch),

    # counters

    dc_counter_value_t counter_read_ipv6_multicast_route_s_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_ipv6_multicast_route_s_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_acl_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_acl_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_storm_control_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_storm_control_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_ingress_bd_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_ingress_bd_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_ipv4_multicast_route_star_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_ipv4_multicast_route_star_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_drop_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_drop_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_ipv4_multicast_route_s_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_ipv4_multicast_route_s_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_drop_stats_2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_drop_stats_2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_ipv6_multicast_route_star_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_ipv6_multicast_route_star_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_racl_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_racl_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),

    dc_counter_value_t counter_read_egress_bd_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_flags_t flags) throws (1:InvalidCounterOperation ouch),
    void counter_write_egress_bd_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:dc_counter_value_t counter_value) throws (1:InvalidCounterOperation ouch),


    void counter_hw_sync_ipv6_multicast_route_s_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_acl_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_storm_control_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_ingress_bd_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_ipv4_multicast_route_star_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_drop_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_ipv4_multicast_route_s_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_drop_stats_2(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_ipv6_multicast_route_star_g_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_racl_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),
    void counter_hw_sync_egress_bd_stats(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:bool blocking) throws (1:InvalidCounterOperation ouch),

    # registers



    dc_bytes_meter_spec_t meter_read_storm_control_meter(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index) throws (1:InvalidMeterOperation ouch),
    void meter_set_storm_control_meter(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_bytes_meter_spec_t meter_spec) throws (1:InvalidMeterOperation ouch),

    dc_packets_meter_spec_t meter_read_copp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index) throws (1:InvalidMeterOperation ouch),
    void meter_set_copp(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:dc_packets_meter_spec_t meter_spec) throws (1:InvalidMeterOperation ouch),








    void hash_calc_lkp_ipv6_hash1_input_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv6_hash1_input_t input) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_ipv6_hash1_input_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_ipv6_hash1_algorithm_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv6_hash1_algo_t algo) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_ipv6_hash1_algorithm_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_ipv6_hash1_seed_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:i64 seed) throws (1:InvalidTableOperation ouch),

    i64 hash_calc_lkp_ipv6_hash1_seed_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_ipv6_hash1_input_field_attribute_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv6_hash1_input_t input, 4:list<dc_lkp_ipv6_hash1_input_field_attribute_t> array_of_attrs) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_ipv6_hash1_input_field_attribute_count_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv6_hash1_input_t input) throws (1:InvalidTableOperation ouch),

    list<dc_lkp_ipv6_hash1_input_field_attribute_t> hash_calc_lkp_ipv6_hash1_input_field_attribute_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv6_hash1_input_t input) throws (1:InvalidTableOperation ouch),


    void hash_calc_lag_hash_input_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lag_hash_input_t input) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lag_hash_input_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lag_hash_algorithm_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lag_hash_algo_t algo) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lag_hash_algorithm_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lag_hash_seed_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:i64 seed) throws (1:InvalidTableOperation ouch),

    i64 hash_calc_lag_hash_seed_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lag_hash_input_field_attribute_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lag_hash_input_t input, 4:list<dc_lag_hash_input_field_attribute_t> array_of_attrs) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lag_hash_input_field_attribute_count_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lag_hash_input_t input) throws (1:InvalidTableOperation ouch),

    list<dc_lag_hash_input_field_attribute_t> hash_calc_lag_hash_input_field_attribute_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lag_hash_input_t input) throws (1:InvalidTableOperation ouch),


    void hash_calc_lkp_ipv4_hash1_input_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv4_hash1_input_t input) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_ipv4_hash1_input_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_ipv4_hash1_algorithm_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv4_hash1_algo_t algo) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_ipv4_hash1_algorithm_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_ipv4_hash1_seed_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:i64 seed) throws (1:InvalidTableOperation ouch),

    i64 hash_calc_lkp_ipv4_hash1_seed_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_ipv4_hash1_input_field_attribute_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv4_hash1_input_t input, 4:list<dc_lkp_ipv4_hash1_input_field_attribute_t> array_of_attrs) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_ipv4_hash1_input_field_attribute_count_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv4_hash1_input_t input) throws (1:InvalidTableOperation ouch),

    list<dc_lkp_ipv4_hash1_input_field_attribute_t> hash_calc_lkp_ipv4_hash1_input_field_attribute_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_ipv4_hash1_input_t input) throws (1:InvalidTableOperation ouch),


    void hash_calc_lkp_non_ip_hash1_input_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_non_ip_hash1_input_t input) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_non_ip_hash1_input_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_non_ip_hash1_algorithm_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_non_ip_hash1_algo_t algo) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_non_ip_hash1_algorithm_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_non_ip_hash1_seed_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:i64 seed) throws (1:InvalidTableOperation ouch),

    i64 hash_calc_lkp_non_ip_hash1_seed_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_lkp_non_ip_hash1_input_field_attribute_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_non_ip_hash1_input_t input, 4:list<dc_lkp_non_ip_hash1_input_field_attribute_t> array_of_attrs) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_lkp_non_ip_hash1_input_field_attribute_count_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_non_ip_hash1_input_t input) throws (1:InvalidTableOperation ouch),

    list<dc_lkp_non_ip_hash1_input_field_attribute_t> hash_calc_lkp_non_ip_hash1_input_field_attribute_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_lkp_non_ip_hash1_input_t input) throws (1:InvalidTableOperation ouch),


    void hash_calc_ecmp_hash_input_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_ecmp_hash_input_t input) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_ecmp_hash_input_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_ecmp_hash_algorithm_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_ecmp_hash_algo_t algo) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_ecmp_hash_algorithm_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_ecmp_hash_seed_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:i64 seed) throws (1:InvalidTableOperation ouch),

    i64 hash_calc_ecmp_hash_seed_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id) throws (1:InvalidTableOperation ouch),

    void hash_calc_ecmp_hash_input_field_attribute_set(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_ecmp_hash_input_t input, 4:list<dc_ecmp_hash_input_field_attribute_t> array_of_attrs) throws (1:InvalidTableOperation ouch),

    i32 hash_calc_ecmp_hash_input_field_attribute_count_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_ecmp_hash_input_t input) throws (1:InvalidTableOperation ouch),

    list<dc_ecmp_hash_input_field_attribute_t> hash_calc_ecmp_hash_input_field_attribute_get(1:res.SessionHandle_t sess_hdl, 2:byte dev_id, 3:dc_ecmp_hash_input_t input) throws (1:InvalidTableOperation ouch),


} 
