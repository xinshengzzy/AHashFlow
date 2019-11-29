/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/

#include <saivlan.h>
#include "saiinternal.h"
#include <switchapi/switch.h>
#include <switchapi/switch_vlan.h>
#include <switchapi/switch_device.h>
#include <switchapi/switch_table.h>
#include <switchapi/switch_queue.h>
#include <switchapi/switch_nhop.h>
#include <switchapi/switch_buffer.h>
#include <switchapi/switch_l3.h>
#include <switchapi/switch_dtel.h>
#include <switchapi/switch_mirror.h>
#include <switchapi/switch_port.h>

static sai_api_t api_id = SAI_API_SWITCH;

sai_switch_notification_t sai_switch_notifications;

extern sai_object_id_t sai_hostif_get_default(void);
extern switch_handle_t sai_bridge_get_default1q_bridge(void);

sai_object_id_t hash_id =
    (SWITCH_HANDLE_TYPE_HASH << SWITCH_HANDLE_TYPE_SHIFT) | 0x1;

const char *switch_attr_name[] = {
    "SAI_SWITCH_ATTR_PORT_NUMBER",
    "SAI_SWITCH_ATTR_MAX_NUMBER_OF_SUPPORTED_PORTS",
    "SAI_SWITCH_ATTR_PORT_LIST",
    "SAI_SWITCH_ATTR_PORT_MAX_MTU",
    "SAI_SWITCH_ATTR_CPU_PORT",
    "SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS",
    "SAI_SWITCH_ATTR_FDB_TABLE_SIZE",
    "SAI_SWITCH_ATTR_L3_NEIGHBOR_TABLE_SIZE",
    "SAI_SWITCH_ATTR_L3_ROUTE_TABLE_SIZE",
    "SAI_SWITCH_ATTR_LAG_MEMBERS",
    "SAI_SWITCH_ATTR_NUMBER_OF_LAGS",
    "SAI_SWITCH_ATTR_ECMP_MEMBERS",
    "SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS",
    "SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES",
    "SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES",
    "SAI_SWITCH_ATTR_NUMBER_OF_QUEUES",
    "SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES",
    "SAI_SWITCH_ATTR_ON_LINK_ROUTE_SUPPORTED",
    "SAI_SWITCH_ATTR_OPER_STATUS",
    "SAI_SWITCH_ATTR_MAX_TEMP",
    "SAI_SWITCH_ATTR_ACL_TABLE_MINIMUM_PRIORITY",
    "SAI_SWITCH_ATTR_ACL_TABLE_MAXIMUM_PRIORITY",
    "SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY",
    "SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY",
    "SAI_SWITCH_ATTR_ACL_TABLE_GROUP_MINIMUM_PRIORITY",
    "SAI_SWITCH_ATTR_ACL_TABLE_GROUP_MAXIMUM_PRIORITY",
    "SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE",
    "SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE",
    "SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE",
    "SAI_SWITCH_ATTR_PORT_USER_META_DATA_RANGE",
    "SAI_SWITCH_ATTR_VLAN_USER_META_DATA_RANGE",
    "SAI_SWITCH_ATTR_ACL_USER_META_DATA_RANGE",
    "SAI_SWITCH_ATTR_ACL_USER_TRAP_ID_RANGE",
    "SAI_SWITCH_ATTR_DEFAULT_VLAN_ID",
    "SAI_SWITCH_ATTR_DEFAULT_STP_INST_ID",
    "SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID",
    "SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID",
    "SAI_SWITCH_ATTR_INGRESS_ACL",
    "SAI_SWITCH_ATTR_EGRESS_ACL",
    "SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_TRAFFIC_CLASSES",
    "SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUP_HIERARCHY_LEVELS",
    "SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUPS_PER_HIERARCHY_LEVEL",
    "SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_CHILDS_PER_SCHEDULER_GROUP",
    "SAI_SWITCH_ATTR_TOTAL_BUFFER_SIZE",
    "SAI_SWITCH_ATTR_INGRESS_BUFFER_POOL_NUM",
    "SAI_SWITCH_ATTR_EGRESS_BUFFER_POOL_NUM",
    "SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_L2MC_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_IPMC_ENTRY",
    "SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE",
    "SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP",
    "SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP",
    "SAI_SWITCH_ATTR_ECMP_HASH",
    "SAI_SWITCH_ATTR_LAG_HASH",
    "SAI_SWITCH_ATTR_RESTART_WARM",
    "SAI_SWITCH_ATTR_RESTART_TYPE",
    "SAI_SWITCH_ATTR_MIN_PLANNED_RESTART_INTERVAL",
    "SAI_SWITCH_ATTR_NV_STORAGE_SIZE",
    "SAI_SWITCH_ATTR_MAX_ACL_ACTION_COUNT",
    "SAI_SWITCH_ATTR_MAX_ACL_RANGE_COUNT",
    "SAI_SWITCH_ATTR_ACL_CAPABILITY",
    "SAI_SWITCH_ATTR_MCAST_SNOOPING_CAPABILITY",
    "SAI_SWITCH_ATTR_SWITCHING_MODE",
    "SAI_SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE",
    "SAI_SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE",
    "SAI_SWITCH_ATTR_SRC_MAC_ADDRESS",
    "SAI_SWITCH_ATTR_MAX_LEARNED_ADDRESSES",
    "SAI_SWITCH_ATTR_FDB_AGING_TIME",
    "SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION",
    "SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION",
    "SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION",
    "SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM",
    "SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED",
    "SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH",
    "SAI_SWITCH_ATTR_ECMP_HASH_IPV4",
    "SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4",
    "SAI_SWITCH_ATTR_ECMP_HASH_IPV6",
    "SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM",
    "SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED",
    "SAI_SWITCH_ATTR_LAG_DEFAULT_SYMMETRIC_HASH",
    "SAI_SWITCH_ATTR_LAG_HASH_IPV4",
    "SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4",
    "SAI_SWITCH_ATTR_LAG_HASH_IPV6",
    "SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL",
    "SAI_SWITCH_ATTR_QOS_DEFAULT_TC",
    "SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP",
    "SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP",
    "SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP",
    "SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP",
    "SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP",
    "SAI_SWITCH_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP",
    "SAI_SWITCH_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP",
    "SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE",
    "SAI_SWITCH_ATTR_SWITCH_PROFILE_ID",
    "SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO",
    "SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME",
    "SAI_SWITCH_ATTR_INIT_SWITCH",
    "SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY",
    "SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY",
    "SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY",
    "SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY",
    "SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY",
    "SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY",
    "SAI_SWITCH_ATTR_FAST_API_ENABLE",
    "SAI_SWITCH_ATTR_MIRROR_TC",
    "SAI_SWITCH_ATTR_ACL_STAGE_INGRESS",
    "SAI_SWITCH_ATTR_ACL_STAGE_EGRESS",
    "SAI_SWITCH_ATTR_SEGMENTROUTE_MAX_SID_DEPTH",
    "SAI_SWITCH_ATTR_SEGMENTROUTE_TLV_TYPE",
    "SAI_SWITCH_ATTR_QOS_NUM_LOSSLESS_QUEUES",
    "SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY",
    "SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION",
    "SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL_RANGE",
    "SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL",
    "SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL_RANGE",
    "SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL",
    "SAI_SWITCH_ATTR_SUPPORTED_PROTECTED_OBJECT_TYPE",
    "SAI_SWITCH_ATTR_TPID_OUTER_VLAN",
    "SAI_SWITCH_ATTR_TPID_INNER_VLAN",
    "SAI_SWITCH_ATTR_CRC_CHECK_ENABLE",
    "SAI_SWITCH_ATTR_CRC_RECALCULATION_ENABLE",
    "SAI_SWITCH_ATTR_BFD_SESSION_STATE_CHANGE_NOTIFY",
    "SAI_SWITCH_ATTR_NUMBER_OF_BFD_SESSION",
    "SAI_SWITCH_ATTR_MAX_BFD_SESSION",
    "SAI_SWITCH_ATTR_MIN_BFD_RX",
    "SAI_SWITCH_ATTR_MIN_BFD_TX",
    "SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE",
    "SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC",
    "SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT",
    "SAI_SWITCH_ATTR_MAX_MIRROR_SESSION",
    "SAI_SWITCH_ATTR_MAX_SAMPLED_MIRROR_SESSION",
    "SAI_SWITCH_ATTR_SUPPORTED_EXTENDED_STATS_MODE",
    "SAI_SWITCH_ATTR_UNINIT_DATA_PLANE_ON_REMOVAL",
    ""};

sai_status_t sai_fdb_packet_type_to_switch_packet_type(
    uint32_t sai_packet_type, switch_packet_type_t *switch_packet_type) {
  switch (sai_packet_type) {
    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
      *switch_packet_type = SWITCH_PACKET_TYPE_UNICAST;
      return SAI_STATUS_SUCCESS;
    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
      *switch_packet_type = SWITCH_PACKET_TYPE_MULTICAST;
      return SAI_STATUS_SUCCESS;
    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
      *switch_packet_type = SWITCH_PACKET_TYPE_BROADCAST;
      return SAI_STATUS_SUCCESS;
    default:
      return SAI_STATUS_FAILURE;
  }
}

/*
* Routine Description:
*    Set switch attribute value
*
* Arguments:
 *   [in] switch_id Switch id
*    [in] attr - switch attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_switch_attribute(_In_ sai_object_id_t switch_id,
                                      _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  switch_uint64_t flags = 0;
  switch_api_device_info_t api_device_info;
  sai_packet_action_t sai_packet_action;
  switch_acl_action_t switch_packet_action;
  switch_packet_type_t switch_packet_type = SWITCH_PACKET_TYPE_UNICAST;
  bool cut_through = false;

  if (!attr) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute: %s", sai_status_to_string(status));
    return status;
  }

  memset(&api_device_info, 0x0, sizeof(api_device_info));
  if (status != SAI_STATUS_SUCCESS) {
    return status;
  }
  if (attr->id <= SAI_SWITCH_ATTR_ACL_STAGE_EGRESS) {  // Unsupported
    SAI_LOG_DEBUG("Switch attribute set: %s", switch_attr_name[attr->id]);
  }

  switch (attr->id) {
    case SAI_SWITCH_ATTR_SRC_MAC_ADDRESS:
      flags |= SWITCH_DEVICE_ATTR_DEFAULT_MAC;
      memcpy(&api_device_info.mac, &attr->value.mac, 6);
      switch_status =
          switch_api_device_attribute_set(device, flags, &api_device_info);
      // Unsupported: Temporary hack till all attrs are supported
      switch_status = SWITCH_STATUS_SUCCESS;
      break;
    case SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY:
      sai_switch_notifications.on_fdb_event = attr->value.ptr;
      break;
    case SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY:
      sai_switch_notifications.on_port_state_change = attr->value.ptr;
      break;
    case SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY:
      sai_switch_notifications.on_packet_event = attr->value.ptr;
      break;
    case SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY:
      sai_switch_notifications.on_switch_state_change = attr->value.ptr;
      break;
    case SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY:
      sai_switch_notifications.on_switch_shutdown_request = attr->value.ptr;
      break;
    case SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL:
      switch_status = switch_api_device_counter_refresh_interval_set(
          device, attr->value.u32);
      break;
    case SAI_SWITCH_ATTR_INIT_SWITCH:  // Unsupported
      break;
    case SAI_SWITCH_ATTR_FDB_AGING_TIME:
      flags |= SWITCH_DEVICE_ATTR_DEFAULT_AGING_TIME;
      api_device_info.aging_interval = attr->value.u32 * 1000;
      switch_status =
          switch_api_device_attribute_set(device, flags, &api_device_info);
      break;
    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
      sai_packet_action = attr->value.s32;
      switch_packet_action =
          sai_packet_action_to_switch_packet_action(sai_packet_action);
      sai_fdb_packet_type_to_switch_packet_type(attr->id, &switch_packet_type);
      status = switch_api_device_dmac_miss_packet_action_set(
          device, switch_packet_type, switch_packet_action);
      break;
    case SAI_SWITCH_ATTR_SWITCHING_MODE:
      if (attr->value.s32 == SAI_SWITCH_SWITCHING_MODE_CUT_THROUGH) {
        cut_through = true;
      } else {
        cut_through = false;
      }
      switch_status =
          switch_api_device_cut_through_mode_set(device, cut_through);
      break;

    case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED:
      switch_status = switch_api_ecmp_hash_seed_set(device, attr->value.u64);
      break;
    case SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED:
      switch_status = switch_api_lag_hash_seed_set(device, attr->value.u64);
      break;

    case SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC:
      flags |= SWITCH_DEVICE_ATTR_TUNNEL_DMAC;
      memcpy(&api_device_info.tunnel_dmac, &attr->value.mac, 6);
      switch_status =
          switch_api_device_attribute_set(device, flags, &api_device_info);
      break;
    case SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM:
    case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM:
      if (attr->value.s32 == SAI_HASH_ALGORITHM_CRC) {
        switch_api_non_ip_hash_algorithm_set(
            device, SWITCH_HASH_NON_IP_INPUT_ALGORITHM_CRC32);
        switch_api_ipv4_hash_algorithm_set(
            device, SWITCH_HASH_IPV4_INPUT_ALGORITHM_CRC32);
        switch_api_ipv6_hash_algorithm_set(
            device, SWITCH_HASH_IPV6_INPUT_ALGORITHM_CRC32);
      }
      break;

    default:
      SAI_LOG_ERROR("Unsupported Switch attribute: %d", attr->id);
      // Unsupported: Temporary hack till all attrs are supported
      switch_status = SWITCH_STATUS_SUCCESS;
  }

  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to set switch attribute %s: %s",
                  switch_attr_name[attr->id],
                  sai_status_to_string(status));
    return status;
  }
  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
 * Routine Description:
 *     Get switch-api table-id mapping from SAI table ids.
 *
 * Arguments:
 *  [in] sai table-id
 *
 * Return value:
 *     switch-api table-id.
 *
 */
switch_table_id_t sai_get_switchapi_table_id(int sai_table_id) {
  switch (sai_table_id) {
    case SAI_SWITCH_ATTR_FDB_TABLE_SIZE:
      return SWITCH_TABLE_DMAC;

    case SAI_SWITCH_ATTR_NUMBER_OF_LAGS:
      return SWITCH_TABLE_LAG_GROUP;

    case SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS:
    case SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY:
      return SWITCH_TABLE_ECMP_GROUP;

    case SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY:
    case SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY:
    case SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY:
      return SWITCH_TABLE_NHOP;

    case SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY:
      return SWITCH_TABLE_DMAC;

    default:
      return SWITCH_TABLE_MAX;
  }
}
#define SAI_SWITCH_ACL_ENTRY_MINIMUM_PRIORITY 0
#define SAI_SWITCH_ACL_ENTRY_MAXIMUM_PRIORITY \
  SWITCH_API_ACL_ENTRY_MAXIMUM_PRIORITY
/*
* Routine Description:
*    Get switch attribute value
*
* Arguments:
*    [in] attr_count - number of switch attributes
 *   [in] switch_id Switch id
*    [inout] attr_list - array of switch attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_switch_attribute(_In_ sai_object_id_t switch_id,
                                      _In_ uint32_t attr_count,
                                      _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  uint32_t index1 = 0, index2 = 0;
  sai_object_list_t *objlist = NULL;
  switch_api_device_info_t api_device_info;
  sai_attribute_t attribute;
  switch_uint64_t flags = 0;
  switch_size_t table_size = 0;
  switch_table_id_t table_id = 0;
  switch_size_t route_tbl_size = 0;
  switch_size_t nhop_size = 0;
  switch_uint32_t max_queues = 0;
  switch_uint8_t max_pools = 0;
  switch_uint32_t cntr_refresh_interval = 0;
  switch_uint64_t buffer_size = 0;
  switch_uint32_t max_tcs = 0;
  switch_handle_t cpu_port_handle = 0;
  switch_size_t inuse_count = 0;
  switch_size_t num_avail = 0;
  uint64_t seed = 0;

  switch_acl_action_t switch_packet_action;
  switch_packet_type_t switch_packet_type = SWITCH_PACKET_TYPE_UNICAST;
  sai_packet_action_t sai_packet_action;
  bool cut_through = false;

  switch_table_id_t table_ipv4[] = {SWITCH_TABLE_IPV4_HOST,
                                    SWITCH_TABLE_IPV4_LPM};
  switch_table_id_t table_ipv6[] = {SWITCH_TABLE_IPV6_HOST,
                                    SWITCH_TABLE_IPV6_LPM};

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  memset(&api_device_info, 0x0, sizeof(api_device_info));
  flags |= SWITCH_DEVICE_ATTR_PORT_LIST;
  flags |= SWITCH_DEVICE_ATTR_MAX_PORTS;
  flags |= SWITCH_DEVICE_ATTR_ETH_CPU_PORT;
  flags |= SWITCH_DEVICE_ATTR_DEFAULT_VRF_HANDLE;
  flags |= SWITCH_DEVICE_ATTR_DEFAULT_MAC;
  flags |= SWITCH_DEVICE_ATTR_DEFAULT_VLAN_HANDLE;
  flags |= SWITCH_DEVICE_ATTR_MAX_LAG_MEMBERS;
  flags |= SWITCH_DEVICE_ATTR_MAX_ECMP_MEMBERS;
  flags |= SWITCH_DEVICE_ATTR_MAX_VRFS;
  flags |= SWITCH_DEVICE_ATTR_DEFAULT_AGING_TIME;
  flags |= SWITCH_DEVICE_ATTR_ACTIVE_PORTS;
  flags |= SWITCH_DEVICE_ATTR_MAX_PORT_MTU;

  switch_status =
      switch_api_device_attribute_get(device, flags, &api_device_info);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to get switch attribute: %s",
                  sai_status_to_string(status));
    return status;
  }
  for (index1 = 0; index1 < attr_count; index1++) {
    attribute = attr_list[index1];
    switch (attr_list[index1].id) {
      case SAI_SWITCH_ATTR_PORT_NUMBER:
        // case SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS:
        // attr_list[index1].value.u32 = api_device_info.num_active_ports;
        // break;
        // case SAI_SWITCH_ATTR_MAX_NUMBER_OF_SUPPORTED_PORTS:
        attr_list[index1].value.u32 = api_device_info.port_list.num_handles;
        break;

      case SAI_SWITCH_ATTR_PORT_LIST:
        objlist = &attr_list->value.objlist;
        objlist->count = api_device_info.port_list.num_handles;
        for (index2 = 0; index2 < objlist->count; index2++) {
          objlist->list[index2] = api_device_info.port_list.handles[index2];
        }
        break;
      case SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED:
        switch_status = switch_api_lag_hash_seed_get(device, &seed);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get lag default hash seed: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u64 = seed;
        break;
      case SAI_SWITCH_ATTR_LAG_HASH_IPV4:          // Unsupported
      case SAI_SWITCH_ATTR_LAG_HASH_IPV4_IN_IPV4:  // Unsupported
        break;
      case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM:
      case SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM:
        /**
         * The only hash that we support in SAI is CRC32 which is by
         * default set for non-ip, ipv4 and ipv6 hashing.
         */
        attr_list[index1].value.s32 = SAI_HASH_ALGORITHM_CRC;
        break;
      case SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED:
        switch_status = switch_api_ecmp_hash_seed_get(device, &seed);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get ecmp default hash seed: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u64 = seed;
        break;
      case SAI_SWITCH_ATTR_ECMP_HASH_IPV4:               // Unsupported
      case SAI_SWITCH_ATTR_ECMP_HASH_IPV4_IN_IPV4:       // Unsupported
      case SAI_SWITCH_ATTR_ECMP_DEFAULT_SYMMETRIC_HASH:  // Unsupported
        break;
      case SAI_SWITCH_ATTR_DEFAULT_STP_INST_ID:  // Unsupported
        break;
      case SAI_SWITCH_ATTR_SRC_MAC_ADDRESS:
        memcpy(attr_list[index1].value.mac, &api_device_info.mac, 6);

        break;
      case SAI_SWITCH_ATTR_CPU_PORT:
        switch_api_device_cpu_port_handle_get(device, &cpu_port_handle);
        attr_list[index1].value.oid = cpu_port_handle;
        break;
      case SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID:
        attr_list[index1].value.oid = api_device_info.vrf_handle;
        break;
      case SAI_SWITCH_ATTR_DEFAULT_VLAN_ID:
        attr_list[index1].value.oid = api_device_info.vlan_handle;
        break;
      case SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY:
        attr_list[index1].value.ptr = sai_switch_notifications.on_fdb_event;
        break;
      case SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY:
        attr_list[index1].value.ptr =
            sai_switch_notifications.on_port_state_change;
        break;
      case SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY:
        attr_list[index1].value.ptr = sai_switch_notifications.on_packet_event;
        break;
      case SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY:
        attr_list[index1].value.ptr =
            sai_switch_notifications.on_switch_state_change;
        break;
      case SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY:
        attr_list[index1].value.ptr =
            sai_switch_notifications.on_switch_shutdown_request;
        break;
      case SAI_SWITCH_ATTR_FDB_TABLE_SIZE:
      case SAI_SWITCH_ATTR_NUMBER_OF_LAGS:
      case SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS:
        table_id = sai_get_switchapi_table_id(attribute.id);
        if (table_id == SWITCH_TABLE_MAX) {
          SAI_LOG_ERROR("Failed to get proper sai-to-switchapi table mapping");
          return SAI_STATUS_FAILURE;
        }
        switch_status =
            switch_api_table_size_get(device, table_id, &table_size);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get table size: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = table_size;
        break;

      case SAI_SWITCH_ATTR_LAG_MEMBERS:
        attr_list[index1].value.u32 = api_device_info.max_lag_members;
        break;
      case SAI_SWITCH_ATTR_ECMP_MEMBERS:
        attr_list[index1].value.u32 = api_device_info.max_ecmp_members;
        break;
      case SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL:
        switch_status = switch_api_device_counter_refresh_interval_get(
            device, &cntr_refresh_interval);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get switch counter refresh interval: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = cntr_refresh_interval;
        break;

      case SAI_SWITCH_ATTR_L3_NEIGHBOR_TABLE_SIZE:
        switch_status = switch_api_nhop_table_size_get(device, &nhop_size);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get nexthop table size: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = nhop_size;
        break;

      case SAI_SWITCH_ATTR_L3_ROUTE_TABLE_SIZE:
        switch_status =
            switch_api_route_table_size_get(device, &route_tbl_size);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get V4 host table size: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = route_tbl_size;
        break;

      case SAI_SWITCH_ATTR_NUMBER_OF_QUEUES:
        switch_status = switch_api_max_queues_get(device, &max_queues);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get max number of queues: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = max_queues;
        break;

      case SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES:
        switch_status = switch_api_max_cpu_queues_get(device, &max_queues);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get max number of CPU queues: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = max_queues;
        break;

      case SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES:
      case SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES:
        attr_list[index1].value.u32 = SWITCH_MAX_PORT_QUEUE;
        break;

      case SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS:
        attr_list[index1].value.u32 = api_device_info.max_vrf;
        break;

      case SAI_SWITCH_ATTR_INGRESS_BUFFER_POOL_NUM:
        switch_status = switch_api_max_ingress_pool_get(device, &max_pools);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get max number of queues: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = max_pools;
        break;

      case SAI_SWITCH_ATTR_EGRESS_BUFFER_POOL_NUM:
        switch_status = switch_api_max_egress_pool_get(device, &max_pools);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get max number of queues: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = max_pools;
        break;

      case SAI_SWITCH_ATTR_TOTAL_BUFFER_SIZE:
        switch_status = switch_api_total_buffer_size_get(device, &buffer_size);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get max number of queues: %s",
                        sai_status_to_string(status));
          return status;
        }
        // Return total buffer size in KB to SAI layer.
        attr_list[index1].value.u32 = (buffer_size >> 10);
        break;

      case SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_TRAFFIC_CLASSES:
        switch_status = switch_api_max_traffic_class_get(device, &max_tcs);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get max number of tcs: %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = max_tcs;
        break;

      case SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP:
        attr_list[index1].value.oid = sai_hostif_get_default();
        break;
      case SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID:
        attr_list[index1].value.oid = sai_bridge_get_default1q_bridge();
        break;

      case SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY:
        attr_list[index1].value.u32 = SAI_SWITCH_ACL_ENTRY_MINIMUM_PRIORITY;
        break;

      case SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY:
        attr_list[index1].value.u32 = SAI_SWITCH_ACL_ENTRY_MAXIMUM_PRIORITY;
        break;

      case SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_CHILDS_PER_SCHEDULER_GROUP:
        switch_status = switch_api_max_queues_get(device, &max_queues);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get max number of queues: %s",
                        sai_status_to_string(status));
          return status;
        }
        /*
         * Number of maximum child scheduler group is same as maximum number of
         * queues.
         */
        attr_list[index1].value.u32 = max_queues;
        break;

      case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
      case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
      case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
        sai_fdb_packet_type_to_switch_packet_type(attr_list[index1].id,
                                                  &switch_packet_type);
        switch_status = switch_api_device_dmac_miss_packet_action_get(
            device, switch_packet_type, &switch_packet_action);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("Failed to get FDB miss packet action : %s",
                        sai_status_to_string(status));
          return status;
        }
        sai_packet_action =
            switch_packet_action_to_sai_packet_action(switch_packet_action);
        attr_list[index1].value.s32 = sai_packet_action;
        break;
      case SAI_SWITCH_ATTR_FDB_AGING_TIME:
        attr_list[index1].value.u32 = (uint32_t)api_device_info.aging_interval;
        break;

      case SAI_SWITCH_ATTR_SWITCHING_MODE:
        switch_status =
            switch_api_device_cut_through_mode_get(device, &cut_through);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("Failed to get cut-through mode : %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.s32 =
            cut_through ? SAI_SWITCH_SWITCHING_MODE_CUT_THROUGH
                        : SAI_SWITCH_SWITCHING_MODE_STORE_AND_FORWARD;
        break;
      case SAI_SWITCH_ATTR_PORT_MAX_MTU:
        attr_list[index1].value.u32 = api_device_info.max_port_mtu;
        break;

      case SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUP_HIERARCHY_LEVELS:
      case SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUPS_PER_HIERARCHY_LEVEL:
        attr_list[index1].value.u32 = 1;
        break;

      case SAI_SWITCH_ATTR_ECMP_HASH:
      case SAI_SWITCH_ATTR_LAG_HASH:
        attr_list[index1].value.oid = hash_id;
        break;

      /* available IPv4/IPv6 routes (SONiC CRM) */
      case SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY:
      case SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY: {
        switch_table_id_t *table_ids =
            (attr_list[index1].id == SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY)
                ? table_ipv4
                : table_ipv6;
        attr_list[index1].value.u32 = 0;
        for (unsigned i = 0; i < sizeof(table_ipv4) / sizeof(switch_table_id_t);
             i++) {
          switch_status = switch_api_table_available_count_get(
              device, table_ids[i], &num_avail);
          status = sai_switch_status_to_sai_status(switch_status);
          if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to get table available count %s",
                          sai_status_to_string(status));
            return status;
          }
          attr_list[index1].value.u32 += num_avail;
        }
      } break;

      /* available IPv4/IPv6 nexthop entries (SONiC CRM) */
      case SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY:
      case SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY:
      case SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY:
      case SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY:
      case SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY: {
        table_id = sai_get_switchapi_table_id(attribute.id);
        if (table_id == SWITCH_TABLE_MAX) {
          SAI_LOG_ERROR("Failed to get proper sai-to-switchapi table mapping");
          return SAI_STATUS_FAILURE;
        }
        switch_status =
            switch_api_table_available_count_get(device, table_id, &num_avail);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get table available count %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 = num_avail;
      } break;

      /* available IPv4/IPv6 neighbors (SONiC CRM)
       * Neighbor entries gets programmed in both host and nhop tables.
       * Return the smaller of available numbers from these two tables.
       */
      case SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY:
      case SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY: {
        uint32_t nhop_available, host_available;
        switch_table_id_t host_table =
            (attr_list[index1].id ==
             SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY)
                ? SWITCH_TABLE_IPV4_HOST
                : SWITCH_TABLE_IPV6_HOST;

        switch_status = switch_api_table_available_count_get(
            device, SWITCH_TABLE_NHOP, &nhop_available);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get table available count for table %s",
                        sai_status_to_string(status));
          return status;
        }
        switch_status = switch_api_table_available_count_get(
            device, host_table, &host_available);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get table available count for table %s",
                        sai_status_to_string(status));
          return status;
        }
        attr_list[index1].value.u32 =
            nhop_available < host_available ? nhop_available : host_available;
      } break;

      /* available ACL table and groups (SONiC CRM) */
      case SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE:
      case SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP: {
        sai_acl_stage_t stage;
        sai_acl_bind_point_type_t bpt;
        uint32_t count, aclresource_size;
        uint32_t ingress_avail, egress_avail;
        uint32_t racl_avail, system_i_avail, system_e_avail;
        switch_table_id_t tid;

        attr_list[index1].value.aclresource.count =
            2 * (SAI_ACL_BIND_POINT_TYPE_SWITCH + 1);
        if (attr_list[index1].value.aclresource.list == NULL) break;

        ingress_avail = egress_avail = 0;

        /* same value for many stage-bind point combination */
        switch_table_id_t ingress_table[] = {SWITCH_TABLE_IPV4_ACL,
                                             SWITCH_TABLE_IPV6_ACL,
                                             SWITCH_TABLE_MAC_ACL,
                                             SWITCH_TABLE_ECN_ACL,
                                             SWITCH_TABLE_IPV4_MIRROR_ACL,
                                             SWITCH_TABLE_IPV6_MIRROR_ACL};
        switch_table_id_t egress_table[] = {SWITCH_TABLE_EGRESS_IPV4_ACL,
                                            SWITCH_TABLE_EGRESS_IPV6_ACL,
                                            SWITCH_TABLE_MAC_ACL,
                                            SWITCH_TABLE_ECN_ACL,
                                            SWITCH_TABLE_IPV4_MIRROR_ACL,
                                            SWITCH_TABLE_IPV6_MIRROR_ACL};
        for (unsigned i = 0;
             i < sizeof(ingress_table) / sizeof(switch_table_id_t);
             i++) {
          switch_status = switch_api_table_available_count_get(
              device, ingress_table[i], &num_avail);
          status = sai_switch_status_to_sai_status(switch_status);
          if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to get table available count %s",
                          sai_status_to_string(status));
            return status;
          }
          ingress_avail += num_avail;
        }
        for (unsigned i = 0;
             i < sizeof(egress_table) / sizeof(switch_table_id_t);
             i++) {
          switch_status = switch_api_table_available_count_get(
              device, egress_table[i], &num_avail);
          status = sai_switch_status_to_sai_status(switch_status);
          if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to get table available count %s",
                          sai_status_to_string(status));
            return status;
          }
          egress_avail += num_avail;
        }

        /* RACL, ingress and egress system ACL have dedicated tables */
        racl_avail = 0;
        for (tid = SWITCH_TABLE_IPV4_RACL; tid <= SWITCH_TABLE_IPV6_RACL;
             tid++) {
          switch_status =
              switch_api_table_available_count_get(device, tid, &num_avail);
          status = sai_switch_status_to_sai_status(switch_status);
          if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to get table available count for table %s",
                          sai_status_to_string(status));
            return status;
          }
          racl_avail += num_avail;
        }

        /* ingress system */
        system_i_avail = 0;
        switch_status = switch_api_table_available_count_get(
            device, SWITCH_TABLE_SYSTEM_ACL, &system_i_avail);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get table available count for table %s",
                        sai_status_to_string(status));
          return status;
        }

        /* egress system */
        system_e_avail = 0;
        switch_status = switch_api_table_available_count_get(
            device, SWITCH_TABLE_EGRESS_SYSTEM_ACL, &system_e_avail);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get switch table size %s",
                        sai_status_to_string(status));
          return status;
        }

        count = 0;
        aclresource_size = sizeof(sai_acl_resource_t) *
                           attr_list[index1].value.aclresource.count;
        memset(attr_list[index1].value.aclresource.list, 0, aclresource_size);
        for (bpt = SAI_ACL_BIND_POINT_TYPE_PORT;
             bpt <= SAI_ACL_BIND_POINT_TYPE_SWITCH;
             bpt++) {
          for (stage = SAI_ACL_STAGE_INGRESS; stage <= SAI_ACL_STAGE_EGRESS;
               stage++) {
            attr_list[index1].value.aclresource.list[count].bind_point = bpt;
            attr_list[index1].value.aclresource.list[count].stage = stage;
            if (bpt == SAI_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE)
              attr_list[index1].value.aclresource.list[count].avail_num =
                  racl_avail;
            else if (bpt == SAI_ACL_BIND_POINT_TYPE_SWITCH) {
              if (stage == SAI_ACL_STAGE_INGRESS)
                attr_list[index1].value.aclresource.list[count].avail_num =
                    system_i_avail;
              else
                attr_list[index1].value.aclresource.list[count].avail_num =
                    system_e_avail;
            } else {
              attr_list[index1].value.aclresource.list[count].avail_num =
                  stage == SAI_ACL_STAGE_INGRESS ? ingress_avail : egress_avail;
            }
            count++;
          }
        }
      } break;

      default:
        SAI_LOG_ERROR("Switch Get Attribute Not supported %d %s\n",
                      attr_list[index1].id,
                      switch_attr_name[attr_list[index1].id]);
        //        return SAI_STATUS_INVALID_PARAMETER;
        break;
    }
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

sai_status_t sai_create_switch(_Out_ sai_object_id_t *switch_id,
                               _In_ uint32_t attr_count,
                               _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  const sai_attribute_t *attribute;
  sai_status_t status = SAI_STATUS_SUCCESS;
  unsigned index = 0;

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  *switch_id =
      (((unsigned long)SWITCH_HANDLE_TYPE_DEVICE) << SWITCH_HANDLE_TYPE_SHIFT) |
      0x1;

  // switch_api should be initialized here..
  for (index = 0; index < attr_count; index++) {
    attribute = &attr_list[index];
    SAI_LOG_ERROR("Switch attribute create: %s",
                  switch_attr_name[attribute->id]);
    switch (attribute->id) {
      // mandatory create attributes ..
      default:
        status = sai_set_switch_attribute(*switch_id, attribute);
        if (status != SAI_STATUS_SUCCESS) {
        }
    }
  }
  SAI_LOG_EXIT();
  return (sai_status_t)status;
}

sai_status_t sai_remove_switch(_In_ sai_object_id_t switch_id) {
  return SAI_STATUS_NOT_SUPPORTED;
}

sai_port_oper_status_t switch_oper_state_to_sai_oper_state(
    switch_port_oper_status_t oper_status) {
  switch (oper_status) {
    case SWITCH_PORT_OPER_STATUS_UP:
      return SAI_PORT_OPER_STATUS_UP;
    case SWITCH_PORT_OPER_STATUS_DOWN:
      return SAI_PORT_OPER_STATUS_DOWN;
    case SWITCH_PORT_OPER_STATUS_NONE:
    case SWITCH_PORT_OPER_STATUS_UNKNOWN:
    default:
      return SAI_PORT_OPER_STATUS_UNKNOWN;
  }
}

void sai_port_state_change(switch_device_t device,
                           switch_handle_t port_handle,
                           switch_port_oper_status_t oper_status,
                           void *cookie) {
  sai_port_oper_status_notification_t port_sc_notif;

  memset(&port_sc_notif, 0x0, sizeof(port_sc_notif));
  port_sc_notif.port_id = port_handle;
  port_sc_notif.port_state = switch_oper_state_to_sai_oper_state(oper_status);

  if (sai_switch_notifications.on_port_state_change) {
    sai_switch_notifications.on_port_state_change(0x1, &port_sc_notif);
  }

  return;
}

/*
* Switch method table retrieved with sai_api_query()
*/
sai_switch_api_t switch_api = {
    .create_switch = sai_create_switch,
    .remove_switch = sai_remove_switch,
    .set_switch_attribute = sai_set_switch_attribute,
    .get_switch_attribute = sai_get_switch_attribute};

sai_status_t sai_switch_initialize(sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing switch");
  sai_api_service->switch_api = switch_api;
  switch_api_port_state_change_notification_register(
      device, SWITCH_SAI_APP_ID, &sai_port_state_change);
  return SAI_STATUS_SUCCESS;
}
