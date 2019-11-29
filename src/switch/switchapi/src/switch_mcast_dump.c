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

#include "switchapi/switch_mcast.h"

/* Local header includes */
#include "switch_internal.h"
#include "switch_pd.h"

#undef __MODULE__
#define __MODULE__ SWITCH_API_TYPE_MCAST

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

switch_status_t switch_api_mcast_handle_dump_internal(
    const switch_device_t device,
    const switch_handle_t mgid_handle,
    const void *cli_ctx) {
  switch_mcast_info_t *mcast_info = NULL;
  switch_mcast_node_info_t *node_info = NULL;
  switch_mcast_ecmp_info_t *ecmp_node_info = NULL;
  switch_node_t *node = NULL;
  switch_mcast_node_t *mcast_node = NULL;
  switch_uint16_t index = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  SWITCH_ASSERT(SWITCH_MGID_HANDLE(mgid_handle));
  status = switch_mgid_get(device, mgid_handle, &mcast_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "mcast handle dump failed on device %d mgid handle 0x%lx :"
        "mcast get failed:(%s)\n",
        device,
        mgid_handle,
        switch_error_to_string(status));
    return status;
  }

  SWITCH_PRINT(cli_ctx, "\tmgid handle: 0x%lx\n", mgid_handle);
  SWITCH_PRINT(cli_ctx, "\t\tmgrp pd handle: 0x%lx\n", mcast_info->mgrp_hdl);
  SWITCH_PRINT(cli_ctx, "\t\tmcast members: %d\n", mcast_info->mbr_count);
  for (index = 0; index < mcast_info->mbr_count; index++) {
    SWITCH_PRINT(cli_ctx,
                 "\t\t\tnetwork handle: 0x%lx\n",
                 mcast_info->mbrs[index].vlan_handle);
    SWITCH_PRINT(cli_ctx,
                 "\t\t\tintf handle: 0x%lx\n",
                 mcast_info->mbrs[index].intf_handle);
    SWITCH_PRINT(cli_ctx,
                 "\t\t\tmember handle: 0x%lx\n",
                 mcast_info->mbrs[index].member_handle);
  }

  SWITCH_PRINT(cli_ctx,
               "\t\tnode list: %d\n",
               SWITCH_LIST_COUNT(&mcast_info->node_list));
  FOR_EACH_IN_LIST(mcast_info->node_list, node) {
    mcast_node = (switch_mcast_node_t *)node;
    SWITCH_PRINT(cli_ctx, "\t\txid: %d\n", mcast_node->xid);
    SWITCH_PRINT(cli_ctx,
                 "\t\tnode type: %s\n",
                 switch_mcast_node_type_to_string(mcast_node->node_type));
    if (mcast_node->node_type == SWITCH_NODE_TYPE_SINGLE) {
      node_info = &mcast_node->u.node_info;
      SWITCH_PRINT(cli_ctx, "\t\trid: %d\n", node_info->rid);
      SWITCH_PRINT(cli_ctx, "\t\thw entry: 0x%lx\n", node_info->hw_entry);
      SWITCH_PRINT(cli_ctx, "\n");
    } else {
      ecmp_node_info = &mcast_node->u.ecmp_info;
      UNUSED(ecmp_node_info);
    }
  }
  FOR_EACH_IN_LIST_END();
  SWITCH_PRINT(cli_ctx, "\n");

  SWITCH_LOG_DEBUG(
      "mgid handle dump on device %d mgid handle 0x%lx\n", device, mgid_handle);

  SWITCH_LOG_EXIT();

  return status;
}

switch_status_t switch_api_mcast_rid_dump_internal(const switch_device_t device,
                                                   const void *cli_ctx) {
  switch_mcast_context_t *mcast_ctx = NULL;
  switch_rid_info_t *rid_info = NULL;
  switch_rid_t rid = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_MCAST, (void **)&mcast_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "mcast rid dump failed on device %d: "
        "mcast context get failed:(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  FOR_EACH_IN_ARRAY(rid, mcast_ctx->rid_array, switch_rid_info_t, rid_info) {
    UNUSED(rid);
    SWITCH_PRINT(cli_ctx, "\trid: %d\n", rid_info->rid);
    SWITCH_PRINT(cli_ctx, "\t\tref count: %d\n", rid_info->ref_count);
    SWITCH_PRINT(cli_ctx, "\t\trid hw entry: %d\n", rid_info->rid_pd_hdl);
    SWITCH_PRINT(cli_ctx,
                 "\t\trid mcast hw entry: %d\n",
                 rid_info->mcast_egress_ifindex_pd_hdl);
    SWITCH_PRINT(cli_ctx, "\n");
  }
  FOR_EACH_IN_ARRAY_END();

  SWITCH_PRINT(cli_ctx, "\n");
  return status;
}

void switch_mcast_group_table_view_dump_route_info(void *cli_ctx, void *node) {
  if (!cli_ctx || !node) return;

  switch_mcast_group_info_t *group_info = (switch_mcast_group_info_t *)node;
  SWITCH_PRINT(cli_ctx,
               "| 0x%lx | \t%40s\t | \t%40s\t | 0x%lx  | 0x%lx | %d | \n",
               group_info->group_key.handle,
               switch_ipaddress_to_string(&group_info->group_key.src_ip),
               switch_ipaddress_to_string(&group_info->group_key.grp_ip),
               group_info->mgid_handle,
               group_info->rpf_handle,
               group_info->copy_to_cpu);

  return;
}

switch_status_t switch_mcast_route_table_view_dump_internal(
    switch_device_t device, void *cli_ctx) {
  switch_mcast_context_t *mcast_ctx = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_MCAST, (void **)&mcast_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "mcast context dump failed on device %d: "
        "mcast table view dump failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  SWITCH_PRINT(cli_ctx, "\n");
  SWITCH_PRINT(cli_ctx,
               "---------------------------------------------------------------"
               "---------------------------------------------------------------"
               "-----------------------------\n");
  SWITCH_PRINT(cli_ctx,
               "| handle | \t\tsource ip address \t\t\t | \t\t dest ip address "
               "\t\t\t | mgid handle | rpf handle | c2c | \n");
  SWITCH_PRINT(cli_ctx,
               "---------------------------------------------------------------"
               "---------------------------------------------------------------"
               "-----------------------------\n");
  SWITCH_HASHTABLE_ITERATOR(&mcast_ctx->mcast_group_hashtable.table,
                            switch_mcast_group_table_view_dump_route_info,
                            cli_ctx);
  SWITCH_PRINT(cli_ctx,
               "---------------------------------------------------------------"
               "---------------------------------------------------------------"
               "-----------------------------\n");
  return status;
}
#ifdef __cplusplus
}
#endif

switch_status_t switch_api_mcast_handle_dump(const switch_device_t device,
                                             const switch_handle_t mgid_handle,
                                             const void *cli_ctx) {
  SWITCH_MT_WRAP(
      switch_api_mcast_handle_dump_internal(device, mgid_handle, cli_ctx))
}

switch_status_t switch_api_mcast_rid_dump(const switch_device_t device,
                                          const void *cli_ctx) {
  SWITCH_MT_WRAP(switch_api_mcast_rid_dump_internal(device, cli_ctx));
}

switch_status_t switch_mcast_route_table_view_dump(switch_device_t device,
                                                   void *cli_ctx) {
  SWITCH_MT_WRAP(switch_mcast_route_table_view_dump_internal(device, cli_ctx));
}
