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

/* Local header includes */
#include "switch_internal.h"
#include "switch_pd.h"

#undef __MODULE__
#define __MODULE__ SWITCH_API_TYPE_PORT

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

switch_status_t switch_api_port_handle_dump_internal(
    const switch_device_t device,
    const switch_handle_t port_handle,
    const void *cli_ctx) {
  switch_port_info_t *port_info = NULL;
  switch_uint16_t index = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_port_priority_group_t *ppg_info = NULL;

  SWITCH_LOG_ENTER();

  SWITCH_ASSERT(SWITCH_PORT_HANDLE(port_handle));
  if (!SWITCH_PORT_HANDLE(port_handle)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    SWITCH_LOG_ERROR(
        "port dump failed on device %d "
        "port handle %lx: parameters invalid(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_port_get(device, port_handle, &port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port dump failed on device %d "
        "port handle %lx: port get failed(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  SWITCH_PRINT(cli_ctx, "\n\n\tport handle: 0x%lx\n", port_handle);
  SWITCH_PRINT(cli_ctx, "\t\tdevice: %d\n", device);
  SWITCH_PRINT(
      cli_ctx, "\t\tport_lag_index: 0x%x\n", port_info->port_lag_index);
  SWITCH_PRINT(cli_ctx, "\t\tport number %d\n", port_info->port);
  SWITCH_PRINT(cli_ctx, "\t\tnum lanes:%d\n", port_info->lane_list.num_lanes);
  for (index = 0; index < port_info->lane_list.num_lanes; index++) {
    SWITCH_PRINT(
        cli_ctx, "\t\t\tlane %d:%d\n", index, port_info->lane_list.lane[index]);
  }
  SWITCH_PRINT(cli_ctx,
               "\t\tport speed %s\n",
               switch_port_speed_to_string(port_info->port_speed));
  SWITCH_PRINT(cli_ctx,
               "\t\toper status: %s\n",
               switch_port_oper_status_to_string(port_info->oper_status));
  SWITCH_PRINT(
      cli_ctx, "\t\tadmin state: %s\n", port_info->admin_state ? "UP" : "DOWN");

  SWITCH_PRINT(cli_ctx, "\t\tlag handle: 0x%lx\n", port_info->lag_handle);
  SWITCH_PRINT(cli_ctx,
               "\t\tingress acl group handle: 0x%lx\n\n",
               port_info->ingress_acl_group_handle);
  SWITCH_PRINT(cli_ctx,
               "\t\tegress acl group handle: 0x%lx\n\n",
               port_info->egress_acl_group_handle);
  SWITCH_PRINT(cli_ctx,
               "\t\tport type: %s\n",
               switch_port_type_to_string(port_info->port_type));
  SWITCH_PRINT(cli_ctx, "\t\tdev_port: %d\n", port_info->dev_port);
  SWITCH_PRINT(
      cli_ctx, "\t\ttrust dscp: %s\n", port_info->trust_dscp ? "Yes" : "No");
  SWITCH_PRINT(
      cli_ctx, "\t\ttrust pcp: %s\n", port_info->trust_pcp ? "Yes" : "No");
  SWITCH_PRINT(cli_ctx,
               "\t\tauto neg: %s\n",
               switch_port_auto_neg_mode_to_string(port_info->an_mode));
  SWITCH_PRINT(cli_ctx,
               "\t\tlb mode: %s\n",
               switch_port_lb_mode_to_string(port_info->lb_mode));
  SWITCH_PRINT(cli_ctx, "\t\tyid: %d\n", port_info->yid);

  SWITCH_PRINT(cli_ctx, "\t\ttx mtu: %d\n", port_info->tx_mtu);
  SWITCH_PRINT(cli_ctx, "\t\trx mtu: %d\n", port_info->rx_mtu);
  SWITCH_PRINT(cli_ctx, "\t\tmax queues: %d\n", port_info->max_queues);
  SWITCH_PRINT(cli_ctx, "\t\tnum queues: %d\n", port_info->num_queues);
  for (index = 0; index < port_info->num_queues; index++) {
    SWITCH_PRINT(cli_ctx,
                 "\t\t\tqid: %d - handle: 0x%lx\n",
                 index,
                 port_info->queue_handles[index])
  }
  SWITCH_PRINT(cli_ctx,
               "\t\tdefault ppg handle: 0x%lx\n",
               port_info->default_ppg_handle);
  SWITCH_PRINT(cli_ctx, "\t\tnon-default ppgs: %d\n", port_info->num_ppg);
  for (index = 0; index < SWITCH_MAX_PPG; index++) {
    if (port_info->ppg_handles[index] != SWITCH_API_INVALID_HANDLE) {
      switch_ppg_get(device, port_info->ppg_handles[index], &ppg_info);
      SWITCH_PRINT(cli_ctx,
                   "\t\t\tppg: %d - handle: 0x%lx, hw_programmed: %s\n",
                   index,
                   port_info->ppg_handles[index],
                   ppg_info->hw_programmed == TRUE ? "yes" : "no")
    }
  }
  SWITCH_PRINT(
      cli_ctx, "\t\tenable learning: %x\n", port_info->learning_enabled);
  SWITCH_PRINT(
      cli_ctx,
      "\t\tswitching mode: %s\n",
      (port_info->cut_through_mode == true) ? "cut-through" : "store-fwd");

  SWITCH_PRINT(cli_ctx, "\n");

  SWITCH_PRINT(cli_ctx, "\tpd handles\n");
  SWITCH_PRINT(cli_ctx,
               "\t\tingress mapping: 0x%lx\n",
               port_info->ingress_mapping_hw_entry);
  SWITCH_PRINT(cli_ctx,
               "\t\tegress mapping: 0x%lx\n",
               port_info->egress_mapping_hw_entry);
  SWITCH_PRINT(cli_ctx,
               "\t\tingress properties: 0x%lx\n",
               port_info->ingress_prop_hw_entry);
  SWITCH_PRINT(
      cli_ctx, "\t\tingress yid: 0x%lx\n", port_info->ingress_yid_hw_entry);

  SWITCH_PRINT(cli_ctx, "\n");

  SWITCH_LOG_DEBUG(
      "port handle dump on device %d port handle %lx\n", device, port_handle);

  SWITCH_LOG_EXIT();

  return status;
}

switch_status_t switch_api_port_info_by_port_number_dump_internal(
    const switch_device_t device,
    const switch_port_t port,
    const void *cli_ctx) {
  switch_port_context_t *port_ctx = NULL;
  switch_handle_t port_handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_PORT, (void **)&port_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port info port number dump failed on device %d: "
        "port device context get failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  port_handle = port_ctx->port_handles[port];

  if (!SWITCH_PORT_HANDLE(port_handle)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    SWITCH_LOG_ERROR(
        "port info port number dump failed on device %d: "
        "port not added(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_api_port_handle_dump(
      device, port_ctx->port_handles[port], cli_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port info port number dump failed on device %d: "
        "port handle %lx: port handle dump failed(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  return status;
}

switch_status_t switch_api_port_stats_dump_internal(
    const switch_device_t device,
    const switch_handle_t port_handle,
    const void *cli_ctx) {
  switch_port_info_t *port_info = NULL;
  switch_port_counter_id_t port_counter_ids[SWITCH_PORT_STAT_MAX];
  uint64_t port_counters[SWITCH_PORT_STAT_MAX];
  switch_uint32_t index = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  SWITCH_ASSERT(SWITCH_PORT_HANDLE(port_handle));
  if (!SWITCH_PORT_HANDLE(port_handle)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    SWITCH_LOG_ERROR(
        "port dump failed on device %d "
        "port handle %lx: parameters invalid(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_port_get(device, port_handle, &port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port dump failed on device %d "
        "port handle %lx: port get failed(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  SWITCH_MEMSET(port_counters, 0x0, SWITCH_PORT_STAT_MAX * sizeof(uint64_t));
  SWITCH_MEMSET(port_counter_ids,
                0x0,
                SWITCH_PORT_STAT_MAX * sizeof(switch_port_counter_id_t));

  for (index = 0; index < SWITCH_PORT_STAT_MAX; index++) {
    port_counter_ids[index] = (switch_port_counter_id_t)index;
  }

  status = switch_pd_port_stats_get(device,
                                    port_info->dev_port,
                                    SWITCH_PORT_STAT_MAX,
                                    port_counter_ids,
                                    port_counters);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port dump failed on device %d "
        "port handle %lx: port stats get failed(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  SWITCH_PRINT(cli_ctx, "\n\n\tport counters\n");
  for (index = 0; index < SWITCH_PORT_STAT_MAX; index++) {
    SWITCH_PRINT(cli_ctx,
                 "\t\t%s: %" PRIu64 "\n",
                 switch_port_counter_id_to_string(index),
                 port_counters[index]);
  }

  return status;
}

switch_status_t switch_api_port_stats_by_port_number_dump_internal(
    const switch_device_t device,
    const switch_port_t port,
    const void *cli_ctx) {
  switch_port_context_t *port_ctx = NULL;
  switch_handle_t port_handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_device_api_context_get(
      device, SWITCH_API_TYPE_PORT, (void **)&port_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port stats port number dump failed on device %d: "
        "port device context get failed(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  port_handle = port_ctx->port_handles[port];

  if (!SWITCH_PORT_HANDLE(port_handle)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    SWITCH_LOG_ERROR(
        "port stats port number dump failed on device %d: "
        "port not added(%s)\n",
        device,
        switch_error_to_string(status));
    return status;
  }

  status =
      switch_api_port_stats_dump(device, port_ctx->port_handles[port], cli_ctx);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port stats port number dump failed on device %d: "
        "port handle %lx: port stats get failed(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  return status;
}

switch_status_t switch_api_port_storm_control_stats_dump_internal(
    const switch_device_t device,
    const switch_handle_t port_handle,
    const void *cli_ctx) {
  switch_port_info_t *port_info = NULL;
  switch_counter_t counters[SWITCH_COLOR_MAX];
  switch_packet_type_t pkt_type = 0;
  switch_uint16_t index1 = 0;
  switch_uint16_t index2 = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  SWITCH_ASSERT(SWITCH_PORT_HANDLE(port_handle));
  if (!SWITCH_PORT_HANDLE(port_handle)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    SWITCH_LOG_ERROR(
        "port storm control stats dump failed on device %d "
        "port handle 0x%lx: parameters invalid(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_port_get(device, port_handle, &port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_LOG_ERROR(
        "port storm control stats dump failed on device %d "
        "port handle 0x%lx: port get failed(%s)\n",
        device,
        port_handle,
        switch_error_to_string(status));
    return status;
  }

  SWITCH_PRINT(cli_ctx, "\tport storm control stats: 0x%lx\n", port_handle);

  for (index1 = 0; pkt_type < SWITCH_PACKET_TYPE_MAX; index1++) {
    SWITCH_MEMSET(counters, 0x0, SWITCH_COLOR_MAX * sizeof(switch_counter_t));
    pkt_type = 1 << index1;
    if (pkt_type < SWITCH_PACKET_TYPE_MAX) {
      status = switch_api_port_storm_control_stats_get(
          device, port_handle, pkt_type, counters);
      if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_LOG_ERROR(
            "port storm control stats dump failed on device %d "
            "port handle 0x%lx: sc stats get failed(%s)\n",
            device,
            port_handle,
            switch_error_to_string(status));
        return status;
      }

      SWITCH_PRINT(cli_ctx,
                   "\n\t\tpacket type: %s\n",
                   switch_packet_type_to_string(pkt_type));
      for (index2 = 0; index2 < SWITCH_COLOR_MAX; index2++) {
        if (index2 == SWITCH_COLOR_YELLOW) {
          continue;
        }
        SWITCH_PRINT(
            cli_ctx, "\t\tcolor: %s\n", switch_color_to_string(index2));
        SWITCH_PRINT(cli_ctx,
                     "\t\t\tpackets: %" PRIu64 "\n",
                     counters[index2].num_packets);
      }
    }
  }
  SWITCH_PRINT(cli_ctx, "\n");

  return status;
}

#ifdef __cplusplus
}
#endif

switch_status_t switch_api_port_handle_dump(const switch_device_t device,
                                            const switch_handle_t port_handle,
                                            const void *cli_ctx) {
  SWITCH_MT_WRAP(
      switch_api_port_handle_dump_internal(device, port_handle, cli_ctx))
}

switch_status_t switch_api_port_stats_dump(const switch_device_t device,
                                           const switch_handle_t port_handle,
                                           const void *cli_ctx) {
  SWITCH_MT_WRAP(
      switch_api_port_stats_dump_internal(device, port_handle, cli_ctx))
}

switch_status_t switch_api_port_storm_control_stats_dump(
    const switch_device_t device,
    const switch_handle_t port_handle,
    const void *cli_ctx) {
  SWITCH_MT_WRAP(switch_api_port_storm_control_stats_dump_internal(
      device, port_handle, cli_ctx))
}

switch_status_t switch_api_port_stats_by_port_number_dump(
    const switch_device_t device,
    const switch_port_t port,
    const void *cli_ctx) {
  SWITCH_MT_WRAP(
      switch_api_port_stats_by_port_number_dump_internal(device, port, cli_ctx))
}

switch_status_t switch_api_port_info_by_port_number_dump(
    const switch_device_t device,
    const switch_port_t port,
    const void *cli_ctx) {
  SWITCH_MT_WRAP(
      switch_api_port_info_by_port_number_dump_internal(device, port, cli_ctx))
}
