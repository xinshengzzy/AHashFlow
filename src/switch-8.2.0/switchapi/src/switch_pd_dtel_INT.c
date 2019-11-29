/*******************************************************************************
 *
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

#include "switch_internal.h"
#include "switch_pd_dtel.h"

#define ERSPAN_FT_D_OTHER_INT_UP 0x1000
#define ERSPAN_FT_D_OTHER_INT_DOWN 0x1008
#define ERSPAN_FT_D_OTHER_INT_DOWN_QALERT 0x1408
#define ERSPAN_FT_D_OTHER_INT_1HOP 0x1808
#define ERSPAN_FT_D_OTHER_INT_1HOP_QALERT 0x1C08

#if defined(P4_INT_EP_ENABLE) || \
    (defined(P4_INT_TRANSIT_ENABLE) && defined(P4_DTEL_QUEUE_REPORT_ENABLE))
static int bit_count_array[16] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
static int _bit_count(uint64_t val) {
  int i, count;
  count = 0;
  i = 0;
  while (i < (int)sizeof(val) * 2) {
    count += bit_count_array[val & 0xF];
    val >>= 4;
    i++;
  }
  return count;
}
#endif  // P4_INT_EP_ENABLE ||
        // (P4_INT_TRANSIT_ENABLE && P4_DTEL_QUEUE_REPORT_ENABLE)

switch_status_t switch_pd_dtel_int_tables_init(switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_ENABLE

  p4_pd_entry_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

//------------------------------------------------------------------------------
// Ingress Tables
//------------------------------------------------------------------------------

#ifdef P4_INT_EP_ENABLE

  // INT watchlist table
  pd_status = p4_pd_dc_int_watchlist_set_default_action_int_not_watch(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP int_watchlist set default to nop failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  // add sampling threshold values for default percents in registers
  for (int i = 0; i <= 100; i++) {
    uint32_t value = (uint32_t)(0xFFFFFFFFLL * (i / 100.0));
    pd_status = p4_pd_dc_register_write_dtel_int_sample_rate(
        switch_cfg_sess_hdl, p4_pd_device, i, &value);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "DTel watchlist sampling set sample rate register failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }

#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE

  // sup_make_hash_digest table
  // no harm to always pre calculate the digest for bloom fitlers
  pd_status =
      p4_pd_dc_dtel_make_upstream_digest_set_default_action_make_upstream_digest(
          switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP make_hash_digest set default to nop failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  pd_status = switch_pd_dtel_int_ingress_bfilters_init(device);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    goto cleanup;
  }

#endif  // P4_DTEL_FLOW_STATE_TRACK_ENABLE

  pd_status = p4_pd_dc_int_upstream_report_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_upstream_report set default failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

#endif  // P4_INT_EP_ENABLE

//------------------------------------------------------------------------------
// Egress Tables
//------------------------------------------------------------------------------

#if defined(P4_INT_EP_ENABLE) || \
    (defined(P4_INT_TRANSIT_ENABLE) && defined(P4_DTEL_QUEUE_REPORT_ENABLE))
  p4_pd_tbl_prop_value_t prop_val;
  p4_pd_tbl_prop_args_t prop_arg;
  prop_val.scope = PD_ENTRY_SCOPE_SINGLE_PIPELINE;
  prop_arg.value = 0;
  pd_status = p4_pd_dc_int_report_encap_set_property(
      switch_cfg_sess_hdl, device, PD_TABLE_ENTRY_SCOPE, prop_val, prop_arg);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT int_report_encap set property failed on device %d\n", device);
    goto cleanup;
  }
#endif  // P4_INT_EP_ENABLE ||
        // (P4_INT_TRANSIT_ENABLE && P4_DTEL_QUEUE_REPORT_ENABLE)

#ifdef P4_INT_EP_ENABLE

  pd_status = p4_pd_dc_int_set_sink_set_default_action_int_sink_disable(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_set_sink set default disable action failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  pd_status = p4_pd_dc_int_edge_ports_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP edge port set default entry on device %d : table %s action "
        "%s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE
  pd_status =
      p4_pd_dc_dtel_make_local_digest_set_default_action_make_local_digest(
          switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP make_local_digest set default failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
#endif  // P4_DTEL_FLOW_STATE_TRACK_ENABLE

#ifdef P4_INT_DIGEST_ENABLE
  // int_diget_insert default
  pd_status = p4_pd_dc_int_digest_insert_set_default_action_update_int_digest(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP int_digest_insert set default failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
#endif  // P4_INT_DIGEST_ENABLE
  {
    int max_pipes = SWITCH_MAX_PIPES;
    switch_device_max_pipes_get(device, &max_pipes);
    for (int pipe = 0; pipe < max_pipes; pipe++) {
      p4_pd_device.dev_pipe_id = pipe;
      pd_status = p4_pd_dc_int_report_encap_set_default_action_nop(
          switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "INT EP int_report_encap default action failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    }
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  }

  pd_status = p4_pd_dc_int_sink_local_report_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_sink_local_report table set default action failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

#ifdef P4_INT_L45_DSCP_ENABLE
  pd_status = p4_pd_dc_dtel_intl45_set_dscp_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP dtel_intl45_set_dscp set default action failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  // intl45_dscp int_inport pvs set_property calls
  p4_pd_pvs_prop_value_t prop_value;
  p4_pd_pvs_prop_args_t prop_args;
  prop_args.gress = PD_PVS_GRESS_INGRESS;

  prop_value.gress_scope = PD_PVS_SCOPE_SINGLE_GRESS;
  pd_status = p4_pd_dc_int_inport_set_property(
      switch_cfg_sess_hdl, device, PD_PVS_GRESS_SCOPE, prop_value, prop_args);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value set gress scope failed on device %d\n",
        device);
    goto cleanup;
  }

  prop_value.pipe_scope = PD_PVS_SCOPE_SINGLE_PIPELINE;
  pd_status = p4_pd_dc_int_inport_set_property(
      switch_cfg_sess_hdl, device, PD_PVS_PIPE_SCOPE, prop_value, prop_args);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value set pipe scope failed on device %d\n",
        device);
    goto cleanup;
  }

  prop_value.parser_scope = PD_PVS_SCOPE_SINGLE_PARSER;
  pd_status = p4_pd_dc_int_inport_set_property(
      switch_cfg_sess_hdl, device, PD_PVS_PARSER_SCOPE, prop_value, prop_args);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value set parser scope failed on device %d\n",
        device);
    goto cleanup;
  }
#endif  // P4_INT_L45_DSCP_ENABLE

#endif  // P4_INT_EP_ENABLE

#ifdef P4_INT_L45_MARKER_ENABLE
  p4_pd_pvs_prop_value_t prop_value;
  p4_pd_pvs_prop_args_t prop_args;
  prop_args.gress = PD_PVS_GRESS_ALL;
  int index;

  // intl45_marker set_property calls for 4 * (udp, tcp, icmp)
  switch_pd_status_t (
      *intl45_marker_set_property[DTEL_INT_L45_MARKER_VALUES])() = {
      p4_pd_dc_intl45_marker_udp0_set_property,
      p4_pd_dc_intl45_marker_udp1_set_property,
      p4_pd_dc_intl45_marker_udp2_set_property,
      p4_pd_dc_intl45_marker_udp3_set_property,
      p4_pd_dc_intl45_marker_tcp0_set_property,
      p4_pd_dc_intl45_marker_tcp1_set_property,
      p4_pd_dc_intl45_marker_tcp2_set_property,
      p4_pd_dc_intl45_marker_tcp3_set_property,
      p4_pd_dc_intl45_marker_icmp0_set_property,
      p4_pd_dc_intl45_marker_icmp1_set_property,
      p4_pd_dc_intl45_marker_icmp2_set_property,
      p4_pd_dc_intl45_marker_icmp3_set_property};

  prop_value.gress_scope = PD_PVS_SCOPE_ALL_GRESS;
  for (index = 0; index < DTEL_INT_L45_MARKER_VALUES; index++) {
    pd_status = intl45_marker_set_property[index](
        switch_cfg_sess_hdl, device, PD_PVS_GRESS_SCOPE, prop_value, prop_args);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT L45 marker parser value set gress scope failed "
          "on device %d\n",
          device);
      goto cleanup;
    }
  }

  prop_value.pipe_scope = PD_PVS_SCOPE_ALL_PIPELINES;
  for (index = 0; index < DTEL_INT_L45_MARKER_VALUES; index++) {
    pd_status = intl45_marker_set_property[index](
        switch_cfg_sess_hdl, device, PD_PVS_PIPE_SCOPE, prop_value, prop_args);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT L45 marker parser value set pipe scope failed "
          "on device %d\n",
          device);
      goto cleanup;
    }
  }

  prop_value.parser_scope = PD_PVS_SCOPE_ALL_PARSERS_IN_PIPE;
  for (index = 0; index < DTEL_INT_L45_MARKER_VALUES; index++) {
    pd_status = intl45_marker_set_property[index](switch_cfg_sess_hdl,
                                                  device,
                                                  PD_PVS_PARSER_SCOPE,
                                                  prop_value,
                                                  prop_args);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT L45 marker parser value set parser scope failed "
          "on device %d\n",
          device);
      goto cleanup;
    }
  }
#endif  // P4_INT_L45_MARKER_ENABLE

#ifdef P4_INT_TRANSIT_ENABLE
#ifdef P4_INT_DIGEST_ENABLE
  // int_diget_encode default
  pd_status = p4_pd_dc_int_digest_encode_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit int_digest_encode set default to nop failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
#endif  // P4_INT_DIGEST_ENABLE
#endif  // P4_INT_TRANSIT_ENABLE

  {
    p4_pd_tbl_prop_value_t prop_value;
    prop_value.value = PD_DUPLICATE_ENTRY_CHECK_ENABLE;
    p4_pd_tbl_prop_args_t prop_args;
    prop_args.value = 0;
    pd_status = p4_pd_dc_int_inst_0003_set_property(switch_cfg_sess_hdl,
                                                    device,
                                                    PD_DUPLICATE_ENTRY_CHECK,
                                                    prop_value,
                                                    prop_args);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT int_inst_0003 set property failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }

  pd_status = p4_pd_dc_int_inst_0003_set_default_action_int_set_header_0003_i0(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit int instruction 0003 set default to nop failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  pd_status = p4_pd_dc_int_inst_0407_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit int instruction 0407 set default to nop failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  pd_status = p4_pd_dc_dtel_int_ig_port_convert_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "DTel int ingress_port convert set default failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  pd_status = p4_pd_dc_dtel_int_eg_port_convert_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "DTel int ingress_port convert set default failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  pd_status = p4_pd_dc_int_outer_encap_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "DTel int_outer_encap set default failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:

  status = switch_pd_status_to_status(pd_status);
  p4_pd_complete_operations(switch_cfg_sess_hdl);

#endif  // P4_INT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT add default entries success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT add default entries failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

//------------------------------------------------------------------------------
// EP or TRANSIT
//------------------------------------------------------------------------------

switch_status_t switch_pd_dtel_int_update_switch_id_instruction(
    switch_device_t device, switch_uint32_t switch_id) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(switch_id);
  UNUSED(status);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_int_inst_0003_match_spec_t match_0003_spec;
  {
    p4_pd_dc_int_set_header_0003_i8_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 8;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i8_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i9_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 9;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i9_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i10_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 10;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i10_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i11_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 11;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i11_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i12_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 12;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i12_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i13_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 13;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i13_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i14_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 14;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i14_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i15_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 15;
    pd_status =
        p4_pd_dc_int_inst_0003_table_modify_with_int_set_header_0003_i15_by_match_spec(
            switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

cleanup_0003:
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR("INT set switch ID failed on device %d\n", device);
  }

  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_ENABLE
#endif  // SWITCH_PD
  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT set switch ID success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR("INT set switch ID failed on device %d : %s (pd: 0x%x)",
                        device,
                        switch_error_to_string(status),
                        pd_status);
  }
  return status;
}

switch_status_t switch_pd_dtel_intl45_diffserv_parser_value_set(
    switch_device_t device,
    switch_uint8_t value,
    switch_uint8_t mask,
    switch_pd_pvs_hdl_t *pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(value);
  UNUSED(mask);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_DSCP_ENABLE
  value <<= 2;
  mask <<= 2;

  p4_pd_pvs_prop_value_t prop_value;
  p4_pd_pvs_prop_args_t prop_args;
  prop_args.gress = PD_PVS_GRESS_ALL;

  prop_value.gress_scope = PD_PVS_SCOPE_ALL_GRESS;
  pd_status = p4_pd_dc_int_diffserv_set_property(
      switch_cfg_sess_hdl, device, PD_PVS_GRESS_SCOPE, prop_value, prop_args);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value set gress scope failed "
        "on device %d\n",
        device);
    goto cleanup;
  }

  prop_value.pipe_scope = PD_PVS_SCOPE_ALL_PIPELINES;
  pd_status = p4_pd_dc_int_diffserv_set_property(
      switch_cfg_sess_hdl, device, PD_PVS_PIPE_SCOPE, prop_value, prop_args);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value set pipe scope failed "
        "on device %d\n",
        device);
    goto cleanup;
  }

  prop_value.parser_scope = PD_PVS_SCOPE_ALL_PARSERS_IN_PIPE;
  pd_status = p4_pd_dc_int_diffserv_set_property(
      switch_cfg_sess_hdl, device, PD_PVS_PARSER_SCOPE, prop_value, prop_args);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value set parser scope failed "
        "on device %d\n",
        device);
    goto cleanup;
  }

  p4_pd_dev_parser_target_t p4_pd_parser;
  p4_pd_parser.device_id = device;
  p4_pd_parser.gress_id = PD_PVS_GRESS_ALL;
  p4_pd_parser.dev_pipe_id = PD_DEV_PIPE_ALL;
  p4_pd_parser.parser_id = BF_DEV_PIPE_PARSER_ALL;

  pd_status = p4_pd_dc_int_diffserv_entry_add(
      switch_cfg_sess_hdl, p4_pd_parser, value, mask, pvs_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR("INT L45 DSCP parser value set failed on device %d\n",
                        device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT L45 DSCP parser value set success on device %d\n",
                        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value set failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_diffserv_parser_value_modify(
    switch_device_t device,
    switch_uint8_t value,
    switch_uint8_t mask,
    switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(value);
  UNUSED(mask);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_DSCP_ENABLE
  value <<= 2;
  mask <<= 2;

  pd_status = p4_pd_dc_int_diffserv_entry_modify(
      switch_cfg_sess_hdl, device, pvs_hdl, value, mask);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value modify failed on device %d\n", device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 DSCP parser value modify success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value modify failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_diffserv_parser_value_delete(
    switch_device_t device, switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_DSCP_ENABLE

  pd_status =
      p4_pd_dc_int_diffserv_entry_delete(switch_cfg_sess_hdl, device, pvs_hdl);

  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value delete failed on device %d\n", device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 DSCP parser value delete success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 DSCP parser value delete failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_edge_port_parser_value_set(
    switch_device_t device, switch_port_t port, switch_pd_pvs_hdl_t *pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(port);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  uint32_t pipe_id;
  uint8_t parser_id;
  pd_status = p4_pd_pipe_id_get(device, port, &pipe_id);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value set failed on device %d, "
        "could not get pipe_id\n",
        device);
    goto cleanup;
  }
  pd_status = p4_pd_parser_id_get(device, port, &parser_id);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value set failed on device %d, "
        "could not get parser_id\n",
        device);
    goto cleanup;
  }

  p4_pd_dev_parser_target_t p4_pd_parser;
  p4_pd_parser.device_id = device;
  p4_pd_parser.gress_id = PD_PVS_GRESS_INGRESS;
  p4_pd_parser.dev_pipe_id = pipe_id;
  p4_pd_parser.parser_id = parser_id;

  switch_uint32_t mask = 0x1FF;

  pd_status = p4_pd_dc_int_inport_entry_add(
      switch_cfg_sess_hdl, p4_pd_parser, port, mask, pvs_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value set failed on device %d\n", device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 edge port parser value set success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value set failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_edge_port_parser_value_delete(
    switch_device_t device, switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  pd_status =
      p4_pd_dc_int_inport_entry_delete(switch_cfg_sess_hdl, device, pvs_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value delete failed on device %d\n", device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 edge port parser value delete success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 edge port parser value delete failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_icmp_marker_parser_value_set(
    switch_device_t device,
    switch_int8_t index,
    switch_uint64_t marker,
    switch_pd_pvs_hdl_t *pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(marker);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  p4_pd_dev_parser_target_t p4_pd_parser;
  p4_pd_parser.device_id = device;
  p4_pd_parser.gress_id = PD_PVS_GRESS_ALL;
  p4_pd_parser.dev_pipe_id = PD_DEV_PIPE_ALL;
  p4_pd_parser.parser_id = BF_DEV_PIPE_PARSER_ALL;
  switch_uint16_t mask = 0xffff;

  switch (index) {
    case 0:
      // icmp ignore the low 16 bit (typecode)
      pd_status = p4_pd_dc_intl45_marker_icmp0_entry_add(
          switch_cfg_sess_hdl,
          p4_pd_parser,
          ((switch_uint32_t)(marker >> 48)) << 16,
          ((switch_uint32_t)mask) << 16,
          pvs_hdl);
      break;
    case 1:
      pd_status = p4_pd_dc_intl45_marker_icmp1_entry_add(
          switch_cfg_sess_hdl,
          p4_pd_parser,
          (switch_uint16_t)(marker >> 32),
          mask,
          pvs_hdl);
      break;
    case 2:
      pd_status = p4_pd_dc_intl45_marker_icmp2_entry_add(
          switch_cfg_sess_hdl,
          p4_pd_parser,
          (switch_uint16_t)(marker >> 16),
          mask,
          pvs_hdl);
      break;
    case 3:
      pd_status =
          p4_pd_dc_intl45_marker_icmp3_entry_add(switch_cfg_sess_hdl,
                                                 p4_pd_parser,
                                                 (switch_uint16_t)(marker >> 0),
                                                 mask,
                                                 pvs_hdl);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 ICMP-marker parser value add entry failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 ICMP-marker-%d parser value set failed on device %d\n",
        index,
        device);
    goto cleanup;
  }
cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 ICMP-marker parser value set success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 ICMP-marker parser value set failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_icmp_marker_parser_value_modify(
    switch_device_t device,
    switch_uint8_t index,
    switch_uint64_t marker,
    switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(marker);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  switch_uint16_t mask = 0xffff;
  switch (index) {
    case 0:
      // icmp ignore the low 16 bit (typecode)
      pd_status = p4_pd_dc_intl45_marker_icmp0_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          ((switch_uint32_t)(marker >> 48)) << 16,
          ((switch_uint32_t)mask) << 16);
      break;
    case 1:
      pd_status = p4_pd_dc_intl45_marker_icmp1_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 32),
          mask);
      break;
    case 2:
      pd_status = p4_pd_dc_intl45_marker_icmp2_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 16),
          mask);
      break;
    case 3:
      pd_status = p4_pd_dc_intl45_marker_icmp3_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 0),
          mask);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 ICMP-marker parser value modify failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 ICMP-marker-%d parser value modify failed on device %d\n",
        index,
        device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 ICMP-marker parser value modify success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 ICMP-marker parser value modify failure on device %d : %s "
        "(pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_icmp_marker_parser_value_delete(
    switch_device_t device, switch_uint8_t index, switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  switch (index) {
    case 0:
      pd_status = p4_pd_dc_intl45_marker_icmp0_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 1:
      pd_status = p4_pd_dc_intl45_marker_icmp1_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 2:
      pd_status = p4_pd_dc_intl45_marker_icmp2_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 3:
      pd_status = p4_pd_dc_intl45_marker_icmp3_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 ICMP-marker parser value delete failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 ICMP-marker-%d parser value delete failed on device %d\n",
        index,
        device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 ICMP-marker parser value delete success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 ICMP-marker parser value delete failure on device %d : %s "
        "(pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_tcp_marker_parser_value_set(
    switch_device_t device,
    switch_int8_t index,
    switch_int16_t port,
    switch_int16_t port_mask,
    switch_uint64_t marker,
    switch_pd_pvs_hdl_t *pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(port);
  UNUSED(port_mask);
  UNUSED(marker);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  p4_pd_dev_parser_target_t p4_pd_parser;
  p4_pd_parser.device_id = device;
  p4_pd_parser.gress_id = PD_PVS_GRESS_ALL;
  p4_pd_parser.dev_pipe_id = PD_DEV_PIPE_ALL;
  p4_pd_parser.parser_id = BF_DEV_PIPE_PARSER_ALL;
  switch_uint32_t mask = 0xffff;

  switch (index) {
    case 0:
      pd_status = p4_pd_dc_intl45_marker_tcp0_entry_add(
          switch_cfg_sess_hdl,
          p4_pd_parser,
          (switch_uint32_t)((0xffff & (marker >> 48)) << 16) |
              (port & port_mask),
          (mask << 16) | port_mask,
          pvs_hdl);
      break;
    case 1:
      pd_status =
          p4_pd_dc_intl45_marker_tcp1_entry_add(switch_cfg_sess_hdl,
                                                p4_pd_parser,
                                                (switch_uint16_t)(marker >> 32),
                                                mask,
                                                pvs_hdl);
      break;
    case 2:
      pd_status =
          p4_pd_dc_intl45_marker_tcp2_entry_add(switch_cfg_sess_hdl,
                                                p4_pd_parser,
                                                (switch_uint16_t)(marker >> 16),
                                                mask,
                                                pvs_hdl);
      break;
    case 3:
      pd_status =
          p4_pd_dc_intl45_marker_tcp3_entry_add(switch_cfg_sess_hdl,
                                                p4_pd_parser,
                                                (switch_uint16_t)(marker >> 0),
                                                mask,
                                                pvs_hdl);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 TCP-marker parser value add entry failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 TCP-marker-%d parser value set failed on device %d\n",
        index,
        device);
    goto cleanup;
  }
cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 TCP-marker parser value set success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 TCP-marker parser value set failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_tcp_marker_parser_value_modify(
    switch_device_t device,
    switch_uint8_t index,
    switch_int16_t port,
    switch_int16_t port_mask,
    switch_uint64_t marker,
    switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(port);
  UNUSED(port_mask);
  UNUSED(marker);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  switch_uint32_t mask = 0xffff;
  switch (index) {
    case 0:
      pd_status = p4_pd_dc_intl45_marker_tcp0_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint32_t)((0xffff & (marker >> 48)) << 16) |
              (port & port_mask),
          (mask << 16) | port_mask);
      break;
    case 1:
      pd_status = p4_pd_dc_intl45_marker_tcp1_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 32),
          mask);
      break;
    case 2:
      pd_status = p4_pd_dc_intl45_marker_tcp2_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 16),
          mask);
      break;
    case 3:
      pd_status = p4_pd_dc_intl45_marker_tcp3_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 0),
          mask);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 TCP-marker parser value modify failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 TCP-marker-%d parser value modify failed on device %d\n",
        index,
        device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 TCP-marker parser value modify success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 TCP-marker parser value modify failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_tcp_marker_parser_value_delete(
    switch_device_t device, switch_uint8_t index, switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  switch (index) {
    case 0:
      pd_status = p4_pd_dc_intl45_marker_tcp0_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 1:
      pd_status = p4_pd_dc_intl45_marker_tcp1_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 2:
      pd_status = p4_pd_dc_intl45_marker_tcp2_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 3:
      pd_status = p4_pd_dc_intl45_marker_tcp3_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 TCP-marker parser value delete failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 TCP-marker-%d parser value delete failed on device %d\n",
        index,
        device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 TCP-marker parser value delete success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 TCP-marker parser value delete failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_udp_marker_parser_value_set(
    switch_device_t device,
    switch_int8_t index,
    switch_int16_t port,
    switch_int16_t port_mask,
    switch_uint64_t marker,
    switch_pd_pvs_hdl_t *pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(port);
  UNUSED(port_mask);
  UNUSED(marker);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE

  p4_pd_dev_parser_target_t p4_pd_parser;
  p4_pd_parser.device_id = device;
  p4_pd_parser.gress_id = PD_PVS_GRESS_ALL;
  p4_pd_parser.dev_pipe_id = PD_DEV_PIPE_ALL;
  p4_pd_parser.parser_id = BF_DEV_PIPE_PARSER_ALL;
  switch_uint32_t mask = 0xffff;

  switch (index) {
    case 0:
      pd_status = p4_pd_dc_intl45_marker_udp0_entry_add(
          switch_cfg_sess_hdl,
          p4_pd_parser,
          (switch_uint32_t)((0xffff & (marker >> 48)) << 16) |
              (port & port_mask),
          (mask << 16) | port_mask,
          pvs_hdl);
      break;
    case 1:
      pd_status =
          p4_pd_dc_intl45_marker_udp1_entry_add(switch_cfg_sess_hdl,
                                                p4_pd_parser,
                                                (switch_uint16_t)(marker >> 32),
                                                mask,
                                                pvs_hdl);
      break;
    case 2:
      pd_status =
          p4_pd_dc_intl45_marker_udp2_entry_add(switch_cfg_sess_hdl,
                                                p4_pd_parser,
                                                (switch_uint16_t)(marker >> 16),
                                                mask,
                                                pvs_hdl);
      break;
    case 3:
      pd_status =
          p4_pd_dc_intl45_marker_udp3_entry_add(switch_cfg_sess_hdl,
                                                p4_pd_parser,
                                                (switch_uint16_t)(marker >> 0),
                                                mask,
                                                pvs_hdl);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 UDP-marker parser value add entry failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 UDP-marker-%d parser value set failed on device %d\n",
        index,
        device);
    goto cleanup;
  }
cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 UDP-marker parser value set success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 UDP-marker parser value set failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_udp_marker_parser_value_modify(
    switch_device_t device,
    switch_uint8_t index,
    switch_int16_t port,
    switch_int16_t port_mask,
    switch_uint64_t marker,
    switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(port);
  UNUSED(port_mask);
  UNUSED(marker);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  switch_uint32_t mask = 0xffff;
  switch (index) {
    case 0:
      pd_status = p4_pd_dc_intl45_marker_udp0_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint32_t)((0xffff & (marker >> 48)) << 16) |
              (port & port_mask),
          (mask << 16) | port_mask);
      break;
    case 1:
      pd_status = p4_pd_dc_intl45_marker_udp1_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 32),
          mask);
      break;
    case 2:
      pd_status = p4_pd_dc_intl45_marker_udp2_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 16),
          mask);
      break;
    case 3:
      pd_status = p4_pd_dc_intl45_marker_udp3_entry_modify(
          switch_cfg_sess_hdl,
          device,
          pvs_hdl,
          (switch_uint16_t)(marker >> 0),
          mask);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 UDP-marker parser value modify failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 UDP-marker-%d parser value modify failed on device %d\n",
        index,
        device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 UDP-marker parser value modify success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 UDP-marker parser value modify failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_udp_marker_parser_value_delete(
    switch_device_t device, switch_uint8_t index, switch_pd_pvs_hdl_t pvs_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(index);
  UNUSED(pvs_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_L45_MARKER_ENABLE
  switch (index) {
    case 0:
      pd_status = p4_pd_dc_intl45_marker_udp0_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 1:
      pd_status = p4_pd_dc_intl45_marker_udp1_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 2:
      pd_status = p4_pd_dc_intl45_marker_udp2_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    case 3:
      pd_status = p4_pd_dc_intl45_marker_udp3_entry_delete(
          switch_cfg_sess_hdl, device, pvs_hdl);
      break;
    default:
      SWITCH_PD_LOG_ERROR(
          "INT L45 UDP-marker parser value delete failed on device %d,"
          " Invalid index %d\n",
          device,
          index);
      goto cleanup;
      break;
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT L45 UDP-marker-%d parser value delete failed on device %d\n",
        index,
        device);
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // SWITCH_PD
#endif  // P4_INT_L45_MARKER_ENABLE

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT L45 UDP-marker parser value delete success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT L45 UDP-marker parser value delete failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_ig_port_convert_set(switch_device_t device,
                                                       switch_port_t in_port,
                                                       switch_port_t out_port) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  SWITCH_FAST_RECONFIG(device)

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(in_port);
  UNUSED(out_port);

#ifdef SWITCH_PD

#ifdef P4_INT_ENABLE
  switch_pd_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  switch_pd_hdl_t entry_hdl;

  p4_pd_dc_dtel_int_ig_port_convert_match_spec_t match_spec;
  p4_pd_dc_int_ig_port_convert_action_spec_t action_spec;
  match_spec.int_port_ids_header_ingress_port_id = in_port;
  action_spec.action_port = out_port;
  pd_status =
      p4_pd_dc_dtel_int_ig_port_convert_table_add_with_int_ig_port_convert(
          switch_cfg_sess_hdl,
          p4_pd_device,
          &match_spec,
          &action_spec,
          &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "DTel int ingress_port convert add entery failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "DTel int ingress_port convert add success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "DTel int ingress_port add failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_eg_port_convert_set(switch_device_t device,
                                                       switch_port_t in_port,
                                                       switch_port_t out_port) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(in_port);
  UNUSED(out_port);

#ifdef SWITCH_PD

#ifdef P4_INT_ENABLE
  switch_pd_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  switch_pd_hdl_t entry_hdl;

  p4_pd_dc_dtel_int_eg_port_convert_match_spec_t match_spec;
  p4_pd_dc_int_eg_port_convert_action_spec_t action_spec;
  match_spec.int_port_ids_header_egress_port_id = in_port;
  action_spec.action_port = out_port;
  pd_status =
      p4_pd_dc_dtel_int_eg_port_convert_table_add_with_int_eg_port_convert(
          switch_cfg_sess_hdl,
          p4_pd_device,
          &match_spec,
          &action_spec,
          &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "DTel int egress_port convert add entery failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "DTel int egress_port convert add success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "DTel int egress_port add failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

//------------------------------------------------------------------------------
// TRANSIT
//------------------------------------------------------------------------------

switch_status_t switch_pd_dtel_int_transit_enable(switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_TRANSIT_ENABLE

  switch_pd_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  pd_status = p4_pd_dc_int_transit_set_default_action_adjust_insert_byte_cnt(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit enabling int_transit table by settting default action "
        "failed on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_TRANSIT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT enabling int_transit success on device %d\n",
                        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT enabling int_transit failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_transit_disable(switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_TRANSIT_ENABLE

  switch_pd_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  pd_status = p4_pd_dc_int_transit_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit disabling int_transit table by settting default action to "
        "nop failed on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_TRANSIT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT disabling int_transit success on device %d\n",
                        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT disabling int_transit failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_digest_encode_enable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#if defined(P4_INT_TRANSIT_ENABLE) && defined(P4_INT_DIGEST_ENABLE)
  switch_pd_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_int_digest_encode_match_spec_t match_spec;
  match_spec.int_header_d = 1;
  pd_status = p4_pd_dc_int_digest_encode_table_add_with_update_int_digest(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit enabling int_digest_encode table failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_TRANSIT_ENABLE && P4_INT_DIGEST_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT enabling int digest encode success on device %d\n",
                        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT enabling int digest encode failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_digest_encode_disable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  switch_pd_hdl_t entry_hdl;

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#if defined(P4_INT_TRANSIT_ENABLE) && defined(P4_INT_DIGEST_ENABLE)
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  int index = 0;
  while (index >= 0) {
    pd_status = p4_pd_dc_int_digest_encode_get_first_entry_handle(
        switch_cfg_sess_hdl, p4_pd_device, &index);

    if (pd_status == SWITCH_PD_OBJ_NOT_FOUND) {
      pd_status = SWITCH_PD_STATUS_SUCCESS;
      break;
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Transit deleting an entry from int_digest_encode failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    if (index >= 0) {
      entry_hdl = (switch_pd_hdl_t)index;
      pd_status = p4_pd_dc_int_digest_encode_table_delete(
          switch_cfg_sess_hdl, device, entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "INT Transit deleting an entry from int_digest_encode failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    }
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_TRANSIT_ENABLE && P4_INT_DIGEST_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT disabling int digest encode success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT disabling int digest encode failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_transit_qalert_add(switch_device_t device,
                                                      switch_uint8_t dscp) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(dscp);

#ifdef SWITCH_PD
#if defined(P4_INT_TRANSIT_ENABLE) && defined(P4_DTEL_QUEUE_REPORT_ENABLE)

  switch_pd_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_do_int_transit_qalert_set_flow_action_spec_t action_spec;
  p4_pd_dc_int_transit_qalert_match_spec_t match_spec;
  match_spec.int_header_valid = 1;
  action_spec.action_dscp_report = dscp;
  action_spec.action_path_tracking_flow = 1;
  pd_status =
      p4_pd_dc_int_transit_qalert_table_add_with_do_int_transit_qalert_set_flow(
          switch_cfg_sess_hdl,
          p4_pd_device,
          &match_spec,
          &action_spec,
          &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit adding entry to int_transit_qalert table failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  /*
    match_spec.int_header_valid = 0; */
  action_spec.action_path_tracking_flow = 0;
  action_spec.action_dscp_report = dscp;
  pd_status =
      p4_pd_dc_int_transit_qalert_set_default_action_do_int_transit_qalert_set_flow(
          switch_cfg_sess_hdl, p4_pd_device, &action_spec, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit adding entry to int_transit_qalert table failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT adding to int_transit_qalert success "
        "on device %d 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT adding to int_transit_qalert failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }
#endif  // P4_INT_TRANSIT_ENABLE && P4_DTEL_QUEUE_REPORT_ENABLE
#endif  // SWITCH_PD

  return status;
}

switch_status_t switch_pd_dtel_int_transit_qalert_delete(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_TRANSIT_ENABLE) && defined(P4_DTEL_QUEUE_REPORT_ENABLE)

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_int_transit_qalert_match_spec_t match_spec;
  match_spec.int_header_valid = 1;
  pd_status = p4_pd_dc_int_transit_qalert_table_delete_by_match_spec(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit int_transit_qalert table delete entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_TRANSIT_ENABLE && P4_DTEL_QUEUE_REPORT_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT int_transit_qalert table delete entry success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT int_transit_qalert table delete entry failure on device %d : %s "
        "(pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_meta_header_update_end_enable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  switch_pd_hdl_t entry_hdl;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD

#ifdef P4_INT_TRANSIT_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  pd_status =
      p4_pd_dc_int_meta_header_update_end_set_default_action_int_set_e_bit(
          switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit enabling int_meta_header_update_end table failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT enabling int_meta_header_update_end success "
        "on device %d 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT enabling int_meta_header_update_end failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

#endif  // P4_INT_TRANSIT_ENABLE

#endif  // SWITCH_PD

  return status;
}

switch_status_t switch_pd_dtel_int_meta_header_update_end_disable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  switch_pd_hdl_t entry_hdl = SWITCH_PD_INVALID_HANDLE;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD

#ifdef P4_INT_TRANSIT_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  pd_status = p4_pd_dc_int_meta_header_update_end_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit disabling int_meta_header_update_end table by settting "
        "default action to nop failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_TRANSIT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT disabling int_meta_header_update_end success "
        "on device %d 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT disabling int_meta_header_update_end failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_enable_int_inst(switch_device_t device,
                                                   switch_uint32_t switch_id) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_ENABLE

  switch_pd_hdl_t entry_hdl;
  int i;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  pd_status = p4_pd_dc_int_inst_0003_set_default_action_int_set_header_0003_i0(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT int_inst_0003 set default action failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  // int_inst_0003 table
  switch_pd_status_t (*int_inst_0003_table_actions[7])() = {
      p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i1,
      p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i2,
      p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i3,
      p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i4,
      p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i5,
      p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i6,
      p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i7};

  p4_pd_dc_int_inst_0003_match_spec_t match_0003_spec;
  for (i = 0; i < 7; i++) {
    match_0003_spec.int_header_instruction_bitmap_0003 = i + 1;
    pd_status = int_inst_0003_table_actions[i](
        switch_cfg_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i8_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 8;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i8(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i9_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 9;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i9(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i10_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 10;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i10(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i11_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 11;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i11(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i12_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 12;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i12(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i13_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 13;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i13(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i14_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 14;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i14(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

  {
    p4_pd_dc_int_set_header_0003_i15_action_spec_t action_spec;
    action_spec.action_switch_id = switch_id;
    match_0003_spec.int_header_instruction_bitmap_0003 = 15;
    pd_status = p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i15(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_0003_spec,
        &action_spec,
        &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      goto cleanup_0003;
    }
  }

cleanup_0003:
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT add action for instruction 0-3 %d failed "
        "on device %d : table %s action %s\n",
        i,
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  // int_inst_0407 table
  pd_status = p4_pd_dc_int_inst_0407_set_default_action_int_header_update(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);

  p4_pd_dc_int_inst_0407_match_spec_t match_0407_spec;
  match_0407_spec.int_header_instruction_bitmap_0407 = 0x4;
  match_0407_spec.int_header_instruction_bitmap_0407_mask = 0xC;
  pd_status = p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i4(
      switch_cfg_sess_hdl, p4_pd_device, &match_0407_spec, 1, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT add action for instruction 4-7 %d failed "
        "on device %d : table %s action %s\n",
        0x4,
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  match_0407_spec.int_header_instruction_bitmap_0407 = 0x8;
  match_0407_spec.int_header_instruction_bitmap_0407_mask = 0xC;
  pd_status = p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i8(
      switch_cfg_sess_hdl, p4_pd_device, &match_0407_spec, 1, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT add action for instruction 4-7 %d failed "
        "on device %d : table %s action %s\n",
        0x8,
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  match_0407_spec.int_header_instruction_bitmap_0407 = 0xC;
  match_0407_spec.int_header_instruction_bitmap_0407_mask = 0xC;
  pd_status = p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i12(
      switch_cfg_sess_hdl, p4_pd_device, &match_0407_spec, 1, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT add action for instruction 4-7 %d failed "
        "on device %d : table %s action %s\n",
        0xC,
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT configuring int instructions success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT configuring int instructions failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_disable_int_inst(switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_ENABLE

  switch_pd_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  // go through the tables and delete all entries
  for (int i = 0, index = 0; i < 16 && index >= 0; i++) {
    pd_status = p4_pd_dc_int_inst_0003_get_first_entry_handle(
        switch_cfg_sess_hdl, p4_pd_device, &index);
    if (pd_status == SWITCH_PD_OBJ_NOT_FOUND) {
      pd_status = SWITCH_PD_STATUS_SUCCESS;
      break;
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT deleting an entry from inst0003 failed"
          "on device %d:  (pd: 0x%x)\n",
          device,
          pd_status);
      goto cleanup;
    }

    if (index >= 0) {
      entry_hdl = (switch_pd_hdl_t)index;
      pd_status = p4_pd_dc_int_inst_0003_table_delete(
          switch_cfg_sess_hdl, device, entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "INT deleting an entry from inst0003 failed"
            "on device %d:  (pd: 0x%x)\n",
            device,
            pd_status);
        goto cleanup;
      }
    }
  }

  // int_inst_0407 table
  for (int i = 0, index = 0; i < 16 && index >= 0; i++) {
    pd_status = p4_pd_dc_int_inst_0407_get_first_entry_handle(
        switch_cfg_sess_hdl, p4_pd_device, &index);

    if (pd_status == SWITCH_PD_OBJ_NOT_FOUND) {
      pd_status = SWITCH_PD_STATUS_SUCCESS;
      break;
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Transit deleting an entry from inst0407 failed"
          "on device %d:  (pd: 0x%x)\n",
          device,
          pd_status);
      goto cleanup;
    }
    if (index >= 0) {
      entry_hdl = (switch_pd_hdl_t)index;
      pd_status = p4_pd_dc_int_inst_0407_table_delete(
          switch_cfg_sess_hdl, device, entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "INT Transit deleting an entry from inst0407 failed"
            "on device %d:  (pd: 0x%x)\n",
            device,
            pd_status);
        goto cleanup;
      }
    }
  }

  // Done't even update the hop count
  pd_status = p4_pd_dc_int_inst_0407_set_default_action_nop(
      switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT disabling int instructions success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT disabling int instructions failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_outer_encap_transit_enable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  switch_pd_hdl_t entry_hdl = SWITCH_PD_INVALID_HANDLE;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD

#ifdef P4_INT_TRANSIT_ENABLE
#ifdef P4_INT_OVER_L4_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  // int_outer_encap table at transit
  p4_pd_dc_int_outer_encap_match_spec_t match_spec;

  match_spec.ipv4_valid = 1;
  match_spec.udp_valid = 0;

  pd_status = p4_pd_dc_int_outer_encap_table_add_with_int_update_l45_ipv4(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit int_outer_encap add transit entry for non-UDP failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  match_spec.ipv4_valid = 1;
  match_spec.udp_valid = 1;

  pd_status = p4_pd_dc_int_outer_encap_table_add_with_int_update_l45_ipv4_udp(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec, &entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Transit int_outer_encap add transit entry for UDP failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_OVER_L4_ENABLE
#endif  // P4_INT_TRANSIT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT int_outer_encap for transit configure success "
        "on device %d 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT int_outer_encap for transit configure failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_outer_encap_transit_disable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_TRANSIT_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  // clear int_outer_encap table at transit
  switch_pd_hdl_t entry_hdl;
  int index = 0;
  while (index >= 0) {
    pd_status = p4_pd_dc_int_outer_encap_get_first_entry_handle(
        switch_cfg_sess_hdl, p4_pd_device, &index);

    if (pd_status == SWITCH_PD_OBJ_NOT_FOUND) {
      pd_status = SWITCH_PD_STATUS_SUCCESS;
      break;
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Transit deleting an entry from int_outer_encap failed"
          "on device %d:  (pd: 0x%x)\n",
          device,
          pd_status);
      goto cleanup;
    }
    if (index >= 0) {
      entry_hdl = (switch_pd_hdl_t)index;
      pd_status = p4_pd_dc_int_outer_encap_table_delete(
          switch_cfg_sess_hdl, device, entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "INT Transit deleting an entry from int_outer_encap failed"
            "on device %d:  (pd: 0x%x)\n",
            device,
            pd_status);
        goto cleanup;
      }
    }
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_TRANSIT_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT int_outer_encap for transit disable success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT int_outer_encap for transit disable failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_transit_report_encap_table_enable_e2e(
    switch_device_t device,
    switch_uint32_t switch_id,
    switch_uint16_t dest_udp_port,
    p4_pd_entry_hdl_t *entry_hdl,
    bool add) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(switch_id);
  UNUSED(dest_udp_port);

#ifdef SWITCH_PD
#if defined(P4_INT_TRANSIT_ENABLE) && defined(P4_DTEL_QUEUE_REPORT_ENABLE)

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  p4_pd_entry_hdl_t default_entry_hdl;
  int max_pipes = SWITCH_MAX_PIPES;
  switch_device_max_pipes_get(device, &max_pipes);

  int ins_cnt;
  ins_cnt = _bit_count((uint64_t)INT_E2E_INSTRUCTION);
  p4_pd_dc_int_e2e_action_spec_t action_spec;
  p4_pd_dc_int_report_encap_match_spec_t match_spec;

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    p4_pd_device.dev_pipe_id = pipe;
    pd_status = p4_pd_dc_int_report_encap_set_default_action_nop(
        switch_cfg_sess_hdl, p4_pd_device, &default_entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Transit int_report_encap add E2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }

  match_spec.int_metadata_path_tracking_flow = 0;
  match_spec.dtel_md_queue_alert = 1;

  action_spec.action_udp_port = dest_udp_port;
  action_spec.action_insert_byte_cnt = (ins_cnt * 4);
  action_spec.action_switch_id = switch_id;

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, false, 0, 0, pipe);
    p4_pd_device.dev_pipe_id = pipe;
    if (add) {
      pd_status =
          p4_pd_dc_int_report_encap_table_add_with_int_e2e(switch_cfg_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           &action_spec,
                                                           entry_hdl);
    } else {
      pd_status = p4_pd_dc_int_report_encap_table_modify_with_int_e2e(
          switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Transit int_report_encap add/update E2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    entry_hdl++;
  }

  match_spec.int_metadata_path_tracking_flow = 1;
  match_spec.dtel_md_queue_alert = 1;

  action_spec.action_insert_byte_cnt = (ins_cnt * 4);
  action_spec.action_switch_id = switch_id;

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, true, 0, 0, pipe);
    p4_pd_device.dev_pipe_id = pipe;
    if (add) {
      pd_status =
          p4_pd_dc_int_report_encap_table_add_with_int_e2e(switch_cfg_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           &action_spec,
                                                           entry_hdl);
    } else {
      pd_status = p4_pd_dc_int_report_encap_table_modify_with_int_e2e(
          switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Transit int_report_encap add/update E2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    entry_hdl++;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_TRANSIT_ENABLE && P4_DTEL_QUEUE_REPORT_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT Transit report encap table add entry success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT Transit report encap table add failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

//------------------------------------------------------------------------------
// EP
//------------------------------------------------------------------------------

switch_status_t switch_pd_dtel_int_insert_table_add_update(
    switch_device_t device,
    switch_uint16_t session_id,
    switch_uint16_t instruction,
    switch_uint8_t max_hop,
    bool add,
    switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(session_id);
  UNUSED(instruction);
  UNUSED(max_hop);
  UNUSED(add);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE

  if (max_hop == 0) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    SWITCH_PD_LOG_ERROR(
        "INT EP invalid hop count %d on device %d\n", max_hop, device);
    return status;
  }

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  {
    p4_pd_dc_add_int_header_action_spec_t action_spec;
    action_spec.action_hop_cnt = max_hop;
    action_spec.action_ins_bitmap_0003 = (instruction >> 12) & 0xF;
    action_spec.action_ins_bitmap_0407 = (instruction >> 8) & 0xF;
    action_spec.action_ins_cnt = _bit_count((uint64_t)instruction);

    if (add) {
      p4_pd_dc_int_insert_match_spec_t match_spec;
      match_spec.int_metadata_config_session_id = session_id;

      pd_status =
          p4_pd_dc_int_insert_table_add_with_add_int_header(switch_cfg_sess_hdl,
                                                            p4_pd_device,
                                                            &match_spec,
                                                            &action_spec,
                                                            entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "INT EP int_insert table add entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } else {
      pd_status = p4_pd_dc_int_insert_table_modify_with_add_int_header(
          switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "INT EP int_insert table update entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    }
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT insert table add update entry success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT insert table add update entry failure on device %d : %s"
        " (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_insert_table_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  SWITCH_FAST_RECONFIG(device)
  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  pd_status =
      p4_pd_dc_int_insert_table_delete(switch_cfg_sess_hdl, device, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP int_insert table delete entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT insert table delete entry success on device %d\n",
                        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT insert table delete entry failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

/* For upstream reports: match criteria : source = false, sink = true,
   queue alert = false
   What is set: Path tracking = true, congested queue = false */

switch_status_t switch_pd_dtel_int_report_encap_table_enable_i2e(
    switch_device_t device,
    switch_uint16_t dest_udp_port,
    p4_pd_entry_hdl_t *entry_hdl,
    bool add) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;

  p4_pd_dc_int_report_encap_match_spec_t match_spec;
  p4_pd_dc_int_update_outer_encap_action_spec_t action_spec;

  // I2E
  action_spec.action_udp_port = dest_udp_port;
  action_spec.action_insert_byte_cnt = 0;

  match_spec.int_metadata_sink = 1;
  match_spec.int_metadata_sink_mask = 1;
  match_spec.int_metadata_source = 0;
  match_spec.int_metadata_source_mask = 1;
  match_spec.eg_intr_md_from_parser_aux_clone_src = SWITCH_PKT_TYPE_I2E_CLONED;

#ifdef P4_DTEL_QUEUE_REPORT_ENABLE
  match_spec.dtel_md_queue_alert = 0;
#endif
  int max_pipes = SWITCH_MAX_PIPES;
  switch_device_max_pipes_get(device, &max_pipes);

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    p4_pd_device.dev_pipe_id = pipe;
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_ETHERNET, false, false, true, 0, 0, pipe);
    if (add) {
      pd_status =
          p4_pd_dc_int_report_encap_table_add_with_int_update_outer_encap(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              0,
              &action_spec,
              entry_hdl);
    } else {
      pd_status =
          p4_pd_dc_int_report_encap_table_modify_with_int_update_outer_encap(
              switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap set I2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    entry_hdl++;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT report encap table add update i2e entry success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT report encap table add update i2e failure on device %d : %s "
        "(pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_report_encap_table_add_e2e(
    switch_device_t device,
    switch_uint32_t switch_id,
    switch_uint16_t dest_udp_port,
    switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(switch_id);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  int max_pipes = SWITCH_MAX_PIPES;
  switch_device_max_pipes_get(device, &max_pipes);

  int ins_cnt;
  ins_cnt = _bit_count((uint64_t)INT_E2E_INSTRUCTION);
  p4_pd_dc_int_report_encap_match_spec_t match_spec;

  // any changes to cases below must be kept consistent with
  // switch_pd_dtel_int_report_encap_table_modify_e2e

  // int_update_erspan E2E (sink = 1)
  p4_pd_dc_int_e2e_action_spec_t action_spec;

  /* For downstream or one hop case: match criteria : source = don't care,
     sink = true, queue alert = false
     What is set: Path tracking = true, congested queue = false */
  action_spec.action_udp_port = dest_udp_port;
  action_spec.action_insert_byte_cnt = (ins_cnt * 4);
  action_spec.action_switch_id = switch_id;

  match_spec.int_metadata_sink = 1;
  match_spec.int_metadata_sink_mask = 1;
  match_spec.int_metadata_source = 0;
  match_spec.int_metadata_source_mask = 0;
  match_spec.eg_intr_md_from_parser_aux_clone_src = SWITCH_PKT_TYPE_E2E_CLONED;
#ifdef P4_DTEL_QUEUE_REPORT_ENABLE
  match_spec.dtel_md_queue_alert = 0;
#endif
  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, false, true, 0, 0, pipe);
    p4_pd_device.dev_pipe_id = pipe;
    pd_status =
        p4_pd_dc_int_report_encap_table_add_with_int_e2e(switch_cfg_sess_hdl,
                                                         p4_pd_device,
                                                         &match_spec,
                                                         0,
                                                         &action_spec,
                                                         entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap add E2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    entry_hdl++;
  }

#ifdef P4_DTEL_QUEUE_REPORT_ENABLE
  /* Downstream or one hop case: Match criteria : source = don't care, sink =
     true,
     queue alert = true
     What is set: Path tracking = true, congested queue = true */
  match_spec.dtel_md_queue_alert = 1;
  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, true, 0, 0, pipe);
    p4_pd_device.dev_pipe_id = pipe;
    pd_status =
        p4_pd_dc_int_report_encap_table_add_with_int_e2e(switch_cfg_sess_hdl,
                                                         p4_pd_device,
                                                         &match_spec,
                                                         0,
                                                         &action_spec,
                                                         entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap add E2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    entry_hdl++;
  }

  /* Match criteria : source = true, sink = false,
     queue alert = true
     What is set: Path tracking = true, congested queue = true */
  match_spec.dtel_md_queue_alert = 1;
  match_spec.int_metadata_sink = 0;
  match_spec.int_metadata_sink_mask = 1;
  match_spec.int_metadata_source = 1;
  match_spec.int_metadata_source_mask = 1;

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, true, 0, 0, pipe);
    p4_pd_device.dev_pipe_id = pipe;
    pd_status =
        p4_pd_dc_int_report_encap_table_add_with_int_e2e(switch_cfg_sess_hdl,
                                                         p4_pd_device,
                                                         &match_spec,
                                                         0,
                                                         &action_spec,
                                                         entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap add E2E-1hop entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    entry_hdl++;
  }

  /* Match criteria : source = false, sink = false,
     queue alert = true
     What is set: Path tracking = false, congested queue = true */

  match_spec.dtel_md_queue_alert = 1;
  match_spec.int_metadata_sink = 0;
  match_spec.int_metadata_sink_mask = 1;
  match_spec.int_metadata_source = 0;
  match_spec.int_metadata_source_mask = 1;

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, false, 0, 0, pipe);
    p4_pd_device.dev_pipe_id = pipe;
    pd_status =
        p4_pd_dc_int_report_encap_table_add_with_int_e2e(switch_cfg_sess_hdl,
                                                         p4_pd_device,
                                                         &match_spec,
                                                         0,
                                                         &action_spec,
                                                         entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap add E2E-1hop entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    entry_hdl++;
  }

#endif  // STATELESS

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT report encap table add entry success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT report encap table add failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_report_encap_table_modify_e2e(
    switch_device_t device,
    switch_uint32_t switch_id,
    switch_uint16_t dest_udp_port,
    switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(status);
  UNUSED(pd_status);
  UNUSED(switch_id);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE

  int max_pipes = SWITCH_MAX_PIPES;
  switch_device_max_pipes_get(device, &max_pipes);
  int i = 0;
  int ins_cnt;
  ins_cnt = _bit_count((uint64_t)INT_E2E_INSTRUCTION);

  // any changes to cases below must be kept consistent with
  // switch_pd_dtel_int_report_encap_table_add_e2e

  // int_update_erspan E2E (sink = 1)
  p4_pd_dc_int_e2e_action_spec_t action_spec;

  /* For downstream or one hop case: match criteria : source = don't care,
     sink = true, queue alert = false
     What is set: Path tracking = true, congested queue = false */
  action_spec.action_udp_port = dest_udp_port;
  action_spec.action_insert_byte_cnt = (ins_cnt * 4);
  action_spec.action_switch_id = switch_id;

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, false, true, 0, 0, pipe);
    pd_status = p4_pd_dc_int_report_encap_table_modify_with_int_e2e(
        switch_cfg_sess_hdl, device, entry_hdl[i++], &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap modify E2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }

#ifdef P4_DTEL_QUEUE_REPORT_ENABLE
  /* Downstream or one hop case: Match criteria : source = don't care, sink =
     true,
     queue alert = true
     What is set: Path tracking = true, congested queue = true */
  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, true, 0, 0, pipe);
    pd_status = p4_pd_dc_int_report_encap_table_modify_with_int_e2e(
        switch_cfg_sess_hdl, device, entry_hdl[i++], &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap modify E2E entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }

  /* Match criteria : source = true, sink = false,
     queue alert = true
     What is set: Path tracking = true, congested queue = true */
  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, true, 0, 0, pipe);
    pd_status = p4_pd_dc_int_report_encap_table_modify_with_int_e2e(
        switch_cfg_sess_hdl, device, entry_hdl[i++], &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap modify E2E-1hop entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }

  /* Match criteria : source = false, sink = false,
     queue alert = true
     What is set: Path tracking = false, congested queue = true */

  for (int pipe = 0; pipe < max_pipes; pipe++) {
    action_spec.action_flags = switch_build_dtel_report_flags(
        0, DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL, false, true, false, 0, 0, pipe);
    pd_status = p4_pd_dc_int_report_encap_table_modify_with_int_e2e(
        switch_cfg_sess_hdl, device, entry_hdl[i++], &action_spec);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink int_report_encap modify E2E-1hop entry failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }
#endif  // STATELESS

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT report encap table modify entry success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT report encap table modify failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_report_encap_table_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  SWITCH_FAST_RECONFIG(device)

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  pd_status = p4_pd_dc_int_report_encap_table_delete(
      switch_cfg_sess_hdl, device, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT report_encap delete entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT report_encap delete entry success "
        "on device %d 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT report_encap delete entry failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }
  return status;
}

switch_status_t switch_pd_dtel_int_outer_encap_table_session_add_update(
    switch_device_t device,
    switch_uint16_t session_id,
    switch_uint16_t instruction,
    switch_dtel_int_info_t *int_info,
    switch_uint8_t protocol,
    bool add,
    switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(session_id);
  UNUSED(instruction);
  UNUSED(int_info);
  UNUSED(protocol);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  int ins_cnt;
  ins_cnt = _bit_count((uint64_t)instruction);
  p4_pd_dc_int_outer_encap_match_spec_t match_spec;
#ifdef P4_INT_L45_MARKER_ENABLE
  switch_uint16_t insert_byte_cnt = (ins_cnt * 4) + 12 + 8;
#else
  switch_uint16_t insert_byte_cnt = (ins_cnt * 4) + 12;
#endif  // P4_INT_L45_MARKER_ENABLE

  // int_add_update_l45_ipv4 (source = 1 and sink = 0)
  match_spec.int_metadata_config_session_id = session_id;
  match_spec.udp_valid = 0;
  match_spec.tcp_valid = 0;
  match_spec.icmp_valid = 0;
  switch (protocol) {
    case SWITCH_DTEL_IP_PROTO_UDP: {
      match_spec.udp_valid = 1;
      p4_pd_dc_int_add_update_l45_ipv4_udp_action_spec_t action_spec;
      action_spec.action_int_type = DTEL_INT_TYPE_INT;
      action_spec.action_insert_byte_cnt = insert_byte_cnt;
      action_spec.action_total_words = action_spec.action_insert_byte_cnt / 4;
#ifdef P4_INT_L45_MARKER_ENABLE
      action_spec.action_marker_f0 =
          (switch_uint32_t)(int_info->l45_marker_udp_value >> 32);
      action_spec.action_marker_f1 =
          (switch_uint32_t)int_info->l45_marker_udp_value;
#endif  // P4_INT_L45_MARKER_ENABLE

      if (add) {
        pd_status =
            p4_pd_dc_int_outer_encap_table_add_with_int_add_update_l45_ipv4_udp(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_int_outer_encap_table_modify_with_int_add_update_l45_ipv4_udp(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case SWITCH_DTEL_IP_PROTO_TCP: {
      match_spec.tcp_valid = 1;
      p4_pd_dc_int_add_update_l45_ipv4_action_spec_t action_spec;
      action_spec.action_int_type = DTEL_INT_TYPE_INT;
      action_spec.action_insert_byte_cnt = insert_byte_cnt;
      action_spec.action_total_words = action_spec.action_insert_byte_cnt / 4;
#ifdef P4_INT_L45_MARKER_ENABLE
      action_spec.action_marker_f0 =
          (switch_uint32_t)(int_info->l45_marker_tcp_value >> 32);
      action_spec.action_marker_f1 =
          (switch_uint32_t)int_info->l45_marker_tcp_value;
#endif  // P4_INT_L45_MARKER_ENABLE

      if (add) {
        pd_status =
            p4_pd_dc_int_outer_encap_table_add_with_int_add_update_l45_ipv4(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_int_outer_encap_table_modify_with_int_add_update_l45_ipv4(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case SWITCH_DTEL_IP_PROTO_ICMP: {
      match_spec.icmp_valid = 1;
      p4_pd_dc_int_add_update_l45_ipv4_action_spec_t action_spec;
      action_spec.action_int_type = DTEL_INT_TYPE_INT;
      action_spec.action_insert_byte_cnt = insert_byte_cnt;
      action_spec.action_total_words = action_spec.action_insert_byte_cnt / 4;
#ifdef P4_INT_L45_MARKER_ENABLE
      action_spec.action_marker_f0 =
          (switch_uint32_t)(int_info->l45_marker_icmp_value >> 32);
      action_spec.action_marker_f1 =
          (switch_uint32_t)int_info->l45_marker_icmp_value;
#endif  // P4_INT_L45_MARKER_ENABLE

      if (add) {
        pd_status =
            p4_pd_dc_int_outer_encap_table_add_with_int_add_update_l45_ipv4(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_int_outer_encap_table_modify_with_int_add_update_l45_ipv4(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    default:
      status = SWITCH_STATUS_INVALID_PARAMETER;
      SWITCH_PD_LOG_ERROR(
          "INT Source int_outer_encap set add l45 entry failed "
          "on device %d : table %s action %s, "
          "unrecognized protocol %d\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0),
          protocol);
      return status;
  }

  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Source int_outer_encap set add l45 entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT outer encap table add/update entry success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT outer encap table add/update failure on device %d : %s (pd: "
        "0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_outer_encap_table_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  SWITCH_FAST_RECONFIG(device)

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  pd_status = p4_pd_dc_int_outer_encap_table_delete(
      switch_cfg_sess_hdl, device, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT outer_encap delete entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT outer_encap delete entry success "
        "on device %d 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT outer_encap delete entry failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }
  return status;
}

switch_status_t switch_pd_dtel_int_terminate_init(switch_device_t device,
                                                  switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_EP_ENABLE

  p4_pd_entry_hdl_t default_entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_int_terminate_match_spec_t match_spec;
  match_spec.udp_valid = 1;

  pd_status =
      p4_pd_dc_int_terminate_set_default_action_int_sink_update_intl45_v4(
          switch_cfg_sess_hdl, p4_pd_device, &default_entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_terminate table set default entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  pd_status =
      p4_pd_dc_int_terminate_table_add_with_int_sink_update_intl45_v4_udp(
          switch_cfg_sess_hdl, p4_pd_device, &match_spec, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_terminate table add entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT sink int_terminate table init/update success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT sink int_terminate table init/update failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_upstream_report_enable(
    switch_device_t device, switch_list_t *event_infos) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(event_infos);

#ifdef SWITCH_PD

#ifdef P4_INT_EP_ENABLE
  switch_pd_hdl_t entry_hdl;
  switch_pd_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  dtel_event_info_t *event_info = NULL;
  switch_node_t *node = NULL;

  int priority = 0;
  p4_pd_dc_int_upstream_report_match_spec_t match_spec;
  p4_pd_dc_int_send_to_monitor_i2e_action_spec_t action_spec;

  FOR_EACH_IN_LIST((*event_infos), node) {
    event_info = node->data;
    action_spec.action_dscp_report = event_info->dscp;

#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE
    match_spec.int_metadata_digest_enb = 0;
    match_spec.int_metadata_digest_enb_mask = 0;
    match_spec.int_metadata_bfilter_output_mask = 0;
    match_spec.int_metadata_bfilter_output = 0;
#endif

    match_spec.tcp_valid_mask = 0;
    match_spec.tcp_valid = 0;
    match_spec.tcp_flags = 0;
    match_spec.tcp_flags_mask = 0;

#ifdef P4_DTEL_WATCH_INNER_ENABLE
    match_spec.inner_tcp_info_valid_mask = 0;
    match_spec.inner_tcp_info_valid = 0;
    match_spec.inner_tcp_info_flags_mask = 0;
    match_spec.inner_tcp_info_flags = 0;
#endif
    switch (event_info->type) {
      case SWITCH_DTEL_EVENT_TYPE_FLOW_STATE_CHANGE: {
#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE
        match_spec.int_metadata_digest_enb = 1;
        match_spec.int_metadata_digest_enb_mask = 1;
        match_spec.int_metadata_bfilter_output_mask = 2;
        match_spec.int_metadata_bfilter_output = 2;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (new flow) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.int_metadata_bfilter_output_mask = 3;
        match_spec.int_metadata_bfilter_output = 0;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (flow change) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
#endif
      } break;
      case SWITCH_DTEL_EVENT_TYPE_FLOW_REPORT_ALL_PACKETS: {
#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE
        match_spec.int_metadata_digest_enb = 0;
        match_spec.int_metadata_digest_enb_mask = 1;
#endif
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (report all) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } break;
      case SWITCH_DTEL_EVENT_TYPE_FLOW_TCPFLAG: {
        match_spec.tcp_valid_mask = 1;
        match_spec.tcp_valid = 1;
        match_spec.tcp_flags = 1;
        match_spec.tcp_flags_mask = 1;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (outer TCP FIN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.tcp_flags = 2;
        match_spec.tcp_flags_mask = 2;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (outer TCP SYN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }

        match_spec.tcp_flags = 4;
        match_spec.tcp_flags_mask = 4;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (outer TCP RST) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
#ifdef P4_DTEL_WATCH_INNER_ENABLE
        match_spec.tcp_valid_mask = 0;
        match_spec.tcp_valid = 0;
        match_spec.tcp_flags = 0;
        match_spec.tcp_flags_mask = 0;
        match_spec.inner_tcp_info_valid_mask = 1;
        match_spec.inner_tcp_info_valid = 1;
        match_spec.inner_tcp_info_flags_mask = 1;
        match_spec.inner_tcp_info_flags = 1;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (inner TCP FIN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.inner_tcp_info_flags_mask = 2;
        match_spec.inner_tcp_info_flags = 2;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (inner TCP SYN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.inner_tcp_info_flags_mask = 4;
        match_spec.inner_tcp_info_flags = 4;
        pd_status =
            p4_pd_dc_int_upstream_report_table_add_with_int_send_to_monitor_i2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_upstream_report (inner TCP RST) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
#endif  // P4_DTEL_WATCH_INNER_ENABLE
      } break;
      default:
        break;
    }
  }
  FOR_EACH_IN_LIST_END();

cleanup:
  status = switch_pd_status_to_status(pd_status);
  p4_pd_complete_operations(switch_cfg_sess_hdl);

#endif  // P4_INT_EP_ENABLE

#endif  // SWITCH_PD

  return status;
}

switch_status_t switch_pd_dtel_int_upstream_report_disable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(status);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  switch_pd_hdl_t entry_hdl;
  switch_pd_target_t p4_pd_device;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  int index = 0;
  while (index >= 0) {
    pd_status = p4_pd_dc_int_upstream_report_get_first_entry_handle(
        switch_cfg_sess_hdl, p4_pd_device, &index);

    if (pd_status == SWITCH_PD_OBJ_NOT_FOUND) {
      pd_status = SWITCH_PD_STATUS_SUCCESS;
      break;
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "DTel INT deleting an entry from int_upstream_report failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    if (index >= 0) {
      entry_hdl = (switch_pd_hdl_t)index;
      pd_status = p4_pd_dc_int_upstream_report_table_delete(
          switch_cfg_sess_hdl, device, entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "DTel INT deleting an entry from int_upstream_report "
            "failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    }
  }

cleanup:
  status = switch_pd_status_to_status(pd_status);
  p4_pd_complete_operations(switch_cfg_sess_hdl);
#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "DTel INT upstream report success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "DTel INT upstram report failed "
        "on device %d : %s (pd: 0x%x)",
        device,
        switch_error_to_string(status),
        pd_status);
  }
  return status;
}

switch_status_t switch_pd_dtel_int_sink_local_report_enable(
    switch_device_t device, switch_list_t *event_infos) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(event_infos);

#ifdef SWITCH_PD

#ifdef P4_INT_EP_ENABLE
  switch_pd_hdl_t entry_hdl;
  switch_pd_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  dtel_event_info_t *event_info = NULL;
  switch_node_t *node = NULL;

  int priority = 0;
  p4_pd_dc_int_sink_local_report_match_spec_t match_spec;
  p4_pd_dc_int_send_to_monitor_e2e_action_spec_t action_spec;

  FOR_EACH_IN_LIST((*event_infos), node) {
    event_info = node->data;
    action_spec.action_dscp_report = event_info->dscp;

    match_spec.int_metadata_sink = 1;
    match_spec.int_metadata_sink_mask = 1;

#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE
    match_spec.int_metadata_digest_enb = 0;
    match_spec.int_metadata_digest_enb_mask = 0;
    match_spec.dtel_md_bfilter_output_mask = 0;
    match_spec.dtel_md_bfilter_output = 0;
#endif
#ifdef P4_DTEL_QUEUE_REPORT_ENABLE
    match_spec.dtel_md_queue_alert_mask = 0;
    match_spec.dtel_md_queue_alert = 0;
#endif

    match_spec.tcp_valid_mask = 0;
    match_spec.tcp_valid = 0;
    match_spec.tcp_flags = 0;
    match_spec.tcp_flags_mask = 0;

#ifdef P4_DTEL_WATCH_INNER_ENABLE
    match_spec.inner_tcp_info_valid_mask = 0;
    match_spec.inner_tcp_info_valid = 0;
    match_spec.inner_tcp_info_flags_mask = 0;
    match_spec.inner_tcp_info_flags = 0;
#endif
    switch (event_info->type) {
      case SWITCH_DTEL_EVENT_TYPE_FLOW_STATE_CHANGE: {
#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE
        match_spec.int_metadata_digest_enb = 1;
        match_spec.int_metadata_digest_enb_mask = 1;
        match_spec.dtel_md_bfilter_output_mask = 2;
        match_spec.dtel_md_bfilter_output = 2;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (new flow) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.dtel_md_bfilter_output_mask = 3;
        match_spec.dtel_md_bfilter_output = 0;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (flow change) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
#endif
      } break;
      case SWITCH_DTEL_EVENT_TYPE_FLOW_REPORT_ALL_PACKETS: {
#ifdef P4_DTEL_FLOW_STATE_TRACK_ENABLE
        match_spec.int_metadata_digest_enb = 0;
        match_spec.int_metadata_digest_enb_mask = 1;
#endif
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (report all) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } break;
      case SWITCH_DTEL_EVENT_TYPE_FLOW_TCPFLAG: {
        match_spec.tcp_valid_mask = 1;
        match_spec.tcp_valid = 1;
        match_spec.tcp_flags = 1;
        match_spec.tcp_flags_mask = 1;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (outer TCP FIN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.tcp_flags = 2;
        match_spec.tcp_flags_mask = 2;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (outer TCP SYN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.tcp_flags = 4;
        match_spec.tcp_flags_mask = 4;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (outer TCP RST) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
#ifdef P4_DTEL_WATCH_INNER_ENABLE
        match_spec.tcp_valid_mask = 0;
        match_spec.tcp_valid = 0;
        match_spec.tcp_flags = 0;
        match_spec.tcp_flags_mask = 0;
        match_spec.inner_tcp_info_valid_mask = 1;
        match_spec.inner_tcp_info_valid = 1;
        match_spec.inner_tcp_info_flags_mask = 1;
        match_spec.inner_tcp_info_flags = 1;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (inner TCP FIN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.inner_tcp_info_flags_mask = 2;
        match_spec.inner_tcp_info_flags = 2;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (inner TCP SYN) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
        match_spec.inner_tcp_info_flags_mask = 4;
        match_spec.inner_tcp_info_flags = 4;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (inner TCP RST) enable failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
#endif  // P4_DTEL_WATCH_INNER_ENABLE
      } break;
      case SWITCH_DTEL_EVENT_TYPE_Q_REPORT_THRESHOLD_BREACH: {
#ifdef P4_DTEL_QUEUE_REPORT_ENABLE
        match_spec.dtel_md_queue_alert_mask = 1;
        match_spec.dtel_md_queue_alert = 1;
        match_spec.int_metadata_sink_mask = 0;
        pd_status =
            p4_pd_dc_int_sink_local_report_table_add_with_int_send_to_monitor_e2e(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority++,
                &action_spec,
                &entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "DTel int_sink_local_report (qalert qchange) enable "
              "failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
#endif  // P4_DTEL_QUEUE_REPORT_ENABLE
      } break;
      default:
        break;
    }
  }
  FOR_EACH_IN_LIST_END();

cleanup:
  status = switch_pd_status_to_status(pd_status);
  p4_pd_complete_operations(switch_cfg_sess_hdl);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  return status;
}

switch_status_t switch_pd_dtel_int_sink_local_report_disable(
    switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(status);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  switch_pd_hdl_t entry_hdl;
  switch_pd_target_t p4_pd_device;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  int index = 0;
  while (index >= 0) {
    pd_status = p4_pd_dc_int_sink_local_report_get_first_entry_handle(
        switch_cfg_sess_hdl, p4_pd_device, &index);

    if (pd_status == SWITCH_PD_OBJ_NOT_FOUND) {
      pd_status = SWITCH_PD_STATUS_SUCCESS;
      break;
    }
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "DTel INT deleting an entry from int_sink_local_report "
          "failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
    if (index >= 0) {
      entry_hdl = (switch_pd_hdl_t)index;
      pd_status = p4_pd_dc_int_sink_local_report_table_delete(
          switch_cfg_sess_hdl, device, entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "DTel INT deleting an entry from int_sink_local_report "
            "failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    }
  }

cleanup:
  status = switch_pd_status_to_status(pd_status);
  p4_pd_complete_operations(switch_cfg_sess_hdl);
#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "DTel INT sink local report success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "DTel INT sink local report failed "
        "on device %d : %s (pd: 0x%x)",
        device,
        switch_error_to_string(status),
        pd_status);
  }
  return status;
}

switch_status_t switch_pd_dtel_int_set_sink_enable(switch_device_t device,
                                                   switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD

#ifdef P4_INT_EP_ENABLE
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  int priority = 0;

  if (*entry_hdl == SWITCH_PD_INVALID_HANDLE) {
    p4_pd_dc_int_set_sink_match_spec_t match_spec;
    match_spec.int_header_valid = 1;
    match_spec.ipv4_diffserv = 0;
    match_spec.ipv4_diffserv_mask = 0;
    pd_status = p4_pd_dc_int_set_sink_table_add_with_int_sink_enable(
        switch_cfg_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
  } else {
    pd_status = p4_pd_dc_int_set_sink_table_modify_with_int_sink_enable(
        switch_cfg_sess_hdl, device, *entry_hdl);
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_set_sink set default enable action failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT Sink int_set_sink table enable success "
        "on device %d 0x%x\n",
        device,
        *entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_set_sink table enable failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_set_sink_disable(
    switch_device_t device, switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD

#ifdef P4_INT_EP_ENABLE

  if (*entry_hdl != SWITCH_PD_INVALID_HANDLE) {
    pd_status = p4_pd_dc_int_set_sink_table_delete(
        switch_cfg_sess_hdl, device, *entry_hdl);
  }
  // else can happen at init

  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_set_sink set default disable action failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }
  *entry_hdl = SWITCH_PD_INVALID_HANDLE;

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT Sink int_set_sink table disable success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT Sink int_set_sink table disable failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_pd_status_t switch_pd_dtel_int_ingress_bfilters_init(
    switch_device_t device) {
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);

#ifdef SWITCH_PD

#if defined(P4_INT_EP_ENABLE) && defined(P4_DTEL_FLOW_STATE_TRACK_ENABLE)

  switch_pd_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  switch_pd_status_t (*dtel_ig_bfilter_set_default_actions[4])() = {
      p4_pd_dc_dtel_ig_bfilter_1_set_default_action_run_dtel_ig_bfilter_1,
      p4_pd_dc_dtel_ig_bfilter_2_set_default_action_run_dtel_ig_bfilter_2,
      p4_pd_dc_dtel_ig_bfilter_3_set_default_action_run_dtel_ig_bfilter_3,
      p4_pd_dc_dtel_ig_bfilter_4_set_default_action_run_dtel_ig_bfilter_4};

  for (int filter_id = 0; filter_id < 4; filter_id++) {
    pd_status = dtel_ig_bfilter_set_default_actions[filter_id](
        switch_cfg_sess_hdl, p4_pd_device, &entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "INT Sink ingress bloom filter set default action failed "
          "on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      goto cleanup;
    }
  }

cleanup:

#endif  // P4_INT_EP_ENABLE && P4_DTEL_FLOW_STATE_TRACK_ENABLE

#endif  // SWITCH_PD

  if (pd_status == SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT Sink ingress bloom filters enable success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT Sink ingress bloom filters enable failure "
        "on device %d : (pd: 0x%x)\n",
        device,
        pd_status);
  }

  return pd_status;
}

switch_status_t switch_pd_dtel_intl45_dscp_sink_clear_entry_update(
    switch_device_t device,
    switch_dtel_int_info_t *int_info,
    switch_pd_hdl_t *entry_hdl,
    bool init) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(int_info);
  UNUSED(entry_hdl);
  UNUSED(init);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE

#ifdef P4_INT_L45_DSCP_ENABLE
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  switch_uint8_t diffserv_mask = int_info->l45_diffserv_mask << 2;
  int priority = 0;

  p4_pd_dc_int_edge_ports_match_spec_t match_spec;
  match_spec.int_metadata_source = 0;
  match_spec.int_metadata_sink = 1;
  match_spec.eg_intr_md_egress_port = 0;
  match_spec.eg_intr_md_egress_port_mask = 0;

  switch (diffserv_mask) {
    case 0xfc: {
      if (init) {
        pd_status =
            p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte_l45_dscp_clear_all(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority,
                entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table add sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } else {
        pd_status =
            p4_pd_dc_int_edge_ports_table_modify_with_int_convert_word_to_byte_l45_dscp_clear_all(
                switch_cfg_sess_hdl, device, *entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table modify sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      }
    } break;
    case 0x04: {
      if (init) {
        pd_status =
            p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte_l45_dscp_clear_2(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority,
                entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table add sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } else {
        pd_status =
            p4_pd_dc_int_edge_ports_table_modify_with_int_convert_word_to_byte_l45_dscp_clear_2(
                switch_cfg_sess_hdl, device, *entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table modify sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      }
    } break;
    case 0x08: {
      if (init) {
        pd_status =
            p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte_l45_dscp_clear_3(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority,
                entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table add sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } else {
        pd_status =
            p4_pd_dc_int_edge_ports_table_modify_with_int_convert_word_to_byte_l45_dscp_clear_3(
                switch_cfg_sess_hdl, device, *entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table modify sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      }
    } break;
    case 0x10: {
      if (init) {
        pd_status =
            p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte_l45_dscp_clear_4(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority,
                entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table add sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } else {
        pd_status =
            p4_pd_dc_int_edge_ports_table_modify_with_int_convert_word_to_byte_l45_dscp_clear_4(
                switch_cfg_sess_hdl, device, *entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table modify sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      }
    } break;
    case 0x20: {
      if (init) {
        pd_status =
            p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte_l45_dscp_clear_5(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority,
                entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table add sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } else {
        pd_status =
            p4_pd_dc_int_edge_ports_table_modify_with_int_convert_word_to_byte_l45_dscp_clear_5(
                switch_cfg_sess_hdl, device, *entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table modify sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      }
    } break;
    case 0x40: {
      if (init) {
        pd_status =
            p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte_l45_dscp_clear_6(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority,
                entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table add sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } else {
        pd_status =
            p4_pd_dc_int_edge_ports_table_modify_with_int_convert_word_to_byte_l45_dscp_clear_6(
                switch_cfg_sess_hdl, device, *entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table modify sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      }
    } break;
    case 0x80: {
      if (init) {
        pd_status =
            p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte_l45_dscp_clear_7(
                switch_cfg_sess_hdl,
                p4_pd_device,
                &match_spec,
                priority,
                entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table add sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      } else {
        pd_status =
            p4_pd_dc_int_edge_ports_table_modify_with_int_convert_word_to_byte_l45_dscp_clear_7(
                switch_cfg_sess_hdl, device, *entry_hdl);
        if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
          SWITCH_PD_LOG_ERROR(
              "int_edge_ports table modify sink clear dscp entry failed "
              "on device %d : table %s action %s\n",
              device,
              switch_pd_table_id_to_string(0),
              switch_pd_action_id_to_string(0));
          goto cleanup;
        }
      }
    } break;
    default:
      status = SWITCH_STATUS_INVALID_PARAMETER;
      SWITCH_PD_LOG_ERROR(
          "int_edge_ports sink clear dscp entry init/update failed: invalid "
          "diffserv_mask %2x on device %d : table %s action %s\n",
          diffserv_mask,
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      return status;
  }
#endif  // P4_INT_L45_DSCP_ENABLE

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "int_edge_ports table sink clear dscp init/update success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "int_edge_ports table sink clear dscp init/update failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_dscp_sink_clear_entry_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  if (entry_hdl != SWITCH_PD_INVALID_HANDLE) {
    pd_status = p4_pd_dc_int_edge_ports_table_delete(
        switch_cfg_sess_hdl, device, entry_hdl);
  }

  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "int_edge_ports table delete sink clear dscp entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "int_edge_ports table sink clear dscp delete success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "int_edge_ports table sink clear dscp delete failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_edge_ports_add(switch_device_t device,
                                                  switch_port_t port,
                                                  switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_EP_ENABLE
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_int_edge_ports_match_spec_t match_spec;
  match_spec.eg_intr_md_egress_port = port;
  match_spec.eg_intr_md_egress_port_mask = 0x1FF;
  match_spec.int_metadata_source = 1;
  match_spec.int_metadata_sink = 0;
  int priority = 0;

  pd_status = p4_pd_dc_int_edge_ports_table_add_with_set_int_sink(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP edge port add failed on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT EP edge port add success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT EP edge port add failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_edge_ports_delete(
    switch_device_t device, switch_port_t port, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  SWITCH_FAST_RECONFIG(device)

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

#ifdef P4_INT_EP_ENABLE
  pd_status = p4_pd_dc_int_edge_ports_table_delete(
      switch_cfg_sess_hdl, device, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP edge port delete failed on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT EP edge port delete success on device %d\n",
                        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT EP edge port delete failure on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_convert_word_to_byte_init(
    switch_device_t device, switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(pd_status);

#ifdef SWITCH_PD

// if P4_INT_L45_DSCP_ENABLE, convert_word_to_byte will be taken care of
// together with clearing of DSCP at sink
#if defined(P4_INT_EP_ENABLE) && !defined(P4_INT_L45_DSCP_ENABLE)
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_int_edge_ports_match_spec_t match_spec;
  match_spec.eg_intr_md_egress_port = 0;
  match_spec.eg_intr_md_egress_port_mask = 0;
  match_spec.int_metadata_source = 0;
  match_spec.int_metadata_sink = 1;
  int priority = 0;

  pd_status = p4_pd_dc_int_edge_ports_table_add_with_int_convert_word_to_byte(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "INT EP sink convert word to byte failed on device %d :"
        " table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && !P4_INT_L45_DSCP_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT EP sink convert word to byte success on device %d\n", device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT EP sink convert word to byte failure on device %d : %s"
        " (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
switch_status_t switch_pd_dtel_intl45_set_dscp_add_modify(
    switch_device_t device,
    p4_pd_dc_dtel_intl45_set_dscp_match_spec_t *match_spec,
    int priority,
    switch_uint8_t diffserv_value,
    switch_uint8_t diffserv_mask,
    switch_pd_hdl_t *entry_hdl,
    bool add) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(match_spec);
  UNUSED(priority);
  UNUSED(diffserv_value);
  UNUSED(diffserv_mask);
  UNUSED(entry_hdl);
  UNUSED(add);
  UNUSED(pd_status);

#ifdef SWITCH_PD
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  switch (diffserv_mask) {
    case 0xfc: {
      p4_pd_dc_intl45_set_dscp_all_action_spec_t action_spec;
      action_spec.action_diffserv_value = diffserv_value;
      if (add) {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_add_with_intl45_set_dscp_all(
                switch_cfg_sess_hdl,
                p4_pd_device,
                match_spec,
                priority,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_modify_with_intl45_set_dscp_all(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case 0x04: {
      p4_pd_dc_intl45_set_dscp_2_action_spec_t action_spec;
      action_spec.action_diffserv_value = diffserv_value;
      if (add) {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_add_with_intl45_set_dscp_2(
                switch_cfg_sess_hdl,
                p4_pd_device,
                match_spec,
                priority,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_modify_with_intl45_set_dscp_2(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case 0x08: {
      p4_pd_dc_intl45_set_dscp_3_action_spec_t action_spec;
      action_spec.action_diffserv_value = diffserv_value;
      if (add) {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_add_with_intl45_set_dscp_3(
                switch_cfg_sess_hdl,
                p4_pd_device,
                match_spec,
                priority,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_modify_with_intl45_set_dscp_3(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case 0x10: {
      p4_pd_dc_intl45_set_dscp_4_action_spec_t action_spec;
      action_spec.action_diffserv_value = diffserv_value;
      if (add) {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_add_with_intl45_set_dscp_4(
                switch_cfg_sess_hdl,
                p4_pd_device,
                match_spec,
                priority,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_modify_with_intl45_set_dscp_4(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case 0x20: {
      p4_pd_dc_intl45_set_dscp_5_action_spec_t action_spec;
      action_spec.action_diffserv_value = diffserv_value;
      if (add) {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_add_with_intl45_set_dscp_5(
                switch_cfg_sess_hdl,
                p4_pd_device,
                match_spec,
                priority,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_modify_with_intl45_set_dscp_5(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case 0x40: {
      p4_pd_dc_intl45_set_dscp_6_action_spec_t action_spec;
      action_spec.action_diffserv_value = diffserv_value;
      if (add) {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_add_with_intl45_set_dscp_6(
                switch_cfg_sess_hdl,
                p4_pd_device,
                match_spec,
                priority,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_modify_with_intl45_set_dscp_6(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    case 0x80: {
      p4_pd_dc_intl45_set_dscp_7_action_spec_t action_spec;
      action_spec.action_diffserv_value = diffserv_value;
      if (add) {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_add_with_intl45_set_dscp_7(
                switch_cfg_sess_hdl,
                p4_pd_device,
                match_spec,
                priority,
                &action_spec,
                entry_hdl);
      } else {
        pd_status =
            p4_pd_dc_dtel_intl45_set_dscp_table_modify_with_intl45_set_dscp_7(
                switch_cfg_sess_hdl, device, *entry_hdl, &action_spec);
      }
    } break;
    default:
      status = SWITCH_STATUS_INVALID_PARAMETER;
      SWITCH_PD_LOG_ERROR(
          "dtel_intl45_set_dscp set dscp entry add/modify failed: invalid "
          "diffserv_mask %2x on device %d : table %s action %s\n",
          diffserv_mask,
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      return status;
  }

  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table add or modify set dscp entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
  }

  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // SWITCH_PD

  return status;
}
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE

switch_status_t switch_pd_dtel_intl45_set_dscp_init_update(
    switch_device_t device,
    switch_dtel_int_info_t *int_info,
    switch_pd_hdl_t *entry_hdl,
    bool init) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(int_info);
  UNUSED(entry_hdl);
  UNUSED(init);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  bool pd_failed = false;
  switch_uint8_t diffserv_value = int_info->l45_diffserv_value << 2;
  switch_uint8_t diffserv_mask = int_info->l45_diffserv_mask << 2;

  int priority;

  p4_pd_dc_dtel_intl45_set_dscp_match_spec_t match_spec;

  // if deflected and not sink, nop
  if (init) {
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    priority = DTEL_INT_L45_SET_DSCP_PRIORITY_HIGH;
    match_spec.int_header_valid = 0;
    match_spec.int_header_valid_mask = 0;
    match_spec.ipv4_diffserv = 0;
    match_spec.ipv4_diffserv_mask = 0;
    match_spec.egress_metadata_egress_port = 0;
    match_spec.egress_metadata_egress_port_mask = 0;
    match_spec.int_metadata_sink = 0;
    match_spec.int_metadata_sink_mask = 1;
    match_spec.eg_intr_md_deflection_flag = 1;

    pd_status = p4_pd_dc_dtel_intl45_set_dscp_table_add_with_nop(
        switch_cfg_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "dtel_intl45_set_dscp table add deflect with no int header nop entry "
          "failed on device %d : table %s action %s status %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0),
          switch_error_to_string(status));
      pd_failed = true;
      goto cleanup;
    }
  }

  entry_hdl++;

  // if deflected and sink, clear intl45_dscp
  priority = DTEL_INT_L45_SET_DSCP_PRIORITY_HIGH;
  match_spec.int_header_valid = 0;
  match_spec.int_header_valid_mask = 0;
  match_spec.ipv4_diffserv = 0;
  match_spec.ipv4_diffserv_mask = 0;
  match_spec.egress_metadata_egress_port = 0;
  match_spec.egress_metadata_egress_port_mask = 0;
  match_spec.int_metadata_sink = 1;
  match_spec.int_metadata_sink_mask = 1;
  match_spec.eg_intr_md_deflection_flag = 1;

  status = switch_pd_dtel_intl45_set_dscp_add_modify(
      device, &match_spec, priority, 0, diffserv_mask, entry_hdl, init);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table add or modify deflected with int header "
        " entry failed on device %d : %s\n",
        device,
        switch_error_to_string(status));
    goto cleanup;
  }

  entry_hdl++;

  // set intl45_dscp value if int header valid
  // and in lower priority entry, i.e. not an edge port
  priority = DTEL_INT_L45_SET_DSCP_PRIORITY_LOW;
  match_spec.int_header_valid = 1;
  match_spec.int_header_valid_mask = 1;
  match_spec.ipv4_diffserv = 0;
  match_spec.ipv4_diffserv_mask = 0;
  match_spec.egress_metadata_egress_port = 0;
  match_spec.egress_metadata_egress_port_mask = 0;
  match_spec.int_metadata_sink = 0;
  match_spec.int_metadata_sink_mask = 0;
  match_spec.eg_intr_md_deflection_flag = 0;

  status = switch_pd_dtel_intl45_set_dscp_add_modify(device,
                                                     &match_spec,
                                                     priority,
                                                     diffserv_value,
                                                     diffserv_mask,
                                                     entry_hdl,
                                                     init);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table add or modify set dscp entry failed "
        " on device %d : %s\n",
        device,
        switch_error_to_string(status));
    goto cleanup;
  }

  entry_hdl++;

  // clear intl45_dscp value if no int header and diffserv_value matches
  // and in lower priority entry, i.e. not an edge port
  if (*entry_hdl != SWITCH_PD_INVALID_HANDLE) {
    pd_status = p4_pd_dc_dtel_intl45_set_dscp_table_delete(
        switch_cfg_sess_hdl, device, *entry_hdl);
    if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
      SWITCH_PD_LOG_ERROR(
          "dtel_intl45_set_dscp table modify clear dscp entry failed while "
          "deleting entry on device %d : table %s action %s\n",
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      pd_failed = true;
      goto cleanup;
    }
    *entry_hdl = SWITCH_PD_INVALID_HANDLE;
  }
  priority = DTEL_INT_L45_SET_DSCP_PRIORITY_LOW;
  match_spec.int_header_valid = 0;
  match_spec.int_header_valid_mask = 1;
  match_spec.ipv4_diffserv = diffserv_value;
  match_spec.ipv4_diffserv_mask = diffserv_mask;
  match_spec.egress_metadata_egress_port = 0;
  match_spec.egress_metadata_egress_port_mask = 0;
  match_spec.int_metadata_sink = 0;
  match_spec.int_metadata_sink_mask = 0;
  match_spec.eg_intr_md_deflection_flag = 0;

  status = switch_pd_dtel_intl45_set_dscp_add_modify(
      device, &match_spec, priority, 0, diffserv_mask, entry_hdl, true);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table add or modify clear dscp entry failed "
        " on device %d : %s\n",
        device,
        switch_error_to_string(status));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  if (pd_failed) {
    status = switch_pd_status_to_status(pd_status);
  }
#endif  // P4_INT_L45_DSCP_ENABLE && P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "dtel_intl45_set_dscp table set dscp init/update success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table set dscp init/update failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_set_dscp_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  if (entry_hdl != SWITCH_PD_INVALID_HANDLE) {
    pd_status = p4_pd_dc_dtel_intl45_set_dscp_table_delete(
        switch_cfg_sess_hdl, device, entry_hdl);
  }

  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table set dscp entry delete failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "dtel_intl45_set_dscp table set dscp delete success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table set dscp delete failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_set_dscp_add_edge_port(
    switch_device_t device, switch_port_t port, switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(port);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  // Setting or clearing dscp to reflect whether int header is valid
  // is not applicable on edge ports
  // Add high priority entry in dtel_intl45_set_dscp with nop action

  int priority = DTEL_INT_L45_SET_DSCP_PRIORITY_HIGH;

  p4_pd_dc_dtel_intl45_set_dscp_match_spec_t match_spec;
  match_spec.int_header_valid = 0;
  match_spec.int_header_valid_mask = 0;
  match_spec.ipv4_diffserv = 0;
  match_spec.ipv4_diffserv_mask = 0;
  match_spec.egress_metadata_egress_port = port;
  match_spec.egress_metadata_egress_port_mask = 0x1FF;
  match_spec.int_metadata_sink = 0;
  match_spec.int_metadata_sink_mask = 0;
  match_spec.eg_intr_md_deflection_flag = 0;

  pd_status = p4_pd_dc_dtel_intl45_set_dscp_table_add_with_nop(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table add edge port entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "dtel_intl45_set_dscp table add edge port entry success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table add edge port entry failure on "
        "device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_set_dscp_delete_edge_port(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  pd_status = p4_pd_dc_dtel_intl45_set_dscp_table_delete(
      switch_cfg_sess_hdl, device, entry_hdl);
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table delete edge port entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE

#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "dtel_intl45_set_dscp table delete edge port entry "
        "success on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "dtel_intl45_set_dscp table delete edge port entry failure on "
        "device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_dscp_boundary_clear_entry_update(
    switch_device_t device,
    switch_dtel_int_info_t *int_info,
    switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(int_info);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE

#ifdef P4_INT_L45_DSCP_ENABLE
  // if entry exists, need to delete it first since match_spec is changing
  if (*entry_hdl != SWITCH_PD_INVALID_HANDLE) {
    pd_status = p4_pd_dc_int_set_sink_table_delete(
        switch_cfg_sess_hdl, device, *entry_hdl);
  }
  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "int_set_sink table delete dscp boundary clear entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  int priority = 0;

  switch_uint8_t diffserv_value = int_info->l45_diffserv_value << 2;
  switch_uint8_t diffserv_mask = int_info->l45_diffserv_mask << 2;

  p4_pd_dc_int_set_sink_match_spec_t match_spec;
  match_spec.int_header_valid = 0;
  match_spec.ipv4_diffserv = diffserv_value;
  match_spec.ipv4_diffserv_mask = diffserv_mask;

  switch (diffserv_mask) {
    case 0xfc: {
      p4_pd_dc_int_sink_set_l45_dscp_clear_all_action_spec_t action_spec;
      action_spec.action_sink_bit = 0;
      pd_status =
          p4_pd_dc_int_set_sink_table_add_with_int_sink_set_l45_dscp_clear_all(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              priority,
              &action_spec,
              entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "int_set_sink table add dscp boundary clear entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } break;
    case 0x04: {
      p4_pd_dc_int_sink_set_l45_dscp_clear_2_action_spec_t action_spec;
      action_spec.action_sink_bit = 0;
      pd_status =
          p4_pd_dc_int_set_sink_table_add_with_int_sink_set_l45_dscp_clear_2(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              priority,
              &action_spec,
              entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "int_set_sink table add dscp boundary clear entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } break;
    case 0x08: {
      p4_pd_dc_int_sink_set_l45_dscp_clear_3_action_spec_t action_spec;
      action_spec.action_sink_bit = 0;
      pd_status =
          p4_pd_dc_int_set_sink_table_add_with_int_sink_set_l45_dscp_clear_3(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              priority,
              &action_spec,
              entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "int_set_sink table add dscp boundary clear entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } break;
    case 0x10: {
      p4_pd_dc_int_sink_set_l45_dscp_clear_4_action_spec_t action_spec;
      action_spec.action_sink_bit = 0;
      pd_status =
          p4_pd_dc_int_set_sink_table_add_with_int_sink_set_l45_dscp_clear_4(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              priority,
              &action_spec,
              entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "int_set_sink table add dscp boundary clear entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } break;
    case 0x20: {
      p4_pd_dc_int_sink_set_l45_dscp_clear_5_action_spec_t action_spec;
      action_spec.action_sink_bit = 0;
      pd_status =
          p4_pd_dc_int_set_sink_table_add_with_int_sink_set_l45_dscp_clear_5(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              priority,
              &action_spec,
              entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "int_set_sink table add dscp boundary clear entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } break;
    case 0x40: {
      p4_pd_dc_int_sink_set_l45_dscp_clear_6_action_spec_t action_spec;
      action_spec.action_sink_bit = 0;
      pd_status =
          p4_pd_dc_int_set_sink_table_add_with_int_sink_set_l45_dscp_clear_6(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              priority,
              &action_spec,
              entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "int_set_sink table add dscp boundary clear entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } break;
    case 0x80: {
      p4_pd_dc_int_sink_set_l45_dscp_clear_7_action_spec_t action_spec;
      action_spec.action_sink_bit = 0;
      pd_status =
          p4_pd_dc_int_set_sink_table_add_with_int_sink_set_l45_dscp_clear_7(
              switch_cfg_sess_hdl,
              p4_pd_device,
              &match_spec,
              priority,
              &action_spec,
              entry_hdl);
      if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
        SWITCH_PD_LOG_ERROR(
            "int_set_sink table add dscp boundary clear entry failed "
            "on device %d : table %s action %s\n",
            device,
            switch_pd_table_id_to_string(0),
            switch_pd_action_id_to_string(0));
        goto cleanup;
      }
    } break;
    default:
      status = SWITCH_STATUS_INVALID_PARAMETER;
      SWITCH_PD_LOG_ERROR(
          "int_set_sink table add dscp boundary clear entry failed: invalid "
          "diffserv_mask %2x on device %d : table %s action %s\n",
          diffserv_mask,
          device,
          switch_pd_table_id_to_string(0),
          switch_pd_action_id_to_string(0));
      return status;
  }
#endif  // P4_INT_L45_DSCP_ENABLE

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);

#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "int_set_sink table add dscp boundary clear entry success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "int_set_sink table add dscp boundary clear entry failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_intl45_dscp_boundary_clear_entry_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#if defined(P4_INT_EP_ENABLE) && defined(P4_INT_L45_DSCP_ENABLE)
  if (entry_hdl != SWITCH_PD_INVALID_HANDLE) {
    pd_status = p4_pd_dc_int_set_sink_table_delete(
        switch_cfg_sess_hdl, device, entry_hdl);
  }

  if (pd_status != SWITCH_PD_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "int_set_sink table delete dscp boundary clear entry failed "
        "on device %d : table %s action %s\n",
        device,
        switch_pd_table_id_to_string(0),
        switch_pd_action_id_to_string(0));
    goto cleanup;
  }

cleanup:
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE && P4_INT_L45_DSCP_ENABLE
#endif  // SWITCH_PD

  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "int_set_sink table delete dscp boundary clear entry success "
        "on device %d\n",
        device);
  } else {
    SWITCH_PD_LOG_ERROR(
        "int_set_sink table delete dscp boundary clear entry failure "
        "on device %d : %s (pd: 0x%x)\n",
        device,
        switch_error_to_string(status),
        pd_status);
  }

  return status;
}

switch_status_t switch_pd_dtel_int_watchlist_entry_create(
    switch_device_t device,
    switch_twl_match_spec_t *twl_match,
    switch_uint16_t priority,
    bool watch,
    switch_twl_action_params_t *action_params,
    switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(priority);
  UNUSED(watch);
  UNUSED(action_params);
  UNUSED(entry_hdl);
  UNUSED(status);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  switch_pd_target_t p4_pd_device;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  p4_pd_dc_int_watchlist_match_spec_t match_spec;

  SWITCH_MEMSET(&match_spec, 0x0, sizeof(match_spec));
  match_spec.ethernet_etherType = twl_match->ether_type;
  match_spec.ethernet_etherType_mask = twl_match->ether_type_mask;
  match_spec.ipv4_srcAddr = twl_match->ipv4_src;
  match_spec.ipv4_srcAddr_mask = twl_match->ipv4_src_mask;
  match_spec.ipv4_dstAddr = twl_match->ipv4_dst;
  match_spec.ipv4_dstAddr_mask = twl_match->ipv4_dst_mask;
  match_spec.ipv4_protocol = twl_match->ip_proto;
  match_spec.ipv4_protocol_mask = twl_match->ip_proto_mask;
  match_spec.ipv4_diffserv = twl_match->dscp;
  match_spec.ipv4_diffserv_mask = twl_match->dscp_mask;
  match_spec.l3_metadata_lkp_l4_sport_start = twl_match->l4_port_src_start;
  match_spec.l3_metadata_lkp_l4_sport_end = twl_match->l4_port_src_end;
  match_spec.l3_metadata_lkp_l4_dport_start = twl_match->l4_port_dst_start;
  match_spec.l3_metadata_lkp_l4_dport_end = twl_match->l4_port_dst_end;

  if (match_spec.ipv4_srcAddr_mask != 0 || match_spec.ipv4_dstAddr_mask != 0 ||
      match_spec.ipv4_protocol_mask != 0 ||
      match_spec.ipv4_diffserv_mask != 0 ||
      match_spec.l3_metadata_lkp_l4_sport_start != 0 ||
      match_spec.l3_metadata_lkp_l4_sport_end != 0xFFFF ||
      match_spec.l3_metadata_lkp_l4_dport_start != 0 ||
      match_spec.l3_metadata_lkp_l4_dport_end != 0xFFFF) {
    match_spec.ipv4_valid = 1;
    match_spec.ipv4_valid_mask = 1;
  } else {
    match_spec.ipv4_valid = 0;
    match_spec.ipv4_valid_mask = 0;
  }

#ifdef P4_DTEL_WATCH_INNER_ENABLE
  match_spec.tunnel_metadata_tunnel_vni = twl_match->tunnel_vni;
  match_spec.tunnel_metadata_tunnel_vni_mask = twl_match->tunnel_vni_mask;
  match_spec.inner_ethernet_etherType = twl_match->inner_ether_type;
  match_spec.inner_ethernet_etherType_mask = twl_match->inner_ether_type_mask;
  match_spec.inner_ipv4_srcAddr = twl_match->inner_ipv4_src;
  match_spec.inner_ipv4_srcAddr_mask = twl_match->inner_ipv4_src_mask;
  match_spec.inner_ipv4_dstAddr = twl_match->inner_ipv4_dst;
  match_spec.inner_ipv4_dstAddr_mask = twl_match->inner_ipv4_dst_mask;
  match_spec.inner_ipv4_protocol = twl_match->inner_ip_proto;
  match_spec.inner_ipv4_protocol_mask = twl_match->inner_ip_proto_mask;
  match_spec.inner_l4_ports_srcPort_start = twl_match->inner_l4_port_src_start;
  match_spec.inner_l4_ports_srcPort_end = twl_match->inner_l4_port_src_end;
  match_spec.inner_l4_ports_dstPort_start = twl_match->inner_l4_port_dst_start;
  match_spec.inner_l4_ports_dstPort_end = twl_match->inner_l4_port_dst_end;

  if (match_spec.inner_ipv4_srcAddr_mask != 0 ||
      match_spec.inner_ipv4_dstAddr_mask != 0 ||
      match_spec.inner_ipv4_protocol_mask != 0 ||
      match_spec.inner_l4_ports_srcPort_start != 0 ||
      match_spec.inner_l4_ports_srcPort_end != 0xFFFF ||
      match_spec.inner_l4_ports_dstPort_start != 0 ||
      match_spec.inner_l4_ports_dstPort_end != 0xFFFF) {
    match_spec.inner_ipv4_valid = 1;
    match_spec.inner_ipv4_valid_mask = 1;
  } else {
    match_spec.inner_ipv4_valid = 0;
    match_spec.inner_ipv4_valid_mask = 0;
  }
#endif  // P4_DTEL_WATCH_INNER_ENABLE

  if (watch && action_params->_int.flow_sample_percent == 0) {
    // no_watch is more accurate because of <= in data plane
    watch = false;
  }

  if (watch) {
    p4_pd_dc_int_watch_sample_action_spec_t action_spec;
    action_spec.action_config_session_id = action_params->_int.session_id;
    action_spec.action_digest_enb = !action_params->_int.report_all_packets;
    action_spec.action_sample_index =
        action_params->_int.flow_sample_percent;  // sample_index i keeps
                                                  // percent i
    pd_status = p4_pd_dc_int_watchlist_table_add_with_int_watch_sample(
        switch_cfg_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority,
        &action_spec,
        entry_hdl);
  } else {
    pd_status = p4_pd_dc_int_watchlist_table_add_with_int_not_watch(
        switch_cfg_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
  }
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD
  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG("INT watchlist add success on device %d handle 0x%x\n",
                        device,
                        *entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR("INT watchlist add failed on device %d : %s (pd: 0x%x)",
                        device,
                        switch_error_to_string(status),
                        pd_status);
  }
  return status;
}

switch_status_t switch_pd_dtel_int_watchlist_entry_update(
    switch_device_t device,
    switch_pd_hdl_t entry_hdl,
    bool watch,
    switch_twl_action_params_t *action_params) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(watch);
  UNUSED(action_params);
  UNUSED(entry_hdl);
  UNUSED(status);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  if (watch && action_params->_int.flow_sample_percent == 0) {
    // no_watch is more accurate because of <= in data plane
    watch = false;
  }

  if (watch) {
    p4_pd_dc_int_watch_sample_action_spec_t action_spec;
    action_spec.action_config_session_id = action_params->_int.session_id;
    action_spec.action_digest_enb = !action_params->_int.report_all_packets;
    action_spec.action_sample_index =
        action_params->_int.flow_sample_percent;  // sample_index i keeps
                                                  // percent i
    pd_status = p4_pd_dc_int_watchlist_table_modify_with_int_watch_sample(
        switch_cfg_sess_hdl, device, entry_hdl, &action_spec);
  } else {
    pd_status = p4_pd_dc_int_watchlist_table_modify_with_int_not_watch(
        switch_cfg_sess_hdl, device, entry_hdl);
  }

  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD
  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT watchlist update success on device %d handle 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT watchlist update failed on device %d : %s (pd: 0x%x) handle "
        "0x%x",
        device,
        switch_error_to_string(status),
        pd_status,
        entry_hdl);
  }
  return status;
}

switch_status_t switch_pd_dtel_int_watchlist_entry_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;
  UNUSED(device);
  UNUSED(status);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_INT_EP_ENABLE
  pd_status = p4_pd_dc_int_watchlist_table_delete(
      switch_cfg_sess_hdl, device, entry_hdl);
  p4_pd_complete_operations(switch_cfg_sess_hdl);
  status = switch_pd_status_to_status(pd_status);
#endif  // P4_INT_EP_ENABLE
#endif  // SWITCH_PD
  if (status == SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_DEBUG(
        "INT watchlist delete success on device %d handle 0x%x\n",
        device,
        entry_hdl);
  } else {
    SWITCH_PD_LOG_ERROR(
        "INT watchlist delete failed on device %d : %s (pd: 0x%x) handle "
        "0x%x",
        device,
        switch_error_to_string(status),
        pd_status,
        entry_hdl);
  }
  return status;
}
