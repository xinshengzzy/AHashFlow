/*
Copyright 2013-present Barefoot Networks, Inc.
*/

#include "switch_internal.h"
#include "switch_pd.h"
#include <math.h>

switch_status_t switch_pd_egress_queue_stats_table_entry_add(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    switch_pd_hdl_t *entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(queue_id);
  UNUSED(entry_hdl);
  UNUSED(status);
  UNUSED(pd_status);

#ifdef SWITCH_PD
#ifdef P4_EGRESS_QUEUE_STATS_ENABLE
  p4_pd_dc_egress_queue_stats_match_spec_t match_spec = {0};
  p4_pd_dev_target_t p4_pd_device;

  match_spec.eg_intr_md_egress_port = dev_port;
  match_spec.ig_intr_md_for_tm_qid = queue_id;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#if !(defined(__p4c__))
  pd_status = p4_pd_dc_egress_queue_stats_table_add_with_nop(
      switch_cfg_sess_hdl, p4_pd_device, &match_spec, entry_hdl);
#endif
  if (switch_pd_log_level_debug()) {
    switch_pd_dump_entry_t pd_entry;
    SWITCH_MEMSET(&pd_entry, 0x0, sizeof(pd_entry));
    pd_entry.entry_type = SWITCH_PD_ENTRY_ADD;
    pd_entry.match_spec = (switch_uint8_t *)&match_spec;
    pd_entry.action_spec = NULL;
    pd_entry.match_spec_size = sizeof(match_spec);
    pd_entry.action_spec_size = 0;
    pd_entry.pd_hdl = *entry_hdl;
    switch_pd_entry_dump(device, &pd_entry);
  }

  p4_pd_complete_operations(switch_cfg_sess_hdl);
#endif /* P4_EGRESS_QUEUE_STATS_ENABLE */
#endif /* SWITCH_PD */

  status = switch_pd_status_to_status(pd_status);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "Failed to add egress queue stats table entry for device %d",
        "dev port %d queue id %d: %s",
        device,
        dev_port,
        queue_id,
        switch_error_to_string(status));
  }
  return status;
}

switch_status_t switch_pd_egress_queue_stats_table_entry_delete(
    switch_device_t device, switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD
#ifdef P4_EGRESS_QUEUE_STATS_ENABLE
  pd_status = p4_pd_dc_egress_queue_stats_table_delete(
      switch_cfg_sess_hdl, device, entry_hdl);
  p4_pd_complete_operations(switch_cfg_sess_hdl);
#endif /* P4_EGRESS_QUEUE_STATS_ENABLE */
#endif /* SWITCH_PD */

  status = switch_pd_status_to_status(pd_status);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "Failed to delete egress queue stats table entry for device %d",
        "entry_hdl 0x%lx: %s",
        device,
        entry_hdl,
        switch_error_to_string(status));
  }
  return status;
}

switch_status_t switch_pd_egress_queue_stats_get(
    switch_device_t device,
    switch_pd_hdl_t entry_hdl,
    switch_counter_t *queue_stats) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);
  UNUSED(queue_stats);

#ifdef SWITCH_PD
#ifdef P4_EGRESS_QUEUE_STATS_ENABLE
  p4_pd_counter_value_t counter = {0};
  p4_pd_dev_target_t p4_pd_device;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

  pd_status = p4_pd_dc_counter_read_egress_queue_stats(
      switch_cfg_sess_hdl,
      p4_pd_device,
      entry_hdl,
      switch_pd_counter_read_flags(device),
      &counter);

  queue_stats->num_packets = counter.packets;
  queue_stats->num_bytes = counter.bytes;

  p4_pd_complete_operations(switch_cfg_sess_hdl);
#endif /* P4_EGRESS_QUEUE_STATS_ENABLE */
#endif /* SWITCH_PD */

  status = switch_pd_status_to_status(pd_status);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR("Failed to get egress queue stats for device %d",
                        "entry handle 0x%lx: %s",
                        device,
                        entry_hdl,
                        switch_error_to_string(status));
  }
  return status;
}

switch_status_t switch_pd_egress_queue_stats_clear(switch_device_t device,
                                                   switch_pd_hdl_t entry_hdl) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_pd_status_t pd_status = SWITCH_PD_STATUS_SUCCESS;

  UNUSED(device);
  UNUSED(entry_hdl);

#ifdef SWITCH_PD
#ifdef P4_EGRESS_QUEUE_STATS_ENABLE
  p4_pd_counter_value_t counter = {0};
  p4_pd_dev_target_t p4_pd_device;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

  pd_status = p4_pd_dc_counter_write_egress_queue_stats(
      switch_cfg_sess_hdl, p4_pd_device, entry_hdl, counter);

  p4_pd_complete_operations(switch_cfg_sess_hdl);
#endif /* P4_EGRESS_QUEUE_STATS_ENABLE */
#endif /* SWITCH_PD */

  status = switch_pd_status_to_status(pd_status);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR("Failed to get egress queue stats for device %d",
                        "entry handle 0x%lx: %s",
                        device,
                        entry_hdl,
                        switch_error_to_string(status));
  }
  return status;
}
#if !defined(BMV2TOFINO) && !defined(BMV2)

switch_status_t switch_pd_queue_pool_usage_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    switch_pd_pool_id_t pool_id,
    switch_api_buffer_profile_t *buffer_profile_info,
    bool enable) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  p4_pd_tm_queue_baf_t dyn_baf = PD_Q_BAF_DISABLE;
  switch_uint32_t buffer_cells = 0;
  switch_uint32_t default_hysteresis = 0, default_buffer, default_baf,
                  default_pool_id;
  switch_uint32_t threshold = 0;
  switch_uint32_t buffer_size = 0;

  if (enable) {
    if (buffer_profile_info->threshold_mode ==
        SWITCH_BUFFER_THRESHOLD_MODE_DYNAMIC) {
      /*
       * Hardware supports 8 different dynamic thresholds -
       * p4_pd_tm_queue_baf_t.
       * Distributing the thresholds based on the threshold factor(32).
       */
      threshold = (buffer_profile_info->threshold == 0)
                      ? SWITCH_BUFFER_MAX_THRESHOLD
                      : buffer_profile_info->threshold;
      if (threshold == SWITCH_BUFFER_MAX_THRESHOLD) {
        dyn_baf = PD_Q_BAF_80_PERCENT;
      } else {
        dyn_baf = (p4_pd_tm_queue_baf_t)(threshold / DYNAMIC_THRESHOLD_FACTOR);
      }
    }
    buffer_size = buffer_profile_info->buffer_size;
    /*
     * Driver expects the buffer size in cells.
     */
    switch_pd_buffer_bytes_to_cells(device, buffer_size, &buffer_cells);

    /*
     * Get the default hysteresis for buffer pool and set it.
     */
    p4_pd_tm_get_q_app_pool_usage(device,
                                  dev_port,
                                  queue_id,
                                  &default_pool_id,
                                  &default_buffer,
                                  &default_baf,
                                  &default_hysteresis);
    status = p4_pd_tm_set_q_app_pool_usage(device,
                                           dev_port,
                                           queue_id,
                                           pool_id,
                                           buffer_cells,
                                           dyn_baf,
                                           default_hysteresis);
  } else {
    status = p4_pd_tm_disable_q_app_pool_usage(device, dev_port, queue_id);
  }
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */

  return status;
}

switch_status_t switch_pd_queue_color_drop_enable(switch_device_t device,
                                                  switch_dev_port_t dev_port,
                                                  switch_qid_t queue_id,
                                                  bool enable) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
  if (enable) {
    status = p4_pd_tm_enable_q_color_drop(device, dev_port, queue_id);
  } else {
    status = p4_pd_tm_disable_q_color_drop(device, dev_port, queue_id);
  }
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_guaranteed_min_limit_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    uint32_t limit) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
  switch_uint32_t num_cells = 0;
  switch_pd_buffer_bytes_to_cells(device, limit, &num_cells);
  status = p4_pd_tm_set_q_guaranteed_min_limit(
      device, dev_port, queue_id, num_cells);
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_color_limit_set(switch_device_t device,
                                                switch_dev_port_t dev_port,
                                                switch_qid_t queue_id,
                                                switch_color_t color,
                                                uint32_t limit) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
  switch_uint32_t num_cells = 0;
  switch_pd_buffer_bytes_to_cells(device, limit, &num_cells);
  status =
      p4_pd_tm_set_q_color_limit(device, dev_port, queue_id, color, num_cells);
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_color_hysteresis_set(switch_device_t device,
                                                     switch_dev_port_t dev_port,
                                                     switch_qid_t queue_id,
                                                     switch_color_t color,
                                                     uint32_t limit) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  switch_uint32_t num_cells = 0;
  switch_pd_buffer_bytes_to_cells(device, limit, &num_cells);
  status = p4_pd_tm_set_q_color_hysteresis(
      device, dev_port, queue_id, color, num_cells);
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_pfc_cos_mapping(switch_device_t device,
                                                switch_dev_port_t dev_port,
                                                switch_qid_t queue_id,
                                                uint8_t cos) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  status = p4_pd_tm_set_q_pfc_cos_mapping(device, dev_port, queue_id, cos);
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_port_mapping(switch_device_t device,
                                             switch_dev_port_t dev_port,
                                             uint8_t queue_count,
                                             switch_qid_t *queue_mapping) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  status =
      p4_pd_tm_set_port_q_mapping(device, dev_port, queue_count, queue_mapping);
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_scheduling_enable(switch_device_t device,
                                                  switch_dev_port_t dev_port,
                                                  switch_qid_t queue_id,
                                                  bool enable) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  if (enable) {
    status = p4_pd_tm_enable_q_sched(device, dev_port, queue_id);
  } else {
    status = p4_pd_tm_disable_q_sched(device, dev_port, queue_id);
  }
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
p4_pd_tm_sched_prio_t switch_scheduler_priority_to_pd_scheduler_priority(
    switch_scheduler_priority_t priority) {
  switch (priority) {
    case SWITCH_SCHEDULER_PRIORITY_0:
      return PD_TM_SCH_PRIO_0;
    case SWITCH_SCHEDULER_PRIORITY_1:
      return PD_TM_SCH_PRIO_1;
    case SWITCH_SCHEDULER_PRIORITY_2:
      return PD_TM_SCH_PRIO_2;
    case SWITCH_SCHEDULER_PRIORITY_3:
      return PD_TM_SCH_PRIO_3;
    case SWITCH_SCHEDULER_PRIORITY_4:
      return PD_TM_SCH_PRIO_4;
    case SWITCH_SCHEDULER_PRIORITY_5:
      return PD_TM_SCH_PRIO_5;
    case SWITCH_SCHEDULER_PRIORITY_6:
      return PD_TM_SCH_PRIO_6;
    case SWITCH_SCHEDULER_PRIORITY_7:
      return PD_TM_SCH_PRIO_7;
    default:
      return PD_TM_SCH_PRIO_LOW;
  }
}
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */

switch_status_t switch_pd_queue_scheduling_strict_priority_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    switch_scheduler_priority_t priority) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  p4_pd_tm_sched_prio_t pd_scheduler_priority =
      switch_scheduler_priority_to_pd_scheduler_priority(priority);
  status = p4_pd_tm_set_q_sched_priority(
      device, dev_port, queue_id, pd_scheduler_priority);
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_scheduling_remaining_bw_priority_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    uint32_t priority) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  status = p4_pd_tm_set_q_remaining_bw_sched_priority(
      device, dev_port, queue_id, priority);
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

/*
 * SAI's valid range for weight is 1-100 and hardware supports
 * 0-1023 value.
 */
#define SWITCH_PD_WEIGHT(weight) (weight * 100)
switch_status_t switch_pd_queue_scheduling_dwrr_weight_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    uint16_t weight) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE
  status = p4_pd_tm_set_q_dwrr_weight(
      device, dev_port, queue_id, SWITCH_PD_WEIGHT(weight));
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

uint32_t switch_api_shaping_rate_kbps(uint64_t rate_bps) {
  uint32_t rate_kbps = ceil(rate_bps / 1000);
  return rate_kbps;
}

switch_status_t switch_pd_queue_guaranteed_rate_set(switch_device_t device,
                                                    switch_dev_port_t dev_port,
                                                    switch_qid_t queue_id,
                                                    bool pps,
                                                    uint32_t burst_size,
                                                    uint64_t rate) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
#ifdef P4_QOS_CLASSIFICATION_ENABLE

  uint32_t min_rate = 0;

  if (pps) {
    min_rate = rate;
  } else {
    min_rate = switch_api_shaping_rate_kbps(rate);
  }
  status = p4_pd_tm_set_q_guaranteed_rate(
      device, dev_port, queue_id, pps, burst_size, min_rate);

  if (status != SWITCH_STATUS_SUCCESS) {
    return status;
  }

  if (min_rate) {
    status = p4_pd_tm_q_min_rate_shaper_enable(device, dev_port, queue_id);
  } else {
    status = p4_pd_tm_q_min_rate_shaper_disable(device, dev_port, queue_id);
  }
#endif /* P4_QOS_CLASSIFICATION_ENABLE */
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_port_shaping_set(switch_device_t device,
                                           switch_dev_port_t dev_port,
                                           bool pps,
                                           uint32_t burst_size,
                                           uint64_t rate) {
  switch_status_t status = 0;
  uint32_t shaping_rate = 0;

#ifdef SWITCH_PD
  if (pps) {
    shaping_rate = rate;
  } else {
    shaping_rate = switch_api_shaping_rate_kbps(rate);
  }
  status = p4_pd_tm_set_port_shaping_rate(
      device, dev_port, pps, burst_size, shaping_rate);

#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_shaping_set(switch_device_t device,
                                            switch_dev_port_t dev_port,
                                            switch_qid_t queue_id,
                                            bool pps,
                                            uint32_t burst_size,
                                            uint64_t rate) {
  switch_status_t status = 0;
  uint32_t shaping_rate;

#ifdef SWITCH_PD
  if (pps) {
    shaping_rate = rate;
  } else {
    shaping_rate = switch_api_shaping_rate_kbps(rate);
  }
  status = p4_pd_tm_set_q_shaping_rate(
      device, dev_port, queue_id, pps, burst_size, shaping_rate);

  if (status != SWITCH_STATUS_SUCCESS) {
    return status;
  }

  if (shaping_rate) {
    status = p4_pd_tm_q_max_rate_shaper_enable(device, dev_port, queue_id);
  } else {
    status = p4_pd_tm_q_max_rate_shaper_disable(device, dev_port, queue_id);
  }
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_dtel_tail_drop_deflection_queue_set(
    switch_device_t device,
    switch_pipe_t pipe_id,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id) {
  switch_status_t status = 0;

#ifdef SWITCH_PD
  status =
      p4_pd_tm_set_negative_mirror_dest(device, pipe_id, dev_port, queue_id);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_PD_LOG_ERROR(
        "mod queue set failed on device %d "
        "TM set deflect on drop on pipe %d devport %d "
        "and queue %d failed:(%s)\n",
        device,
        pipe_id,
        dev_port,
        queue_id,
        switch_error_to_string(status));

    return status;
  }
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_drop_count_get(switch_device_t device,
                                               switch_dev_port_t dev_port,
                                               switch_qid_t queue_id,
                                               uint64_t *num_packets) {
  switch_status_t status = 0;
#ifdef SWITCH_PD
  status = p4_pd_tm_q_drop_get(device, 0x0, dev_port, queue_id, num_packets);
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_drop_count_clear(switch_device_t device,
                                                 switch_dev_port_t dev_port,
                                                 switch_qid_t queue_id) {
  switch_status_t status = 0;
#ifdef SWITCH_PD
  status = p4_pd_tm_q_drop_count_clear(device, dev_port, queue_id);
#endif /* SWITCH_PD */
  return status;
}

switch_status_t switch_pd_queue_usage_get(switch_device_t device,
                                          switch_dev_port_t dev_port,
                                          switch_qid_t queue_id,
                                          uint64_t *inuse_bytes,
                                          uint64_t *wm_bytes) {
  switch_status_t status = 0;
#ifdef SWITCH_PD
  switch_uint32_t inuse_cells = 0;
  switch_uint32_t wm_cells = 0;
  status = p4_pd_tm_q_usage_get(
      device, 0x0, dev_port, queue_id, &inuse_cells, &wm_cells);
  switch_pd_buffer_cells_to_bytes(device, inuse_cells, inuse_bytes);
  switch_pd_buffer_cells_to_bytes(device, wm_cells, wm_bytes);

#endif /* SWITCH_PD */
  return status;
}

#else

switch_status_t switch_pd_queue_pool_usage_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    switch_pd_pool_id_t pool_id,
    switch_api_buffer_profile_t *buffer_profile_info,
    bool enable) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_color_drop_enable(switch_device_t device,
                                                  switch_dev_port_t dev_port,
                                                  switch_qid_t queue_id,
                                                  bool enable) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_color_limit_set(switch_device_t device,
                                                switch_dev_port_t dev_port,
                                                switch_qid_t queue_id,
                                                switch_color_t color,
                                                uint32_t limit) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_color_hysteresis_set(switch_device_t device,
                                                     switch_dev_port_t dev_port,
                                                     switch_qid_t queue_id,
                                                     switch_color_t color,
                                                     uint32_t limit) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_pfc_cos_mapping(switch_device_t device,
                                                switch_dev_port_t dev_port,
                                                switch_qid_t queue_id,
                                                uint8_t cos) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_port_mapping(switch_device_t device,
                                             switch_dev_port_t dev_port,
                                             uint8_t queue_count,
                                             uint8_t *queue_mapping) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_scheduling_enable(switch_device_t device,
                                                  switch_dev_port_t dev_port,
                                                  switch_qid_t queue_id,
                                                  bool enable) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_scheduling_strict_priority_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    switch_scheduler_priority_t priority) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_scheduling_remaining_bw_priority_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    uint32_t priority) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_scheduling_dwrr_weight_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    uint16_t weight) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_scheduling_guaranteed_shaping_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    bool pps,
    uint32_t burst_size,
    uint32_t rate) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_port_shaping_set(switch_device_t device,
                                           switch_dev_port_t dev_port,
                                           bool pps,
                                           uint32_t burst_size,
                                           uint64_t rate) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_scheduling_dwrr_shaping_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    bool pps,
    uint32_t burst_size,
    uint32_t rate) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_dtel_tail_drop_deflection_queue_set(
    switch_device_t device,
    switch_pipe_t pipe_id,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_shaping_set(switch_device_t device,
                                            switch_dev_port_t dev_port,
                                            switch_qid_t queue_id,
                                            bool pps,
                                            uint32_t burst_size,
                                            uint64_t rate) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_guaranteed_rate_set(switch_device_t device,
                                                    switch_dev_port_t dev_port,
                                                    switch_qid_t queue_id,
                                                    bool pps,
                                                    uint32_t burst_size,
                                                    uint64_t rate) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_drop_count_get(switch_device_t device,
                                               switch_dev_port_t dev_port,
                                               switch_qid_t queue_id,
                                               uint64_t *num_packets) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_drop_count_clear(switch_device_t device,
                                                 switch_dev_port_t dev_port,
                                                 switch_qid_t queue_id) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_guaranteed_min_limit_set(
    switch_device_t device,
    switch_dev_port_t dev_port,
    switch_qid_t queue_id,
    uint32_t limit) {
  switch_status_t status = 0;
  return status;
}

switch_status_t switch_pd_queue_usage_get(switch_device_t device,
                                          switch_dev_port_t dev_port,
                                          switch_qid_t queue_id,
                                          uint64_t *inuse_bytes,
                                          uint64_t *wm_bytes) {
  switch_status_t status = 0;
  return status;
}
#endif /* BMV2TOFINO && BMV2 */
