#include <saiobject.h>
#include <saistatus.h>
#include "saiinternal.h"
#include <switchapi/switch_device.h>

sai_status_t sai_get_maximum_attribute_count(_In_ sai_object_id_t switch_id,
                                             _In_ sai_object_type_t object_type,
                                             _Inout_ uint32_t *count) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_object_count(_In_ sai_object_id_t switch_id,
                                  _In_ sai_object_type_t object_type,
                                  _Inout_ uint32_t *count) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_object_key(_In_ sai_object_id_t switch_id,
                                _In_ sai_object_type_t object_type,
                                _In_ uint32_t object_count,
                                _Inout_ sai_object_key_t *object_list) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_bulk_get_attribute(_In_ sai_object_id_t switch_id,
                                    _In_ sai_object_type_t object_type,
                                    _In_ uint32_t object_count,
                                    _In_ const sai_object_key_t *object_key,
                                    _Inout_ uint32_t *attr_count,
                                    _Inout_ sai_attribute_t **attrs,
                                    _Inout_ sai_status_t *object_statuses) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_query_attribute_capability(
    _In_ sai_object_id_t switch_id,
    _In_ sai_object_type_t object_type,
    _In_ sai_attr_id_t attr_id,
    _Out_ sai_attr_capability_t *attr_capability) {
  switch_status_t switch_status;
  sai_status_t status = SAI_STATUS_SUCCESS;
  bool enabled = false;

  attr_capability->get_implemented = false;

  switch (object_type) {
    case SAI_OBJECT_TYPE_DTEL:
      switch_status = switch_api_device_feature_get(
          device, SWITCH_DEVICE_FEATURE_DTEL, &enabled);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("Feature capability get failed(%s)\n",
                      sai_status_to_string(status));
        return status;
      }

      if (enabled) {
        attr_capability->get_implemented = true;
      }
      break;
    default:
      return SAI_STATUS_SUCCESS;
  }

  return SAI_STATUS_SUCCESS;
}
