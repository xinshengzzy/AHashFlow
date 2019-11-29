################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2015-2016 Barefoot Networks, Inc.

# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, # Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material is
# strictly forbidden unless prior written permission is obtained from
# Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a
# written agreement with Barefoot Networks, Inc.
#
# $Id: $
#
###############################################################################
"""
Thrift API interface basic tests
"""

import switchapi_thrift

import time
import sys
import logging

import unittest
import random

import ptf.dataplane as dataplane
import api_base_tests
import pd_base_tests
try:
    import pltfm_pm_rpc
    from pltfm_pm_rpc.ttypes import *
except ImportError:
    pass

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *

import os
import ptf.mask

from switchapi_thrift.ttypes import *
from switchapi_thrift.switch_api_headers import *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '..'))
from common.utils import *

device = 0
cpu_port = 64

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)

if swports == []:
    swports = [x for x in range(65)]

###############################################################################

@group('copp-stats')
class BGPCoppStatsTest(pd_base_tests.ThriftInterfaceDataPlane,
                        api_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, ["switch"],
                                                        ["dc"])

    def runTest(self):
        print

        devport = []
        for i in range(0,4):
            devport.append(swport_to_devport(self, swports[i]))
        print devport
        self.cpu_port = get_cpu_port(self)
        api_base_tests.ThriftInterfaceDataPlane.setUp(self)
        self.client.switch_api_init(device)

        cpu_port_handle = self.client.switch_api_port_id_to_handle_get(device, self.cpu_port)
        queue_handles = self.client.switch_api_queues_get(device, cpu_port_handle)
      
        api_meter_info = switcht_meter_info_t(
            meter_mode=1,
            color_source=1,
            meter_type=1,
            cbs=10,
            cir=10,
            pbs=10,
            pir=10,
            green_action=2,
            yellow_action=2,
            red_action=1)
        meter_handle_list = []
        meter_handle = self.client.switch_api_hostif_meter_create(0, api_meter_info)
        hostif_group1 = switcht_hostif_group_t(queue_handles[0], policer_handle=meter_handle)
        hostif_group_id1 = self.client.switch_api_hostif_group_create(
            device, hostif_group1)

        flags = 0
        flags |= SWITCH_HOSTIF_RCODE_ATTR_REASON_CODE
        flags |= SWITCH_HOSTIF_RCODE_ATTR_PACKET_ACTION
        flags |= SWITCH_HOSTIF_RCODE_ATTR_HOSTIF_GROUP
        bgp_rcode_info = switcht_hostif_rcode_info_t(
            reason_code=SWITCH_HOSTIF_REASON_CODE_BGP,
            action=SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
            hostif_group_id=hostif_group_id1,
            priority=50)
        rcode_handle1 = self.client.switch_api_hostif_reason_code_create(
            device, flags, bgp_rcode_info)

        vrf = self.client.switch_api_vrf_create(device, 2)
        vlan_id = 10
        vlan = self.client.switch_api_vlan_create(device, vlan_id)

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])
        port3 = self.client.switch_api_port_id_to_handle_get(device, swports[3])

        rmac = self.client.switch_api_router_mac_group_create(
            device, SWITCH_RMAC_TYPE_INNER)
        self.client.switch_api_router_mac_add(device, rmac, '00:77:66:55:44:33')

        i_info1 = switcht_interface_info_t(
            handle=port1, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if1 = self.client.switch_api_interface_create(device, i_info1)

        i_info2 = switcht_interface_info_t(
            handle=port2, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if2 = self.client.switch_api_interface_create(device, i_info2)

        self.client.switch_api_vlan_member_add(device, vlan, if1)
        self.client.switch_api_vlan_member_add(device, vlan, if2)

        self.client.switch_api_mac_table_entry_create(
            device, vlan, '00:22:22:22:22:22', 2, if2)

        rif_info3 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_INTF,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=1,
            v6_unicast_enabled=1)
        rif3 = self.client.switch_api_rif_create(0, rif_info3)
        i_info3 = switcht_interface_info_t(
            handle=port3, type=SWITCH_INTERFACE_TYPE_PORT, rif_handle=rif3)
        if3 = self.client.switch_api_interface_create(device, i_info3)
        i_ip3 = switcht_ip_addr_t(
            addr_type=SWITCH_API_IP_ADDR_V4,
            ipaddr='192.168.0.2',
            prefix_length=16)
        self.client.switch_api_l3_interface_address_add(device, rif3, vrf,
                                                        i_ip3)

        rif_info4 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_VLAN,
            vlan=vlan_id,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=1,
            v6_unicast_enabled=1)
        rif4 = self.client.switch_api_rif_create(0, rif_info4)
        i_ip4 = switcht_ip_addr_t(
            addr_type=SWITCH_API_IP_ADDR_V4,
            ipaddr='172.16.0.2',
            prefix_length=16)
        self.client.switch_api_l3_interface_address_add(device, rif4, vrf,
                                                        i_ip4)

        # Add a static route
        i_ip41 = switcht_ip_addr_t(
            addr_type=SWITCH_API_IP_ADDR_V4,
            ipaddr='172.20.10.1',
            prefix_length=32)
        nhop_key41 = switcht_nhop_key_t(intf_handle=rif4, ip_addr_valid=0)
        nhop41 = self.client.switch_api_nhop_create(device, nhop_key41)
        self.client.switch_api_l3_route_add(device, vrf, i_ip41, nhop41)

        # send the test packet(s)
        try:
            pkt1 = simple_tcp_packet(
                eth_dst='00:77:66:55:44:33',
                eth_src='00:66:66:66:66:66',
                ip_dst='172.16.0.2',
                ip_src='192.168.0.1',
                ip_id=105,
                ip_ttl=64,
                tcp_dport=179)
            ingress_ifindex = self.client.switch_api_interface_ifindex_get(
                device, if3)

            exp_pkt1 = simple_cpu_packet(
                ingress_port=devport[3],
                ingress_ifindex=ingress_ifindex,
                reason_code=0x401,
                ingress_bd=2,
                inner_pkt=pkt1)
            exp_pkt1 = cpu_packet_mask_ingress_bd(exp_pkt1)
            print "Sending bgp packet l3 port %d" % swports[
                3], "to cpu %d with reason_code=bgp" % self.cpu_port
            total_packets = 40
            send_packet(self, swports[3], str(pkt1),total_packets)
            time.sleep(20)
            meter_counter = self.client.switch_api_hostif_meter_stats_get(device, meter_handle)
            packet_count = 0
            green_count = meter_counter[0].num_packets
            red_count = meter_counter[2].num_packets
            print "meter_counter", meter_counter
            print "Green %d, Red %d"%(green_count, red_count)
            packet_count = green_count + red_count
            print "Total packet count %d"%(packet_count)
            self.assertTrue(packet_count == total_packets)

        finally:
            self.client.switch_api_l3_route_delete(device, vrf, i_ip41, nhop41)
            self.client.switch_api_nhop_delete(device, nhop41)

            self.client.switch_api_l3_interface_address_delete(device, rif3,
                                                               vrf, i_ip3)
            self.client.switch_api_l3_interface_address_delete(device, rif4,
                                                               vrf, i_ip4)

            self.client.switch_api_mac_table_entry_delete(device, vlan,
                                                          '00:22:22:22:22:22')

            self.client.switch_api_vlan_member_remove(device, vlan, if1)
            self.client.switch_api_vlan_member_remove(device, vlan, if2)

            self.client.switch_api_interface_delete(device, if1)
            self.client.switch_api_interface_delete(device, if2)
            self.client.switch_api_interface_delete(device, if3)

            self.client.switch_api_rif_delete(0, rif3)
            self.client.switch_api_rif_delete(0, rif4)

            self.client.switch_api_vlan_delete(device, vlan)

            self.client.switch_api_router_mac_delete(device, rmac,
                                                     '00:77:66:55:44:33')
            self.client.switch_api_router_mac_group_delete(device, rmac)
            self.client.switch_api_vrf_delete(device, vrf)
            self.client.switch_api_hostif_group_delete(device, hostif_group_id1)
            self.client.switch_api_hostif_meter_stats_clear(0, meter_handle)
            self.client.switch_api_hostif_meter_delete(0, meter_handle)
            self.client.switch_api_hostif_reason_code_delete(device, rcode_handle1)

@group('copp-learn-dis')
class LLDPMacLearnDisableTest(api_base_tests.ThriftInterfaceDataPlane):
    def sendL2Packet(self, port, learn_disable):
        src_mac = '00:00:00:00:00:'
        for i in range(1,10):
          eth_src = src_mac+str(i)
          print eth_src
          pkt = simple_eth_packet(
              eth_dst='01:80:c2:00:00:0e',
              eth_src=eth_src,
            eth_type=0x88cc)
          send_packet(self, port, str(pkt))

        time.sleep(10)
        count = self.client.switch_api_mac_table_entry_count_get(0)
        print "Total mac count %d"%(count)
        if learn_disable is 0:
          self.assertTrue(count != 0)
        else:
          self.assertTrue(count == 0)
    def runTest(self):
        print
        vlan = self.client.switch_api_vlan_create(device, 10)

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])
        port3 = self.client.switch_api_port_id_to_handle_get(device, swports[3])

        i_info1 = switcht_interface_info_t(
            handle=port1, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if1 = self.client.switch_api_interface_create(device, i_info1)
        ingress_ifindex = self.client.switch_api_interface_ifindex_get(device, if1)

        i_info2 = switcht_interface_info_t(
            handle=port2, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if2 = self.client.switch_api_interface_create(device, i_info2)

        i_info3 = switcht_interface_info_t(
            handle=port3, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if3 = self.client.switch_api_interface_create(device, i_info3)

        self.client.switch_api_vlan_member_add(device, vlan, if1)
        self.client.switch_api_vlan_member_add(device, vlan, if2)
        self.client.switch_api_vlan_member_add(device, vlan, if3)

        acl = self.client.switch_api_acl_list_create(
            0, SWITCH_API_DIRECTION_INGRESS, SWITCH_ACL_TYPE_SYSTEM,
            SWITCH_HANDLE_TYPE_PORT)
        # create kvp to match destination IP
        kvp = []
        kvp_val = switcht_acl_value_t(value_num=int("88cc", 16))
        kvp_mask = switcht_acl_value_t(value_num=int("ffff", 16))
        kvp.append(
            switcht_acl_key_value_pair_t(SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE,
                                         kvp_val, kvp_mask))
        action = SWITCH_ACL_ACTION_PERMIT
        action_params = switcht_acl_action_params_t(
            cpu_redirect=switcht_acl_action_cpu_redirect(reason_code=SWITCH_HOSTIF_REASON_CODE_LLDP))
        opt_action_params = switcht_acl_opt_action_params_t(learn_disable=0)
        ace = self.client.switch_api_acl_system_rule_create(
            0, acl, 10, 1, kvp, action, action_params, opt_action_params)

        self.devport = []
        self.devport.append(swport_to_devport(self, swports[0]))
        self.devport.append(swport_to_devport(self, swports[1]))

        try:
          LLDPMacLearnDisableTest.sendL2Packet(self, swports[1], 0)

          self.client.switch_api_mac_table_entry_flush(
              device, SWITCH_MAC_FLUSH_TYPE_ALL, 0x0, 0x0)
          #raw_input("Try with learn disable")
          opt_action_params = switcht_acl_opt_action_params_t(learn_disable=1)
          self.client.switch_api_acl_entry_action_set(
              0, ace, 10, action, action_params, opt_action_params)
          LLDPMacLearnDisableTest.sendL2Packet(self, swports[1], 1)

          opt_action_params = switcht_acl_opt_action_params_t(learn_disable=0)
          self.client.switch_api_acl_entry_action_set(
              0, ace, 10, action, action_params, opt_action_params)
          LLDPMacLearnDisableTest.sendL2Packet(self, swports[1], 0)

        finally:
            self.client.switch_api_mac_table_entry_flush(
                device, SWITCH_MAC_FLUSH_TYPE_ALL, 0x0, 0x0)

            self.client.switch_api_vlan_member_remove(device, vlan, if1)
            self.client.switch_api_vlan_member_remove(device, vlan, if2)
            self.client.switch_api_vlan_member_remove(device, vlan, if3)

            self.client.switch_api_interface_delete(device, if1)
            self.client.switch_api_interface_delete(device, if2)
            self.client.switch_api_interface_delete(device, if3)

            self.client.switch_api_vlan_delete(device, vlan)
            self.client.switch_api_acl_rule_delete(device, acl, ace)
            self.client.switch_api_acl_list_delete(device, acl)

@group('copp-4tuple')
class SystemAclIpFieldsTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        vlan = self.client.switch_api_vlan_create(device, 10)

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])
        port3 = self.client.switch_api_port_id_to_handle_get(device, swports[3])

        i_info1 = switcht_interface_info_t(
            handle=port1, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if1 = self.client.switch_api_interface_create(device, i_info1)
        ingress_ifindex = self.client.switch_api_interface_ifindex_get(device, if1)

        i_info2 = switcht_interface_info_t(
            handle=port2, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if2 = self.client.switch_api_interface_create(device, i_info2)

        i_info3 = switcht_interface_info_t(
            handle=port3, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if3 = self.client.switch_api_interface_create(device, i_info3)

        self.client.switch_api_vlan_member_add(device, vlan, if1)
        self.client.switch_api_vlan_member_add(device, vlan, if2)
        self.client.switch_api_vlan_member_add(device, vlan, if3)

        acl = self.client.switch_api_acl_list_create(
            0, SWITCH_API_DIRECTION_INGRESS, SWITCH_ACL_TYPE_SYSTEM,
            SWITCH_HANDLE_TYPE_PORT)
        # create kvp to match TCP Souce port
        kvp = []
        kvp_val = switcht_acl_value_t(value_num=int("1000", 16))
        kvp_mask = switcht_acl_value_t(value_num=int("ffff", 16))
        kvp.append(
            switcht_acl_key_value_pair_t(SWITCH_ACL_SYSTEM_FIELD_L4_SOURCE_PORT,
                                         kvp_val, kvp_mask))
        kvp_val = switcht_acl_value_t(value_num=int("1000", 16))
        kvp_mask = switcht_acl_value_t(value_num=int("ffff", 16))
        kvp.append(
            switcht_acl_key_value_pair_t(SWITCH_ACL_SYSTEM_FIELD_L4_DEST_PORT,
                                         kvp_val, kvp_mask))
        kvp_val = switcht_acl_value_t(value_num=int("0a0a0a01", 16))
        kvp_mask = switcht_acl_value_t(value_num=int("ffffffff", 16))
        kvp.append(
            switcht_acl_key_value_pair_t(SWITCH_ACL_SYSTEM_FIELD_IPV4_DEST,
                                         kvp_val, kvp_mask))
        action = SWITCH_ACL_ACTION_DROP
        action_params = switcht_acl_action_params_t(
            drop=switcht_acl_action_drop(reason_code=SWITCH_HOSTIF_REASON_CODE_DROP))
        opt_action_params = switcht_acl_opt_action_params_t(learn_disable=0)
        ace = self.client.switch_api_acl_system_rule_create(
            0, acl, 10, 3, kvp, action, action_params, opt_action_params)

        try:
            pkt = simple_tcp_packet(
                eth_dst='00:77:66:55:44:33',
                eth_src='00:11:11:11:11:11',
                ip_dst='172.20.10.1',
                ip_src='11.11.11.1',
                ip_id=105,
                ip_ttl=64,
                tcp_sport=4096,
                tcp_dport=4096,
                pktlen=150)
            send_packet(self, swports[1], str(pkt))
            verify_no_other_packets(self, timeout=2)

        finally:
            self.client.switch_api_vlan_member_remove(device, vlan, if1)
            self.client.switch_api_vlan_member_remove(device, vlan, if2)
            self.client.switch_api_vlan_member_remove(device, vlan, if3)

            self.client.switch_api_interface_delete(device, if1)
            self.client.switch_api_interface_delete(device, if2)
            self.client.switch_api_interface_delete(device, if3)

            self.client.switch_api_vlan_delete(device, vlan)
            self.client.switch_api_acl_rule_delete(device, acl, ace)
            self.client.switch_api_acl_list_delete(device, acl)
