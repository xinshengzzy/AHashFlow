# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface ACL tests
"""

from switch import *
import sai_base_test
import switchapi_thrift
from switchapi_thrift.switch_api_headers import *
from switchapi_thrift.ttypes import *
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from switchsai_thrift.sai_headers import  *
from switch_utils import *
import time

@group('acl')
@group('acl-ocp')
class IPAclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.0.1 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # bind this ACL table to port2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src 192.168.0.1/255.255.255.0, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            verify_no_other_packets(self, timeout=2)
        finally:
            # unbind this ACL table from port2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port2, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)

@group('acl')
@group('acl-ocp')
class MACSrcAclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "This test is not supported. MAC lookup cannot be done for IP Packets in switch.p4"
        return

        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.0.1 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source MAC
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = '00:22:22:22:22:22'
        mac_dst = None
        mac_src_mask = 'ff:ff:ff:ff:ff:ff'
        mac_dst_mask = None
        ip_src = None
        ip_src_mask = None
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # bind this ACL table to port2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src mac 00:22:22:22:22:22, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            verify_no_other_packets(self, timeout=2)
        finally:
            # unbind this ACL table from port2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port2, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)

@group('acl')
@group('acl-ocp')
class L3AclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Testing L3AclTest"

        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.100.100 --->172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        L4_SRC_PORT = 1000
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_sport = L4_SRC_PORT,
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_sport = L4_SRC_PORT,
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP and SPORT
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.100.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None

        u32range = sai_thrift_range_t(min=1000, max=1000)
        acl_range_id = sai_thrift_create_acl_range(
            self.client, SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, u32range)
        range_list = [acl_range_id]

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # bind this ACL table to rif_id2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_router_interface_attribute(rif_id2, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src ip 192.168.100.1/255.255.255.0, SPORT 1000, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 0'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from rif_id2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_router_interface_attribute(rif_id2, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            self.client.sai_thrift_delete_acl_range(acl_range_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)

@group('acl')
@group('acl-ocp')
class SeqAclTableGroupTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.0.1 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"

        #Disable ACL optimization as the testcase creates two ACLs with same type.
        sai_base_test.ThriftInterface.createSwitchApiRpcClient(self)
        self.swclient.switch_api_config_acl_optimization_set(0, 0)
        # setup ACL table group
        group_stage = SAI_ACL_STAGE_INGRESS
        group_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL

        # create ACL table group
        acl_table_group_id = sai_thrift_create_acl_table_group(self.client,
            group_stage,
            group_bind_point_list,
            group_type)

        # setup ACL tables to block based on Source MAC
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        # create ACL table #1
        acl_table_id1 = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id1 = sai_thrift_create_acl_entry(self.client,
            acl_table_id1,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # create ACL table #2
        acl_table_id2 = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id2 = sai_thrift_create_acl_entry(self.client,
            acl_table_id2,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # setup ACL table group members
        group_member_priority1 = 1
        group_member_priority2 = 100

        # create ACL table group members
        acl_table_group_member_id1 = sai_thrift_create_acl_table_group_member(self.client,
            acl_table_group_id,
            acl_table_id1,
            group_member_priority1)
        acl_table_group_member_id2 = sai_thrift_create_acl_table_group_member(self.client,
            acl_table_group_id,
            acl_table_id2,
            group_member_priority2)

        # bind this ACL table group to port2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_group_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        try:
            assert acl_table_group_id > 0, 'acl_table_group_id is <= 0'
            assert acl_table_id1 > 0, 'acl_entry_id1 is <= 0'
            assert acl_entry_id1 > 0, 'acl_entry_id1 is <= 0'
            assert acl_table_id2 > 0, 'acl_entry_id2 is <= 0'
            assert acl_entry_id2 > 0, 'acl_entry_id2 is <= 0'
            assert acl_table_group_member_id1 > 0, 'acl_table_group_member_id1 is <= 0'
            assert acl_table_group_member_id2 > 0, 'acl_table_group_member_id2 is <= 0'

            print '#### ACL \'DROP, src mac 00:22:22:22:22:22, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from port2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port2, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_table_group_member(acl_table_group_member_id1)
            self.client.sai_thrift_remove_acl_table_group_member(acl_table_group_member_id2)
            self.client.sai_thrift_remove_acl_entry(acl_entry_id1)
            self.client.sai_thrift_remove_acl_table(acl_table_id1)
            self.client.sai_thrift_remove_acl_entry(acl_entry_id2)
            self.client.sai_thrift_remove_acl_table(acl_table_id2)
            self.client.sai_thrift_remove_acl_table_group(acl_table_group_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)
            self.swclient.switch_api_config_acl_optimization_set(0, 1)
            sai_base_test.ThriftInterface.closeSwitchApiRpcClient(self)

@group('acl')
@group('acl-ocp')
class MultBindAclTableGroupTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 4 -> [ptf_intf 1, ptf_intf 2, ptf_intf 3] (192.168.0.1 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        port3 = port_list[2]
        port4 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2, port3, port4])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port4, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id4, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id4)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id4)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            send_packet(self, 0, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_packet(self, exp_pkt, 3)
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_packet(self, exp_pkt, 3)
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 3'
            send_packet(self, 2, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_packet(self, exp_pkt, 3)
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet [ptf_intf 1, ptf_intf 2, ptf_intf 3] - [acl]->ptf_intf 4 (192.168.0.1 -[acl]-> 172.16.10.1 [id = 105])"

        # setup ACL table group
        group_stage = SAI_ACL_STAGE_INGRESS
        group_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL

        #Disable ACL optimization as the testcase creates two ACLs with same type.
        sai_base_test.ThriftInterface.createSwitchApiRpcClient(self)
        self.swclient.switch_api_config_acl_optimization_set(0, 0)
        # create ACL table group
        acl_table_group_id = sai_thrift_create_acl_table_group(self.client,
            group_stage,
            group_bind_point_list,
            group_type)

        # setup ACL tables to block based on Source MAC
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2, port3, port4]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        # create ACL table #1
        acl_table_id1 = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id1 = sai_thrift_create_acl_entry(self.client,
            acl_table_id1,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # create ACL table #2
        acl_table_id2 = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id2 = sai_thrift_create_acl_entry(self.client,
            acl_table_id2,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # setup ACL table group members
        group_member_priority1 = 1
        group_member_priority2 = 100

        # create ACL table group members
        acl_table_group_member_id1 = sai_thrift_create_acl_table_group_member(self.client,
            acl_table_group_id,
            acl_table_id1,
            group_member_priority1)
        acl_table_group_member_id2 = sai_thrift_create_acl_table_group_member(self.client,
            acl_table_group_id,
            acl_table_id2,
            group_member_priority2)

        # bind this ACL table group to port1, port2, port3 object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_group_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port1, attr)
        self.client.sai_thrift_set_port_attribute(port2, attr)
        self.client.sai_thrift_set_port_attribute(port3, attr)

        try:
            assert acl_table_group_id > 0, 'acl_table_group_id is <= 0'
            assert acl_table_id1 > 0, 'acl_entry_id1 is <= 0'
            assert acl_entry_id1 > 0, 'acl_entry_id1 is <= 0'
            assert acl_table_id2 > 0, 'acl_entry_id2 is <= 0'
            assert acl_entry_id2 > 0, 'acl_entry_id2 is <= 0'
            assert acl_table_group_member_id1 > 0, 'acl_table_group_member_id1 is <= 0'
            assert acl_table_group_member_id2 > 0, 'acl_table_group_member_id2 is <= 0'

            print '#### ACL \'DROP, src mac 00:22:22:22:22:22, in_ports[ptf_intf_1,2,3,4]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            send_packet(self, 0, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_no_other_packets(self, timeout=1)
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_no_other_packets(self, timeout=1)
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 3'
            send_packet(self, 2, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from port1, port2, port3 object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port1, attr)
            self.client.sai_thrift_set_port_attribute(port2, attr)
            self.client.sai_thrift_set_port_attribute(port3, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_table_group_member(acl_table_group_member_id1)
            self.client.sai_thrift_remove_acl_table_group_member(acl_table_group_member_id2)
            self.client.sai_thrift_remove_acl_entry(acl_entry_id1)
            self.client.sai_thrift_remove_acl_table(acl_table_id1)
            self.client.sai_thrift_remove_acl_entry(acl_entry_id2)
            self.client.sai_thrift_remove_acl_table(acl_table_id2)
            self.client.sai_thrift_remove_acl_table_group(acl_table_group_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id4)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id4, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2, port3, port4])
            self.client.sai_thrift_remove_virtual_router(vr_id)
            self.swclient.switch_api_config_acl_optimization_set(0, 1)
            sai_base_test.ThriftInterface.closeSwitchApiRpcClient(self)

@group('acl')
@group('acl-ocp')
class BindAclTableInGroupTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet [ptf_intf 1, ptf_intf 2, ptf_intf 3, ptf_intf 4]-> ptf_intf 5 (192.168.0.1 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2, port3, port4, port5])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port4, 0, v4_enabled, v6_enabled, mac)
        rif_id5 = sai_thrift_create_router_interface(self.client, vr_id, 1, port5, 0, v4_enabled, v6_enabled, mac)


        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.0'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id5, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id5)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id5)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_packet(self, exp_pkt, 5)
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 2, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_packet(self, exp_pkt, 5)
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 3'
            send_packet(self, 3, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_packet(self, exp_pkt, 5)
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            send_packet(self, 4, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_packet(self, exp_pkt, 5)
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet [ptf_intf 1, ptf_intf 2, ptf_intf 3, ptf_intf 4] -> ptf_intf 5 (192.168.0.1 ---> 172.16.10.1 [id = 105])"

        # setup ACL table group
        group_stage = SAI_ACL_STAGE_INGRESS
        group_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL

        #Disable ACL optimization as the testcase creates two ACLs with same type.
        sai_base_test.ThriftInterface.createSwitchApiRpcClient(self)
        self.swclient.switch_api_config_acl_optimization_set(0, 0)
        # create ACL table group
        acl_table_group_id = sai_thrift_create_acl_table_group(self.client,
            group_stage,
            group_bind_point_list,
            group_type)

        # setup ACL tables to block based on Source MAC
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2, port3, port4, port5]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        ingress_mirror_id = None
        egress_mirror_id = None
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        # create ACL table #1
        acl_table_id1 = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id1 = sai_thrift_create_acl_entry(self.client,
            acl_table_id1,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # create ACL table #2
        acl_table_id2 = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id2 = sai_thrift_create_acl_entry(self.client,
            acl_table_id2,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # setup ACL table group members
        group_member_priority1 = 1
        group_member_priority2 = 100

        # create ACL table group members
        acl_table_group_member_id1 = sai_thrift_create_acl_table_group_member(self.client,
            acl_table_group_id,
            acl_table_id1,
            group_member_priority1)
        acl_table_group_member_id2 = sai_thrift_create_acl_table_group_member(self.client,
            acl_table_group_id,
            acl_table_id2,
            group_member_priority2)

        # bind this ACL table group to port1, port2, port3, port4 object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_group_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        attr_value1 = sai_thrift_attribute_value_t(oid=acl_table_id2)
        attr1 = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port1, attr)
        self.client.sai_thrift_set_port_attribute(port2, attr)
        self.client.sai_thrift_set_port_attribute(port3, attr)
        self.client.sai_thrift_set_port_attribute(port4, attr1)

        try:
            assert acl_table_group_id > 0, 'acl_table_group_id is <= 0'
            assert acl_table_id1 > 0, 'acl_entry_id1 is <= 0'
            assert acl_entry_id1 > 0, 'acl_entry_id1 is <= 0'
            assert acl_table_id2 > 0, 'acl_entry_id2 is <= 0'
            assert acl_entry_id2 > 0, 'acl_entry_id2 is <= 0'
            assert acl_table_group_member_id1 > 0, 'acl_table_group_member_id1 is <= 0'
            assert acl_table_group_member_id2 > 0, 'acl_table_group_member_id2 is <= 0'

            print '#### ACL \'DROP, src mac 00:22:22:22:22:22, in_ports[ptf_intf_1,2,3,4]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            send_packet(self, 1, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_no_other_packets(self, timeout=1)
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 2, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_no_other_packets(self, timeout=1)
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 3'
            send_packet(self, 3, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_no_other_packets(self, timeout=1)
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            send_packet(self, 4, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 5'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from port1, port2, port3, port4 object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port1, attr)
            self.client.sai_thrift_set_port_attribute(port2, attr)
            self.client.sai_thrift_set_port_attribute(port3, attr)
            self.client.sai_thrift_set_port_attribute(port4, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_table_group_member(acl_table_group_member_id1)
            self.client.sai_thrift_remove_acl_table_group_member(acl_table_group_member_id2)
            self.client.sai_thrift_remove_acl_entry(acl_entry_id1)
            self.client.sai_thrift_remove_acl_table(acl_table_id1)
            self.client.sai_thrift_remove_acl_entry(acl_entry_id2)
            self.client.sai_thrift_remove_acl_table(acl_table_id2)
            self.client.sai_thrift_remove_acl_table_group(acl_table_group_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id5)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id5, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)
            self.client.sai_thrift_remove_router_interface(rif_id5)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2, port3, port4, port5])
            self.client.sai_thrift_remove_virtual_router(vr_id)
            self.swclient.switch_api_config_acl_optimization_set(0, 1)
            sai_base_test.ThriftInterface.closeSwitchApiRpcClient(self)

@group('acl')
@group('acl-ocp')
class L3AclRangeTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.100.100 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        L4_DST_PORT = 1000
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP and SPORT
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.100.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None

        u32range = sai_thrift_range_t(min=1000, max=1000)
        acl_range_id = sai_thrift_create_acl_range(
            self.client, SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE, u32range)
        range_list = [acl_range_id]
        print "ACL range created 0x%lx"%(acl_range_id)

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            None,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        print "ACL Table created 0x%lx"%(acl_table_id)

        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # bind this ACL table to rif_id2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_router_interface_attribute(rif_id2, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src ip 192.168.100.1/255.255.255.0, SPORT 1000, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 0'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from rif_id2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_router_interface_attribute(rif_id2, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            self.client.sai_thrift_delete_acl_range(acl_range_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)

@group('acl')
@group('acl-ocp')
class L3L4PortTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Testing L4 src/dest port acl filter"
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.100.100 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        L4_DST_PORT = 1000
        L4_SRC_PORT = 500
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_sport = L4_SRC_PORT,
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_sport = L4_SRC_PORT,
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP and SPORT
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.100.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = L4_SRC_PORT
        dst_l4_port = L4_DST_PORT
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            None,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        print "ACL Table created 0x%lx"%(acl_table_id)

        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # bind this ACL table to rif_id2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_router_interface_attribute(rif_id2, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src ip 192.168.100.1/255.255.255.0, SPORT 1000, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 0'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from rif_id2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_router_interface_attribute(rif_id2, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)

@group('egress-acl')
class EgressL3L4PortTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.100.100 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        L4_DST_PORT = 1000
        L4_SRC_PORT = 500
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_sport = L4_SRC_PORT,
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_sport = L4_SRC_PORT,
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP and SPORT
        table_stage = SAI_ACL_STAGE_EGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.100.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = L4_SRC_PORT
        dst_l4_port = L4_DST_PORT
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            None,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        print "ACL Table created 0x%lx"%(acl_table_id)

        acl_counter_handle = sai_thrift_create_acl_counter(
            client=self.client, acl_table_id=acl_table_id)
        print acl_counter_handle

        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list,acl_counter_id = acl_counter_handle)

        # bind this ACL table to rif_id2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_router_interface_attribute(rif_id1, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src ip 192.168.100.1/255.255.255.0, SPORT 1000, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            # send the same packet
            num_packet = 10
            send_packet(self, 1, str(pkt),count=num_packet)
            time.sleep(10)
            counter_values1 = sai_thrift_get_acl_counter_attribute(
                client=self.client, acl_counter_id=acl_counter_handle)
            print counter_values1[0].u64
            if counter_values1[0].u64 == num_packet:
              print "ACL counter matches with num packets sent"
            else:
              print "ACL counter mismatch"
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 0'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from rif_id2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_router_interface_attribute(rif_id1, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)
            self.client.sai_thrift_remove_acl_counter(acl_counter_handle)

@group('egress-acl')
class EgressL3AclRangeTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.100.100 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        L4_DST_PORT = 1000
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=63)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP and SPORT
        table_stage = SAI_ACL_STAGE_EGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.100.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None

        u32range = sai_thrift_range_t(min=1000, max=1000)
        acl_range_id = sai_thrift_create_acl_range(
            self.client, SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE, u32range)
        range_list = [acl_range_id]
        print "ACL range created 0x%lx"%(acl_range_id)

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            None,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        print "ACL Table created 0x%lx"%(acl_table_id)

        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        # bind this ACL table to rif_id2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_router_interface_attribute(rif_id1, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src ip 192.168.100.1/255.255.255.0, SPORT 1000, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 0'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from rif_id2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_router_interface_attribute(rif_id1, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            self.client.sai_thrift_delete_acl_range(acl_range_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)

@group('mirror-acl')
class MultAclTableGroupBindTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 4 -> [ptf_intf 1, ptf_intf 2, ptf_intf 3] (192.168.0.1 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        port3 = port_list[2]
        port4 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2, port3, port4])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port4, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.0'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id4, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id4)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id4)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_ttl=63)

        print '#### NO ACL Applied ####'
        print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
        send_packet(self, 0, str(pkt))
        print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
        verify_packet(self, exp_pkt, 3)
        print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
        send_packet(self, 1, str(pkt))
        print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
        verify_packet(self, exp_pkt, 3)
        print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 3'
        send_packet(self, 2, str(pkt))
        print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
        verify_packet(self, exp_pkt, 3)

        sai_base_test.ThriftInterface.createSwitchApiRpcClient(self)
        self.swclient.switch_api_config_acl_optimization_set(0, 1)
        # setup ACL table group
        group_stage = SAI_ACL_STAGE_INGRESS
        group_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        group_type = SAI_ACL_TABLE_GROUP_TYPE_PARALLEL

        # setup ACL tables to block based on Source MAC
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2, port3, port4]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None
        range_list = None

        # create ACL table #1
        acl_table_id1 = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
        acl_entry_id1 = sai_thrift_create_acl_entry(self.client,
            acl_table_id1,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

    # Setup Mirror ACL
        monitor_port = port1
        mirror_type=SAI_MIRROR_SESSION_TYPE_LOCAL
        spanid=sai_thrift_create_mirror_session(self.client,mirror_type=mirror_type,port=monitor_port,vlan=0,vlan_priority=0,vlan_tpid=0,vlan_header_valid=False,src_mac=None,dst_mac=None,src_ip=None,dst_ip=None,encap_type=0,iphdr_version=0,ttl=0,tos=0,gre_type=0)
        print spanid
        attrb_value = sai_thrift_attribute_value_t(objlist=sai_thrift_object_list_t(count=1,object_id_list=[spanid]))

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (20.20.20.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP
        ip_src = "20.20.20.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = "172.16.10.1"
        ip_dst_mask = "255.255.255.0"
        ip_proto = 6
        src_l4_port = 4000
        dst_l4_port = 5000
        ingress_mirror_id = spanid

        mirror_acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            in_ports,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list)
    # setup ACL table group members
        group_member_priority1 = 1
        group_member_priority2 = 100

        acl_group_list = []
        acl_group_member_list = []
        for port in in_ports:
          # create ACL table group for each port
          acl_table_group_id = sai_thrift_create_acl_table_group(self.client,
              group_stage,
              group_bind_point_list,
              group_type)

          # create ACL table group members
          acl_table_group_member_id1 = sai_thrift_create_acl_table_group_member(self.client,
              acl_table_group_id,
              acl_table_id1,
              group_member_priority1)

          acl_table_group_member_id2 = sai_thrift_create_acl_table_group_member(self.client,
              acl_table_group_id,
              mirror_acl_table_id,
              group_member_priority1)

          acl_group_list.append(acl_table_group_id)
          acl_group_member_list.append(acl_table_group_member_id1)
          acl_group_member_list.append(acl_table_group_member_id2)


        for i in range(0,len(in_ports)):
          # bind this ACL table group to port1, port2, port3 object id
          print "Bind aclgroup 0x%lx to port 0x%lx"%(acl_group_list[i],in_ports[i])
          attr_value = sai_thrift_attribute_value_t(oid=acl_group_list[i])
          attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
          self.client.sai_thrift_set_port_attribute(in_ports[i], attr)

        mirror_acl_entry = sai_thrift_create_acl_entry(self.client,
            mirror_acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list)

        try:
            print '#### ACL \'DROP, src mac 00:22:22:22:22:22, in_ports[ptf_intf_1,2,3,4]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 1'
            time.sleep(5)
            send_packet(self, 0, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_no_other_packets(self, timeout=1)
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_no_other_packets(self, timeout=1)
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.0.1 | @ ptf_intf 3'
            send_packet(self, 2, str(pkt))
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.0.1 | @ ptf_intf 4'
            verify_no_other_packets(self, timeout=1)
            print "Verify Mirror ACL"
            time.sleep(5)
            pkt = simple_tcp_packet(eth_dst=router_mac,
                                    eth_src='00:22:22:22:22:22',
                                    ip_src='20.20.20.1',
                                    ip_dst='172.16.10.1',
                                    ip_id=101,
                                    ip_ttl=64,
                                    tcp_sport=4000,
                                    tcp_dport=5000)
            print "Sending packet port 2 -> port 3 (00:22:22:22:22:22 -> 00:00:00:00:00:33)"
            send_packet(self, 2, pkt)
            verify_packets(self, pkt, ports=[0])

        finally:
            # unbind this ACL table from port1, port2, port3 object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
            for i in range(0,len(in_ports)):
                self.client.sai_thrift_set_port_attribute(in_ports[i], attr)
            # cleanup ACL
            for mbr in acl_group_member_list:
                self.client.sai_thrift_remove_acl_table_group_member(mbr)
            for grp in acl_group_list:
                self.client.sai_thrift_remove_acl_table_group(grp)
            self.client.sai_thrift_remove_acl_entry(acl_entry_id1)
            self.client.sai_thrift_remove_acl_table(acl_table_id1)
            self.client.sai_thrift_remove_acl_entry(mirror_acl_entry)
            self.client.sai_thrift_remove_acl_table(mirror_acl_table_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id4)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id4, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2, port3, port4])
            self.client.sai_thrift_remove_virtual_router(vr_id)
            self.swclient.switch_api_config_acl_optimization_set(0, 0)
            sai_base_test.ThriftInterface.closeSwitchApiRpcClient(self)

@group('egress-acl')
class EgressL3AclDscp(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print '----------------------------------------------------------------------------------------------'
        print "Sending packet ptf_intf 2 -> ptf_intf 1 (192.168.100.100 ---> 172.16.10.1 [id = 105])"

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        L4_DST_PORT = 1000
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2])
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '172.16.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=64,ip_tos = 200)
        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src=router_mac,
            ip_dst='172.16.10.1',
            ip_src='192.168.100.100',
            tcp_dport = L4_DST_PORT,
            ip_id=105,
            ip_ttl=63,ip_tos = 200)
        try:
            print '#### NO ACL Applied ####'
            print '#### Sending  ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 2'
            send_packet(self, 1, str(pkt))
            print '#### Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            verify_packets(self, exp_pkt, [0])
        finally:
            print '----------------------------------------------------------------------------------------------'

        print "Sending packet ptf_intf 2 -[acl]-> ptf_intf 1 (192.168.0.1-[acl]-> 172.16.10.1 [id = 105])"
        # setup ACL to block based on Source IP and SPORT
        table_stage = SAI_ACL_STAGE_EGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_ROUTER_INTF]
        entry_priority = 1
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.100.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        src_l4_port = None
        dst_l4_port = None
        ingress_mirror_id = None
        egress_mirror_id = None
        dscp=50

        u32range = sai_thrift_range_t(min=1000, max=1200)
        acl_range_id = sai_thrift_create_acl_range(
            self.client, SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE, u32range)
        range_list = [acl_range_id]
        print "ACL range created 0x%lx"%(acl_range_id)

        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src,
            mac_dst,
            ip_src,
            ip_dst,
            ip_proto,
            None,
            out_ports,
            in_port,
            out_port,
            src_l4_port,
            dst_l4_port,
            range_list, dscp)
        print "ACL Table created 0x%lx"%(acl_table_id)

        acl_entry_id = sai_thrift_create_acl_entry(self.client,
            acl_table_id,
            entry_priority,
            action, addr_family,
            mac_src, mac_src_mask,
            mac_dst, mac_dst_mask,
            ip_src, ip_src_mask,
            ip_dst, ip_dst_mask,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            ingress_mirror_id,
            egress_mirror_id,
            range_list, dscp)

        # bind this ACL table to rif_id2s object id
        attr_value = sai_thrift_attribute_value_t(oid=acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_router_interface_attribute(rif_id1, attr)

        try:
            assert acl_table_id > 0, 'acl_entry_id is <= 0'
            assert acl_entry_id > 0, 'acl_entry_id is <= 0'

            print '#### ACL \'DROP, src ip 192.168.100.1/255.255.255.0, SPORT 1000, in_ports[ptf_intf_1,2]\' Applied ####'
            print '#### Sending      ', router_mac, '| 00:22:22:22:22:22 | 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 1'
            # send the same packet
            send_packet(self, 1, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            print '#### NOT Expecting 00:11:22:33:44:55 |', router_mac, '| 172.16.10.1 | 192.168.100.100 | SPORT 1000 | @ ptf_intf 0'
            verify_no_other_packets(self, timeout=1)
        finally:
            # unbind this ACL table from rif_id2s object id
            attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
            attr = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, value=attr_value)
            self.client.sai_thrift_set_router_interface_attribute(rif_id1, attr)
            # cleanup ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            self.client.sai_thrift_delete_acl_range(acl_range_id)
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            sai_thrift_create_default_bridge_ports(self.client, [port1, port2])
            self.client.sai_thrift_remove_virtual_router(vr_id)
