# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface CRM tests
"""
import socket
import sai_base_test
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from switchsai_thrift.sai_headers import  *
from switch_utils import *

port_list_tmp = []
class IPv4RouteEntryTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        self.test_params = testutils.test_params_get()
        attr_id_ipv4 = SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY
        attr_id_ipv6 = SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY
        avail1_ipv4 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv4)
        avail1_ipv6 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv6)
        self.assertTrue(avail1_ipv4.id==attr_id_ipv4, "IPV4 route entry available get failed")
        self.assertTrue(avail1_ipv4.value.u32>0, "Invalid IPV4 route entry available count")
        self.assertTrue(avail1_ipv6.id==attr_id_ipv6, "IPV6 route entry available get failed")
        self.assertTrue(avail1_ipv6.value.u32>0, "Invalid IPV6 route entry available count")

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        """
        The test will create following IPV4 route entries
        1) Default route for virtual router (LPM)
        2) Host entry for nexthop
        3) LPM entry for nexthop subnet
        4) LPM entry for 10.10.10.0 subnet

        and following IPV6 route entries ...
        1) Default route for virtual router (LPM)
        """
        impacted_ipv4_route_entries = [3,4]
        impacted_ipv6_route_entries = 1

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, ports)
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.0'
        ip_mask1 = '255.255.255.0'
        dmac1 = '00:11:22:33:44:55'
        nhop_ip1 = '20.20.20.1'
        nhop_ip1_subnet = '20.20.20.0'
        ip_mask2 = '255.255.255.0'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_route(self.client, vr_id, addr_family, nhop_ip1_subnet, ip_mask2, rif_id1)

        avail2_ipv4 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv4)
        avail2_ipv6 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv6)

        # cleanup
        sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_remove_route(self.client, vr_id, addr_family, nhop_ip1_subnet, ip_mask2, rif_id1)
        sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
        self.client.sai_thrift_remove_next_hop(nhop1)
        self.client.sai_thrift_remove_router_interface(rif_id1)
        self.client.sai_thrift_remove_router_interface(rif_id2)
        sai_thrift_create_default_bridge_ports(self.client, ports)
        self.client.sai_thrift_remove_virtual_router(vr_id)

        self.assertTrue(avail1_ipv4.value.u32-avail2_ipv4.value.u32 in impacted_ipv4_route_entries,
            "Invalid IPV4 route entry available count")
        self.assertTrue(avail1_ipv6.value.u32-avail2_ipv6.value.u32==impacted_ipv6_route_entries,
            "Invalid IPV6 route entry available count")

class IPv6RouteEntryTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        self.test_params = testutils.test_params_get()
        attr_id_ipv4 = SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY
        attr_id_ipv6 = SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY
        avail1_ipv4 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv4)
        avail1_ipv6 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv6)
        self.assertTrue(avail1_ipv4.id==attr_id_ipv4, "IPV4 route entry available get failed")
        self.assertTrue(avail1_ipv4.value.u32>0, "Invalid IPV4 route entry available count")
        self.assertTrue(avail1_ipv6.id==attr_id_ipv6, "IPV6 route entry available get failed")
        self.assertTrue(avail1_ipv6.value.u32>0, "Invalid IPV6 route entry available count")

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        """
        The test will create following IPV6 route entries
        1) Default route for virtual router (LPM)
        2) Host entry for nexthop
        3) LPM entry for test subnet

        and following IPV4 route entries ...
        1) Default route for virtual router (LPM)
        """
        impacted_ipv4_route_entries = 1
        impacted_ipv6_route_entries = 3

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, ports)
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV6
        ip_addr1_subnet = '2000:aaaa::'
        ip_addr1 = ip_addr1_subnet + '1'
        ip_addr1_mask = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1_subnet, ip_addr1_mask, rif_id1)

        avail2_ipv4 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv4)
        avail2_ipv6 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv6)

        # cleanup
        sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1_subnet, ip_addr1_mask, rif_id1)
        sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        self.client.sai_thrift_remove_next_hop(nhop1)

        self.client.sai_thrift_remove_router_interface(rif_id1)
        self.client.sai_thrift_remove_router_interface(rif_id2)
        sai_thrift_create_default_bridge_ports(self.client, ports)
        self.client.sai_thrift_remove_virtual_router(vr_id)

        self.assertTrue(avail1_ipv4.value.u32-avail2_ipv4.value.u32==impacted_ipv4_route_entries,
            "Invalid IPV4 route entry available count")
        self.assertTrue(avail1_ipv6.value.u32-avail2_ipv6.value.u32==impacted_ipv6_route_entries,
            "Invalid IPV6 route entry available count")

class AclTableTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]

        # baseline availabe ACL table and groups
        avail1 = {}
        switch_attrs = [SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE, SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP]
        count = 2 * (SAI_ACL_BIND_POINT_TYPE_SWITCH + 1);
        for attr in switch_attrs:
            avail1[attr] = self.client.sai_thrift_get_switch_attribute_by_id(attr)
            self.assertTrue(avail1[attr].value.aclresource.count == count, "Invalid resource count")
        # map (stage, bind-point) to available numbers for easy reference
        avail1_map = {(e.stage,e.bind_point):e.avail_num for e in avail1[attr].value.aclresource.aclresourcelist}
        #basic sanity
        for ((stage,bpt), avail) in avail1_map.items():
            self.assertTrue(avail > 0, "Invalid ACL table/group count for (%d,%d)" % (stage, bpt))

        # setup ACL to block based on Source IP
        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY
        action = SAI_PACKET_ACTION_DROP
        mac_src = None; mac_src_mask = None;
        mac_dst = None; mac_dst_mask = None
        ip_src = "192.168.0.1"; ip_src_mask = "255.255.255.0"
        ip_dst = None; ip_dst_mask = None;
        ip_proto = None; src_l4_port = None; dst_l4_port = None
        in_port = None; in_ports = [port1, port2]
        out_port = None; out_ports = None
        ingress_mirror_id = None; egress_mirror_id = None
        range_list = None

        # create a ACL table and group
        acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src, mac_dst,
            ip_src, ip_dst,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
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

        # available ACL table and group numbers should go down by one for each (stage, bind-point) combination
        avail2 = {}
        for attr in switch_attrs:
            avail2[attr] = self.client.sai_thrift_get_switch_attribute_by_id(attr)
        avail2_map = {(e.stage,e.bind_point):e.avail_num for e in avail2[attr].value.aclresource.aclresourcelist}
        for bpt in table_bind_point_list:
            key = (table_stage,bpt)
            self.assertTrue(avail1_map[key] == avail2_map[key] + 1, "Invalid ACL table available count")

        # unbind this ACL table from port2s object id
        attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        # cleanup ACL
        self.client.sai_thrift_remove_acl_entry(acl_entry_id)
        self.client.sai_thrift_remove_acl_table(acl_table_id)

class NexthopEntryTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        self.test_params = testutils.test_params_get()
        attr_id_ipv4 = SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY
        attr_id_ipv6 = SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY
        avail1_ipv4 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv4)
        avail1_ipv6 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv6)
        self.assertTrue(avail1_ipv4.id==attr_id_ipv4, "IPV4 route entry available get failed")
        self.assertTrue(avail1_ipv4.value.u32>0, "Invalid IPV4 route entry available count")
        self.assertTrue(avail1_ipv6.id==attr_id_ipv6, "IPV6 route entry available get failed")
        self.assertTrue(avail1_ipv6.value.u32>0, "Invalid IPV6 route entry available count")
        self.assertTrue(avail1_ipv6.value.u32==avail1_ipv4.value.u32, "IPV6 and IPv4 nexthop entry mismatch")

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        """
        The test will create following nexthop entries
        a) Host entry for IPv4 nexthop
        b) Host entry for IPv6 nexthop
        Impacted entries will be two because table is shared between IPv4 and IPv6 nhops
        """
        impacted_ipv4_nexthop_entries = 2
        impacted_ipv6_nexthop_entries = 2

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, ports)
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        nhop1 = sai_thrift_create_nhop(self.client, SAI_IP_ADDR_FAMILY_IPV4, '20.20.20.1', rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, SAI_IP_ADDR_FAMILY_IPV6, '2000:aaaa::1', rif_id2)

        avail2_ipv4 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv4)
        avail2_ipv6 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id_ipv6)

        # cleanup
        self.client.sai_thrift_remove_next_hop(nhop1)
        self.client.sai_thrift_remove_next_hop(nhop2)
        self.client.sai_thrift_remove_router_interface(rif_id1)
        self.client.sai_thrift_remove_router_interface(rif_id2)
        sai_thrift_create_default_bridge_ports(self.client, ports)
        self.client.sai_thrift_remove_virtual_router(vr_id)

        self.assertTrue(avail1_ipv4.value.u32-avail2_ipv4.value.u32==impacted_ipv4_nexthop_entries,
            "Invalid IPV4 nexthop entry available count")
        self.assertTrue(avail1_ipv6.value.u32-avail2_ipv6.value.u32==impacted_ipv6_nexthop_entries,
            "Invalid IPV6 nexthop entry available count")
        self.assertTrue(avail2_ipv6.value.u32==avail2_ipv4.value.u32, "IPV6 and IPv4 nexthop entry mismatch")

class FdbEntryTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        self.test_params = testutils.test_params_get()
        attr_id = SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY
        avail1 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id)
        self.assertTrue(avail1.id==attr_id, "fdb available get failed")
        self.assertTrue(avail1.value.u32>0, "fdb available count invalid")

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD
        vlan_id = 10

        """
        The test will create a couple of FDB entries and verify available count goes down
        """
        impacted_entries = 2

        vlan_oid = sai_thrift_create_vlan(self.client, vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_oid, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_oid, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        attr_value = sai_thrift_attribute_value_t(u16=vlan_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_PORT_VLAN_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port1, attr)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        sai_thrift_create_fdb(self.client, vlan_oid, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_oid, mac2, port2, mac_action)

        # refresh available values
        avail2 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id)

        # cleanup
        sai_thrift_delete_fdb(self.client, vlan_oid, mac1, port1)
        sai_thrift_delete_fdb(self.client, vlan_oid, mac2, port2)

        attr_value = sai_thrift_attribute_value_t(u16=1)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_PORT_VLAN_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port1, attr)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        self.client.sai_thrift_remove_vlan_member(vlan_member1)
        self.client.sai_thrift_remove_vlan_member(vlan_member2)
        self.client.sai_thrift_remove_vlan(vlan_oid)

        self.assertTrue(avail1.value.u32-avail2.value.u32==impacted_entries,
            "Invalid IPV4 nexthop entry available count")

class IPv4NeighborEntryTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        self.test_params = testutils.test_params_get()
        attr_id = SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY
        avail1 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id)
        self.assertTrue(avail1.id==attr_id, "IPV4 neighbor entry available get failed")
        self.assertTrue(avail1.value.u32>0, "Invalid IPV4 neighbor entry available count")

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        nhop_ip1 = '20.20.20.1'
        dmac1 = '00:11:22:33:44:55'

        """
        The test will create following neighbor entries
        1) IPV4 neighbor entry
        """
        impacted_neighbor_entries = 1

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, ports)
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)

        avail2 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id)

        # cleanup
        sai_thrift_remove_neighbor(self.client, SAI_IP_ADDR_FAMILY_IPV4, rif_id1, nhop_ip1, dmac1)
        self.client.sai_thrift_remove_router_interface(rif_id1)
        sai_thrift_create_default_bridge_ports(self.client, ports)
        self.client.sai_thrift_remove_virtual_router(vr_id)

        self.assertTrue(avail1.value.u32-avail2.value.u32==impacted_neighbor_entries,
            "Invalid IPV4 neighbor entry available count")

class IPv6NeighborEntryTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        self.test_params = testutils.test_params_get()
        attr_id = SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY
        avail1 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id)
        print "Baseline IPv6 neighbor entries %d" % avail1.value.u32
        self.assertTrue(avail1.id==attr_id, "IPV6 neighbor entry available get failed")
        self.assertTrue(avail1.value.u32>0, "Invalid IPV4 neighbor entry available count")

        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        addr_family = SAI_IP_ADDR_FAMILY_IPV6
        nhop_ip1 = '2000:aaaa::1'
        dmac1 = '00:11:22:33:44:55'

        """
        The test will create following neighbor entries
        1) IPV6 neighbor entry
        Impacted entries could be 1 or 2 because neighbor entries are determined
        by smaller or nhop or host fib table. Two fib host entries will be created
        (neighbor and router default route) and one nhop entry will be created.
        Depending on profile, nhop or host table could be smaller so either 1 or 2
        entries will be consumed.
        """
        impacted_neighbor_entries = [1,2]

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, ports)
        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)

        avail2 = self.client.sai_thrift_get_switch_attribute_by_id(attr_id)
        print "After creating one IPv6 neighbor, entries %d" % avail2.value.u32

        # cleanup
        sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
        self.client.sai_thrift_remove_router_interface(rif_id1)
        sai_thrift_create_default_bridge_ports(self.client, ports)
        self.client.sai_thrift_remove_virtual_router(vr_id)

        self.assertTrue(avail1.value.u32-avail2.value.u32 in impacted_neighbor_entries,
            "Invalid IPV6 neighbor entry available count")


class NexthopGroupTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        port3 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.2'
        ip_addr1_subnet = '10.10.10.0'
        ip_mask1 = '255.255.255.0'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'

        # (attr_id, attr name, impacted entries)
        # impacted entries is expected drop in available counts after creating nhop group and members
        avail1 = {}
        attr_info = [
            (SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY,        "nexthop group entry",        1),
            (SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY, "nexthop group member entry", 2)
        ]
        # baseline - available nexthop group
        for (attr_id, attr_name, impacted) in attr_info:
            avail = self.client.sai_thrift_get_switch_attribute_by_id(attr_id)
            self.assertTrue(avail.id==attr_id, "%s available get failed" % attr_name)
            self.assertTrue(avail.value.u32>0, "Invalid %s available count" % attr_name)
            avail1[attr_id] = avail

        vr1 = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        sai_thrift_remove_default_bridge_ports(self.client, [port1, port2, port3])

        rif1 = sai_thrift_create_router_interface(self.client, vr1, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif2 = sai_thrift_create_router_interface(self.client, vr1, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif3 = sai_thrift_create_router_interface(self.client, vr1, 1, port3, 0, v4_enabled, v6_enabled, mac)

        sai_thrift_create_neighbor(self.client, addr_family, rif1, ip_addr1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif2, ip_addr1, dmac2)

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif2)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client)
        nhop_gmember1 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop1)
        nhop_gmember2 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop2)

        sai_thrift_create_route(self.client, vr1, addr_family, ip_addr1_subnet, ip_mask1, nhop_group1)

        # gather new data
        avail2 = {ai[0]:self.client.sai_thrift_get_switch_attribute_by_id(ai[0]) for ai in attr_info}

        # cleanup
        sai_thrift_remove_route(self.client, vr1, addr_family, ip_addr1_subnet, ip_mask1, nhop_group1)
        self.client.sai_thrift_remove_next_hop_group_member(nhop_gmember1)
        self.client.sai_thrift_remove_next_hop_group_member(nhop_gmember2)
        self.client.sai_thrift_remove_next_hop_group(nhop_group1)
        sai_thrift_remove_neighbor(self.client, addr_family, rif1, ip_addr1, dmac1)
        sai_thrift_remove_neighbor(self.client, addr_family, rif2, ip_addr1, dmac2)
        self.client.sai_thrift_remove_next_hop(nhop1)
        self.client.sai_thrift_remove_next_hop(nhop2)
        self.client.sai_thrift_remove_router_interface(rif1)
        self.client.sai_thrift_remove_router_interface(rif2)
        self.client.sai_thrift_remove_router_interface(rif3)
        sai_thrift_create_default_bridge_ports(self.client, [port1, port2, port3])
        self.client.sai_thrift_remove_virtual_router(vr1)

        # validate
        for (attr_id, attr_name, impacted) in attr_info:
            self.assertTrue(avail1[attr_id].value.u32-avail2[attr_id].value.u32==impacted,
                "Invalid %s available count" % attr_name)

class AclEntryTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[0]
        port2 = port_list[1]
        ports = [port1, port2]

        # setup ACL to block based on Source IP
        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        table_stage = SAI_ACL_STAGE_INGRESS
        table_bind_point_list = [SAI_ACL_BIND_POINT_TYPE_PORT]
        entry_priority = SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY
        action = SAI_PACKET_ACTION_DROP
        mac_src = None; mac_src_mask = None;
        mac_dst = None; mac_dst_mask = None
        ip_src = "192.168.0.1"; ip_src_mask = "255.255.255.0"
        ip_dst = None; ip_dst_mask = None;
        ip_proto = None; src_l4_port = None; dst_l4_port = None
        in_port = None; in_ports = [port1, port2]
        out_port = None; out_ports = None
        ingress_mirror_id = None; egress_mirror_id = None
        range_list = None

        ipv4_acl_table_id = sai_thrift_create_acl_table(self.client,
            table_stage,
            table_bind_point_list,
            addr_family,
            mac_src, mac_dst,
            ip_src, ip_dst,
            ip_proto,
            in_ports, out_ports,
            in_port, out_port,
            src_l4_port, dst_l4_port,
            range_list)

        mac_src = '00:22:22:22:22:22'; mac_src_mask = 'ff:ff:ff:ff:ff:ff'
        ip_src = None; ip_src_mask = None
        mac_acl_table_id = sai_thrift_create_acl_table(self.client,
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

        # baseline - create IP and MAC acl tables
        acl_attr = SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY
        ipv4_avail1 = self.client.sai_thrift_get_acl_table_attribute_by_id(acl_attr, ipv4_acl_table_id)
        mac_avail1 = self.client.sai_thrift_get_acl_table_attribute_by_id(acl_attr, mac_acl_table_id)
        print 'Baseline available ipv4: %d, mac=%d' % (ipv4_avail1.value.u32, mac_avail1.value.u32)

        ip_src = "192.168.0.1"; ip_src_mask = "255.255.255.0"
        mac_src = None; mac_src_mask = None;
        ipv4_acl_entry_id = sai_thrift_create_acl_entry(self.client,
            ipv4_acl_table_id,
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
        attr_value = sai_thrift_attribute_value_t(oid=ipv4_acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        # Add one IPV4 ACL entry
        # MAC ACL table entry should not be impacted
        ipv4_avail2 = self.client.sai_thrift_get_acl_table_attribute_by_id(acl_attr, ipv4_acl_table_id)
        mac_avail2  = self.client.sai_thrift_get_acl_table_attribute_by_id(acl_attr, mac_acl_table_id)
        print 'Add ipv4 ACE, available ipv4: %d, mac=%d' % (ipv4_avail2.value.u32, mac_avail2.value.u32)
        self.assertTrue(mac_avail1.value.u32 == mac_avail2.value.u32, "Invalid MAC ACE entry count")
        self.assertTrue(ipv4_avail1.value.u32-ipv4_avail2.value.u32==1, "Invalid IPv4 ACE entry count")

        mac_src = '00:22:22:22:22:22'; mac_src_mask = 'ff:ff:ff:ff:ff:ff'
        ip_src = None; ip_src_mask = None
        mac_acl_entry_id = sai_thrift_create_acl_entry(self.client,
            mac_acl_table_id,
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

        # bind this ACL table to port1s object id
        attr_value = sai_thrift_attribute_value_t(oid=mac_acl_table_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port1, attr)

        # Add one MAC ACL entry
        # IPV4 ACL table entry should not be impacted
        ipv4_avail3 = self.client.sai_thrift_get_acl_table_attribute_by_id(acl_attr, ipv4_acl_table_id)
        mac_avail3  = self.client.sai_thrift_get_acl_table_attribute_by_id(acl_attr, mac_acl_table_id)
        print 'Add mac ACE, available ipv4: %d, mac=%d' % (ipv4_avail3.value.u32, mac_avail3.value.u32)
        self.assertTrue(ipv4_avail2.value.u32 == ipv4_avail3.value.u32, "Invalid IPV4 ACE entry count")
        self.assertTrue(mac_avail2.value.u32-mac_avail3.value.u32==1, "Invalid MAC ACE entry count")

        # unbind ACLs from ports
        attr_value = sai_thrift_attribute_value_t(oid=SAI_NULL_OBJECT_ID)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_INGRESS_ACL, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port1, attr)
        self.client.sai_thrift_set_port_attribute(port2, attr)

        # cleanup ACL
        self.client.sai_thrift_remove_acl_entry(mac_acl_entry_id)
        self.client.sai_thrift_remove_acl_entry(ipv4_acl_entry_id)
        self.client.sai_thrift_remove_acl_table(mac_acl_table_id)
        self.client.sai_thrift_remove_acl_table(ipv4_acl_table_id)
