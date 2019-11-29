"""
Thrift API interface ACL tests
"""

import switchapi_thrift

import time
import sys
import logging

import unittest
import random
import pdb

import ptf.dataplane as dataplane

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *

import os

from switchapi_thrift.ttypes import *
from switchapi_thrift.switch_api_headers import *

from erspan3 import *

this_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(this_dir, '../../base'))
sys.path.append(os.path.join(this_dir, '../../base/api-tests'))
from common.utils import *
from common.api_utils import *
from api_utils import *
from common.api_adapter import ApiAdapter
import api_base_tests

device=0
cpu_port=64
swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)

if swports == []:
    swports = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
invalid_hdl = -1


###############################################################################
@group('qos')
class L3IPv4QosDscpRewriteTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[
            2], "  (192.168.0.1 -> 172.16.0.1 [id = 101])"
        vrf = self.client.switch_api_vrf_create(0, 2)

        rmac = self.client.switch_api_router_mac_group_create(
            device, SWITCH_RMAC_TYPE_ALL)
        self.client.switch_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])

        rif_info1 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_INTF,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=True,
            v6_unicast_enabled=True)
        rif1 = self.client.switch_api_rif_create(0, rif_info1)
        i_info1 = switcht_interface_info_t(
            handle=port1, type=SWITCH_INTERFACE_TYPE_PORT, rif_handle=rif1)
        if1 = self.client.switch_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switch_api_l3_interface_address_add(0, rif1, vrf, i_ip1)

        rif_info2 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_INTF,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=True,
            v6_unicast_enabled=True)
        rif2 = self.client.switch_api_rif_create(0, rif_info2)
        i_info2 = switcht_interface_info_t(
            handle=port2, type=SWITCH_INTERFACE_TYPE_PORT, rif_handle=rif2)
        if2 = self.client.switch_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='172.16.0.2', prefix_length=16)
        self.client.switch_api_l3_interface_address_add(0, rif2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='172.20.10.1', prefix_length=32)
	nhop, neighbor = switch_api_l3_nhop_neighbor_create(self, device, rif2, i_ip3, '00:11:22:33:44:55')
        self.client.switch_api_l3_route_add(0, vrf, i_ip3, nhop)

        qos_map_configured = False

        try:
            # send test packet before qos maps are configured
            pkt = simple_tcp_packet(
                eth_dst='00:77:66:55:44:33',
                eth_src='00:22:22:22:22:22',
                ip_dst='172.20.10.1',
                ip_src='192.168.0.1',
                ip_id=105,
                ip_tos=24,
                ip_ttl=64)
            send_packet(self, swports[1], str(pkt))

            exp_pkt = simple_tcp_packet(
                eth_dst='00:11:22:33:44:55',
                eth_src='00:77:66:55:44:33',
                ip_dst='172.20.10.1',
                ip_src='192.168.0.1',
                ip_id=105,
                ip_tos=24,
                ip_ttl=63)
            verify_packets(self, exp_pkt, [swports[2]])
            print "pass packet before qos maps are configured"

            qos_map1 = switcht_qos_map_t(dscp=1, tc=20)
            qos_map2 = switcht_qos_map_t(dscp=2, tc=24)
            qos_map3 = switcht_qos_map_t(dscp=3, tc=28)
            qos_map4 = switcht_qos_map_t(dscp=4, tc=32)
            ingress_qos_map_list = [qos_map1, qos_map2, qos_map3, qos_map4]
            ingress_qos_handle = self.client.switch_api_qos_map_ingress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC,
                qos_map=ingress_qos_map_list)

            qos_map5 = switcht_qos_map_t(tc=20, icos=1)
            qos_map6 = switcht_qos_map_t(tc=24, icos=0)
            qos_map7 = switcht_qos_map_t(tc=28, icos=1)
            qos_map8 = switcht_qos_map_t(tc=32, icos=0)
            tc_qos_map_list = [qos_map5, qos_map6, qos_map7, qos_map8]
            tc_qos_handle = self.client.switch_api_qos_map_ingress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS,
                qos_map=tc_qos_map_list)

            qos_map51 = switcht_qos_map_t(tc=20, qid=1)
            qos_map61 = switcht_qos_map_t(tc=24, qid=2)
            qos_map71 = switcht_qos_map_t(tc=28, qid=3)
            qos_map81 = switcht_qos_map_t(tc=32, qid=4)
            tc_queue_map_list = [qos_map51, qos_map61, qos_map71, qos_map81]
            tc_queue_handle = self.client.switch_api_qos_map_ingress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE,
                qos_map=tc_queue_map_list)

            qos_map9 = switcht_qos_map_t(tc=20, dscp=9)
            qos_map10 = switcht_qos_map_t(tc=24, dscp=10)
            qos_map11 = switcht_qos_map_t(tc=28, dscp=11)
            qos_map12 = switcht_qos_map_t(tc=32, dscp=12)
            egress_qos_map_list = [qos_map9, qos_map10, qos_map11, qos_map12]
            egress_qos_handle = self.client.switch_api_qos_map_egress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_EGRESS_TC_TO_DSCP,
                qos_map=egress_qos_map_list)

            self.client.switch_api_port_qos_group_ingress_set(
                device=0, port_handle=port1, qos_handle=ingress_qos_handle)
            self.client.switch_api_port_qos_group_tc_set(
                device=0, port_handle=port1, qos_handle=tc_qos_handle)
            self.client.switch_api_port_qos_group_egress_set(
                device=0, port_handle=port1, qos_handle=egress_qos_handle)
            self.client.switch_api_port_trust_dscp_set(
                device=0, port_handle=port1, trust_dscp=True)

            self.client.switch_api_port_qos_group_ingress_set(
                device=0, port_handle=port2, qos_handle=ingress_qos_handle)
            self.client.switch_api_port_qos_group_tc_set(
                device=0, port_handle=port2, qos_handle=tc_qos_handle)
            self.client.switch_api_port_qos_group_egress_set(
                device=0, port_handle=port2, qos_handle=egress_qos_handle)
            self.client.switch_api_port_trust_dscp_set(
                device=0, port_handle=port2, trust_dscp=True)

            qos_map_configured = True

            # send the test packet(s)
            pkt = simple_tcp_packet(
                eth_dst='00:77:66:55:44:33',
                eth_src='00:22:22:22:22:22',
                ip_dst='172.20.10.1',
                ip_src='192.168.0.1',
                ip_id=105,
                ip_tos=4,
                ip_ttl=64)
            send_packet(self, swports[1], str(pkt))

            exp_pkt = simple_tcp_packet(
                eth_dst='00:11:22:33:44:55',
                eth_src='00:77:66:55:44:33',
                ip_dst='172.20.10.1',
                ip_src='192.168.0.1',
                ip_id=105,
                ip_tos=36,
                ip_ttl=63)
            verify_packets(self, exp_pkt, [swports[2]])
            print "pass packet w/ mapped dscp value 1 -> 9"

            # send test packet with different dscp value
            pkt[IP].tos = 12
            send_packet(self, swports[1], str(pkt))

            exp_pkt[IP].tos = 44
            verify_packets(self, exp_pkt, [swports[2]])
            print "pass packet w/ mapped dscp value 3 -> 11"

            # send test packet with unmapped dscp value
            pkt[IP].tos = 24
            send_packet(self, swports[1], str(pkt))

            exp_pkt[IP].tos = 24
            verify_packets(self, exp_pkt, [swports[2]])
            print "pass packet w/ unmapped dscp value 6"

        finally:
            #cleanup

            if qos_map_configured:
                self.client.switch_api_port_qos_group_ingress_set(
                    device=0, port_handle=port1, qos_handle=0)
                self.client.switch_api_port_qos_group_tc_set(
                    device=0, port_handle=port1, qos_handle=0)
                self.client.switch_api_port_qos_group_egress_set(
                    device=0, port_handle=port1, qos_handle=0)
                self.client.switch_api_port_trust_dscp_set(
                    device=0, port_handle=port1, trust_dscp=False)

                self.client.switch_api_port_qos_group_ingress_set(
                    device=0, port_handle=port2, qos_handle=0)
                self.client.switch_api_port_qos_group_tc_set(
                    device=0, port_handle=port2, qos_handle=0)
                self.client.switch_api_port_qos_group_egress_set(
                    device=0, port_handle=port2, qos_handle=0)
                self.client.switch_api_port_trust_dscp_set(
                    device=0, port_handle=port2, trust_dscp=False)

                self.client.switch_api_qos_map_ingress_delete(
                    device=0, qos_map_handle=ingress_qos_handle)
                self.client.switch_api_qos_map_ingress_delete(
                    device=0, qos_map_handle=tc_queue_handle)
                self.client.switch_api_qos_map_ingress_delete(
                    device=0, qos_map_handle=tc_qos_handle)
                self.client.switch_api_qos_map_egress_delete(
                    device=0, qos_map_handle=egress_qos_handle)

            self.client.switch_api_l3_route_delete(0, vrf, i_ip3, nhop)
            self.client.switch_api_neighbor_delete(0, neighbor)
            self.client.switch_api_nhop_delete(0, nhop)

            self.client.switch_api_l3_interface_address_delete(0, rif1, vrf, i_ip1)
            self.client.switch_api_l3_interface_address_delete(0, rif2, vrf, i_ip2)

            self.client.switch_api_rif_delete(0, rif1)
            self.client.switch_api_rif_delete(0, rif2)

            self.client.switch_api_interface_delete(0, if1)
            self.client.switch_api_interface_delete(0, if2)

            self.client.switch_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
            self.client.switch_api_router_mac_group_delete(0, rmac)
            self.client.switch_api_vrf_delete(0, vrf)


@group('qos')
class L3IPv4QosPCPRewriteTest(ApiAdapter):
    def setUp(self):
        super(self.__class__, self).setUp()
        self.vlan_id = 10
        self.mac_type = SWITCH_MAC_ENTRY_STATIC
        self.fp_ports = [swports[0], swports[1]]
        self.macs = ['00:22:22:22:22:22', '00:11:11:11:11:11']
        self.intf_mode = ['trunk', 'trunk']
        self.vlan_h = [0] * 100
        self.port_h = [0] * len(self.fp_ports)
        self.intf_h = [0] * len(self.fp_ports)

        self.vlan_h[self.vlan_id] = self.add_vlan(device, self.vlan_id)

        for index in range(0, len(self.fp_ports)):
          self.port_h[index] = self.select_port(device, swports[index])
          self.intf_h[index] = self.cfg_l2intf_on_port(device, self.port_h[index], mode=self.intf_mode[index])

        for index in range(0, len(self.intf_h)):
          self.add_vlan_member(device, self.vlan_h[self.vlan_id], self.intf_h[index])

        for index in range(0, len(self.macs)):
          self.add_mac_table_entry(device,
                                   self.vlan_h[self.vlan_id],
                                   self.macs[index],
                                   self.mac_type,
                                   self.intf_h[index])

        qos_map_configured = False

    def runTest(self):

        pkt = simple_udp_packet(
            eth_dst='00:11:11:11:11:11',
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.0.1',
            dl_vlan_enable=True,
            vlan_vid=10,
            vlan_pcp=2,
            pktlen=104,
            ip_ttl=64)

        send_packet(self, swports[0], str(pkt))
        verify_packets(self, pkt, [swports[1]])
        print "pass packet before qos maps are configured"

        try:
            qos_map1 = switcht_qos_map_t(pcp=1, tc=20)
            qos_map2 = switcht_qos_map_t(pcp=2, tc=24)
            qos_map3 = switcht_qos_map_t(pcp=3, tc=28)
            qos_map4 = switcht_qos_map_t(pcp=4, tc=32)
            ingress_qos_map_list = [qos_map1, qos_map2, qos_map3, qos_map4]
            ingress_qos_handle = self.client.switch_api_qos_map_ingress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_INGRESS_PCP_TO_TC,
                qos_map=ingress_qos_map_list)

            qos_map5 = switcht_qos_map_t(tc=20, icos=1)
            qos_map6 = switcht_qos_map_t(tc=24, icos=0)
            qos_map7 = switcht_qos_map_t(tc=28, icos=1)
            qos_map8 = switcht_qos_map_t(tc=32, icos=0)
            tc_qos_map_list = [qos_map5, qos_map6, qos_map7, qos_map8]
            tc_qos_handle = self.client.switch_api_qos_map_ingress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS,
                qos_map=tc_qos_map_list)

            qos_map51 = switcht_qos_map_t(tc=20, qid=1)
            qos_map61 = switcht_qos_map_t(tc=24, qid=2)
            qos_map71 = switcht_qos_map_t(tc=28, qid=3)
            qos_map81 = switcht_qos_map_t(tc=32, qid=4)
            tc_queue_map_list = [qos_map51, qos_map61, qos_map71, qos_map81]
            tc_queue_handle = self.client.switch_api_qos_map_ingress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE,
                qos_map=tc_queue_map_list)

            qos_map9 = switcht_qos_map_t(tc=20, pcp=4)
            qos_map10 = switcht_qos_map_t(tc=24, pcp=5)
            qos_map11 = switcht_qos_map_t(tc=28, pcp=6)
            qos_map12 = switcht_qos_map_t(tc=32, pcp=7)
            egress_qos_map_list = [qos_map9, qos_map10, qos_map11, qos_map12]
            egress_qos_handle = self.client.switch_api_qos_map_egress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_EGRESS_TC_TO_PCP,
                qos_map=egress_qos_map_list)

            self.client.switch_api_port_qos_group_ingress_set(
                device=0, port_handle=self.port_h[0], qos_handle=ingress_qos_handle)
            self.client.switch_api_port_qos_group_tc_set(
                device=0, port_handle=self.port_h[0], qos_handle=tc_qos_handle)
            self.client.switch_api_port_qos_group_egress_set(
                device=0, port_handle=self.port_h[0], qos_handle=egress_qos_handle)
            self.client.switch_api_port_trust_pcp_set(
                device=0, port_handle=self.port_h[0], trust_pcp=True)

            self.client.switch_api_port_qos_group_ingress_set(
                device=0, port_handle=self.port_h[1], qos_handle=ingress_qos_handle)
            self.client.switch_api_port_qos_group_tc_set(
                device=0, port_handle=self.port_h[1], qos_handle=tc_qos_handle)
            self.client.switch_api_port_qos_group_egress_set(
                device=0, port_handle=self.port_h[1], qos_handle=egress_qos_handle)
            self.client.switch_api_port_trust_pcp_set(
                device=0, port_handle=self.port_h[1], trust_pcp=True)

            qos_map_configured = True

            exp_pkt = simple_udp_packet(
                eth_dst='00:11:11:11:11:11',
                eth_src='00:22:22:22:22:22',
                ip_dst='172.16.0.1',
                dl_vlan_enable=True,
                vlan_vid=10,
                vlan_pcp=5,
                pktlen=104,
                ip_ttl=64)
        finally:
            send_packet(self, swports[0], str(pkt))
            verify_packets(self, exp_pkt, [swports[1]])
            print "pass packet w/ mapped pcp value 1 -> 4"


    def tearDown(self):
      self.cleanup()
      api_base_tests.ThriftInterfaceDataPlane.tearDown(self)

###############################################################################
@group('qos')
class L3IPv4QosTosRewriteTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[
            2], "  (192.168.0.1 -> 172.16.0.1 [id = 101])"
        vrf = self.client.switch_api_vrf_create(0, 2)

        rmac = self.client.switch_api_router_mac_group_create(
            device, SWITCH_RMAC_TYPE_ALL)
        self.client.switch_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])

        rif_info1 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_INTF,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=True,
            v6_unicast_enabled=True)
        rif1 = self.client.switch_api_rif_create(0, rif_info1)
        i_info1 = switcht_interface_info_t(
            handle=port1, type=SWITCH_INTERFACE_TYPE_PORT, rif_handle=rif1)
        if1 = self.client.switch_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switch_api_l3_interface_address_add(0, rif1, vrf, i_ip1)

        rif_info2 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_INTF,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=True,
            v6_unicast_enabled=True)
        rif2 = self.client.switch_api_rif_create(0, rif_info2)
        i_info2 = switcht_interface_info_t(
            handle=port2, type=SWITCH_INTERFACE_TYPE_PORT, rif_handle=rif2)
        if2 = self.client.switch_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='172.16.0.2', prefix_length=16)
        self.client.switch_api_l3_interface_address_add(0, rif2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='172.20.10.1', prefix_length=32)
	nhop, neighbor = switch_api_l3_nhop_neighbor_create(self, device, rif2, i_ip3, '00:11:22:33:44:55')
        self.client.switch_api_l3_route_add(0, vrf, i_ip3, nhop)

        qos_map1 = switcht_qos_map_t(tos=1, tc=20)
        qos_map2 = switcht_qos_map_t(tos=2, tc=24)
        qos_map3 = switcht_qos_map_t(tos=3, tc=28)
        qos_map4 = switcht_qos_map_t(tos=4, tc=32)
        ingress_qos_map_list = [qos_map1, qos_map2, qos_map3, qos_map4]
        ingress_qos_handle = self.client.switch_api_qos_map_ingress_create(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_INGRESS_TOS_TO_TC,
            qos_map=ingress_qos_map_list)

        qos_map5 = switcht_qos_map_t(tc=20, icos=1)
        qos_map6 = switcht_qos_map_t(tc=24, icos=0)
        qos_map7 = switcht_qos_map_t(tc=28, icos=1)
        qos_map8 = switcht_qos_map_t(tc=32, icos=0)
        tc_qos_map_list = [qos_map5, qos_map6, qos_map7, qos_map8]
        tc_qos_handle = self.client.switch_api_qos_map_ingress_create(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS,
            qos_map=tc_qos_map_list)

        qos_map9 = switcht_qos_map_t(tc=20, tos=9)
        qos_map10 = switcht_qos_map_t(tc=24, tos=10)
        qos_map11 = switcht_qos_map_t(tc=28, tos=11)
        qos_map12 = switcht_qos_map_t(tc=32, tos=12)
        egress_qos_map_list = [qos_map9, qos_map10, qos_map11, qos_map12]
        egress_qos_handle = self.client.switch_api_qos_map_egress_create(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_EGRESS_TC_TO_TOS,
            qos_map=egress_qos_map_list)

        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port1, qos_handle=ingress_qos_handle)
        self.client.switch_api_port_qos_group_tc_set(
            device=0, port_handle=port1, qos_handle=tc_qos_handle)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port1, qos_handle=egress_qos_handle)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port1, trust_dscp=True)

        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port2, qos_handle=ingress_qos_handle)
        self.client.switch_api_port_qos_group_tc_set(
            device=0, port_handle=port2, qos_handle=tc_qos_handle)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port2, qos_handle=egress_qos_handle)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port2, trust_dscp=True)

        # send the test packet(s)
        # send the test packet(s)
        pkt = simple_tcp_packet(
            eth_dst='00:77:66:55:44:33',
            eth_src='00:22:22:22:22:22',
            ip_dst='172.20.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_tos=4,
            ip_ttl=64)
        send_packet(self, swports[1], str(pkt))

        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src='00:77:66:55:44:33',
            ip_dst='172.20.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_tos=12,
            ip_ttl=63)
        verify_packets(self, exp_pkt, [swports[2]])

        #cleanup
        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port1, qos_handle=0)
        self.client.switch_api_port_qos_group_tc_set(
            device=0, port_handle=port1, qos_handle=0)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port1, qos_handle=0)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port1, trust_dscp=False)

        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port2, qos_handle=0)
        self.client.switch_api_port_qos_group_tc_set(
            device=0, port_handle=port2, qos_handle=0)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port2, qos_handle=0)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port2, trust_dscp=False)

        self.client.switch_api_qos_map_ingress_delete(
            device=0, qos_map_handle=ingress_qos_handle)
        self.client.switch_api_qos_map_ingress_delete(
            device=0, qos_map_handle=tc_qos_handle)
        self.client.switch_api_qos_map_egress_delete(
            device=0, qos_map_handle=egress_qos_handle)

        self.client.switch_api_l3_route_delete(0, vrf, i_ip3, nhop)
        self.client.switch_api_neighbor_delete(0, neighbor)
        self.client.switch_api_nhop_delete(0, nhop)

        self.client.switch_api_l3_interface_address_delete(0, rif1, vrf, i_ip1)
        self.client.switch_api_l3_interface_address_delete(0, rif2, vrf, i_ip2)

        self.client.switch_api_rif_delete(0, rif1)
        self.client.switch_api_rif_delete(0, rif2)

        self.client.switch_api_interface_delete(0, if1)
        self.client.switch_api_interface_delete(0, if2)

        self.client.switch_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
        self.client.switch_api_router_mac_group_delete(0, rmac)
        self.client.switch_api_vrf_delete(0, vrf)


###############################################################################

@group('ent')
class L3IPv4QosDscpRewriteTest2(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        #QOS_CLASSIFICATION flag is not enabled for QOS_PROFILE, bypass
        #this test for now.
        return
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[
            2], "  (192.168.0.1 -> 172.16.0.1 [id = 101])"
        vrf = self.client.switch_api_vrf_create(0, 2)

        rmac = self.client.switch_api_router_mac_group_create(
            device, SWITCH_RMAC_TYPE_ALL)
        self.client.switch_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])

        rif_info1 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_INTF,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=True,
            v6_unicast_enabled=True)
        rif1 = self.client.switch_api_rif_create(0, rif_info1)
        i_info1 = switcht_interface_info_t(
            handle=port1, type=SWITCH_INTERFACE_TYPE_PORT, rif_handle=rif1)
        if1 = self.client.switch_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switch_api_l3_interface_address_add(0, rif1, vrf, i_ip1)

        rif_info2 = switcht_rif_info_t(
            rif_type=SWITCH_RIF_TYPE_INTF,
            vrf_handle=vrf,
            rmac_handle=rmac,
            v4_unicast_enabled=True,
            v6_unicast_enabled=True)
        rif2 = self.client.switch_api_rif_create(0, rif_info2)
        i_info2 = switcht_interface_info_t(
            handle=port2, type=SWITCH_INTERFACE_TYPE_PORT, rif_handle=rif2)
        if2 = self.client.switch_api_interface_create(device, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='172.16.0.2', prefix_length=16)
        self.client.switch_api_l3_interface_address_add(0, rif2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='172.20.10.1', prefix_length=32)
	nhop, neighbor = switch_api_l3_nhop_neighbor_create(self, device, rif2, i_ip3, '00:11:22:33:44:55')
        self.client.switch_api_l3_route_add(0, vrf, i_ip3, nhop)

        qos_map1 = switcht_qos_map_t(dscp=1,  qid=1, icos=1, tc=20)
        qos_map2 = switcht_qos_map_t(dscp=2,  qid=2, icos=0, tc=24)
        qos_map3 = switcht_qos_map_t(dscp=3,  qid=3, icos=1, tc=28)
        qos_map4 = switcht_qos_map_t(dscp=4,  qid=4, icos=0, tc=32)
        ingress_qos_map_list = [qos_map1, qos_map2, qos_map3, qos_map4]
        ingress_qos_handle = self.client.switch_api_qos_map_ingress_create(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_INGRESS_DSCP_TO_QID_AND_TC,
            qos_map=ingress_qos_map_list)

        qos_map9 = switcht_qos_map_t(tc=20,  dscp=9)
        qos_map10 = switcht_qos_map_t(tc=24, dscp=10)
        qos_map11 = switcht_qos_map_t(tc=28, dscp=11)
        qos_map12 = switcht_qos_map_t(tc=32, dscp=12)
        egress_qos_map_list = [qos_map9, qos_map10, qos_map11, qos_map12]
        egress_qos_handle = self.client.switch_api_qos_map_egress_create(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_EGRESS_TC_TO_DSCP,
            qos_map=egress_qos_map_list)

        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port1, qos_handle=ingress_qos_handle)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port1, qos_handle=egress_qos_handle)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port1, trust_dscp=True)

        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port2, qos_handle=ingress_qos_handle)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port2, qos_handle=egress_qos_handle)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port2, trust_dscp=True)

        # send the test packet(s)
        pkt = simple_tcp_packet(
            eth_dst='00:77:66:55:44:33',
            eth_src='00:22:22:22:22:22',
            ip_dst='172.20.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_tos=4,
            ip_ttl=64)
        send_packet(self, swports[1], str(pkt))

        exp_pkt = simple_tcp_packet(
            eth_dst='00:11:22:33:44:55',
            eth_src='00:77:66:55:44:33',
            ip_dst='172.20.10.1',
            ip_src='192.168.0.1',
            ip_id=105,
            ip_tos=36,
            ip_ttl=63)
        verify_packets(self, exp_pkt, [swports[2]])

        #cleanup
        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port1, qos_handle=0)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port1, qos_handle=0)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port1, trust_dscp=False)

        self.client.switch_api_port_qos_group_ingress_set(
            device=0, port_handle=port2, qos_handle=0)
        self.client.switch_api_port_qos_group_egress_set(
            device=0, port_handle=port2, qos_handle=0)
        self.client.switch_api_port_trust_dscp_set(
            device=0, port_handle=port2, trust_dscp=False)

        self.client.switch_api_qos_map_ingress_delete(
            device=0, qos_map_handle=ingress_qos_handle)
        self.client.switch_api_qos_map_egress_delete(
            device=0, qos_map_handle=egress_qos_handle)

        self.client.switch_api_neighbor_delete(0, neighbor)
        self.client.switch_api_nhop_delete(0, nhop)
        self.client.switch_api_l3_route_delete(0, vrf, i_ip3, if2)

        self.client.switch_api_l3_interface_address_delete(0, rif1, vrf, i_ip1)
        self.client.switch_api_l3_interface_address_delete(0, rif2, vrf, i_ip2)

        self.client.switch_api_rif_delete(0, rif1)
        self.client.switch_api_rif_delete(0, rif2)

        self.client.switch_api_interface_delete(0, if1)
        self.client.switch_api_interface_delete(0, if2)

        self.client.switch_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
        self.client.switch_api_router_mac_group_delete(0, rmac)
        self.client.switch_api_vrf_delete(0, vrf)

###############################################################################

@group('qos-meter')
class L3IPv4QosDscpMeterTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        vlan = self.client.switch_api_vlan_create(device, 10)

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[0])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[1])

        i_info1 = switcht_interface_info_t(
            handle=port1, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if1 = self.client.switch_api_interface_create(device, i_info1)

        i_info2 = switcht_interface_info_t(
            handle=port2, type=SWITCH_INTERFACE_TYPE_ACCESS)
        if2 = self.client.switch_api_interface_create(device, i_info2)

        self.client.switch_api_vlan_member_add(device, vlan, if1)
        self.client.switch_api_vlan_member_add(device, vlan, if2)

        self.client.switch_api_mac_table_entry_create(
            device, vlan, '00:11:11:11:11:11', 2, if2)
        self.client.switch_api_mac_table_entry_create(
            device, vlan, '00:22:22:22:22:22', 2, if1)

        pkt = simple_udp_packet(
            eth_dst='00:11:11:11:11:11',
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.0.1',
            ip_ttl=64, ip_tos=80)
        exp_pkt = simple_udp_packet(
            eth_dst='00:11:11:11:11:11',
            eth_src='00:22:22:22:22:22',
            ip_dst='172.16.0.1',
            ip_ttl=64, ip_tos=80)

        try:
            api_meter_info = switcht_meter_info_t(
                meter_mode=1,
                color_source=1,
                meter_type=2,
                cbs=8,
                cir=1000,
                pbs=16,
                pir=2000,
                green_action=2,
                yellow_action=2,
                red_action=1)
            meter = self.client.switch_api_meter_create(0, api_meter_info)
            qos_map1 = switcht_qos_map_t(dscp=20, tc=20, meter_handle=meter)
            ingress_qos_map_list = [qos_map1]
            ingress_qos_handle = self.client.switch_api_qos_map_ingress_create(
                device=0,
                qos_map_type=SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC_AND_COLOR_AND_METER,
                qos_map=ingress_qos_map_list)
            self.client.switch_api_port_trust_dscp_set(device=0, port_handle=port1,trust_dscp=1)
            self.client.switch_api_port_qos_group_ingress_set(
                device=0, port_handle=port1, qos_handle=ingress_qos_handle)
            total_packets = 40
            counter_ids = [0, 1, 2]
            send_packet(self, swports[0], str(pkt), total_packets)
            time.sleep(20)
            counter = self.client.switch_api_meter_stats_get(0, meter,
                                                              counter_ids)
            total_meter_packets = 0
            for i in range(0, 3):
              total_meter_packets += counter[i].num_packets
              print "Counter %d, packets %d"%(i, counter[i].num_packets)

            self.assertTrue(total_packets == total_meter_packets)
        finally:
            self.client.switch_api_mac_table_entry_delete(device, vlan,
                                                          '00:11:11:11:11:11')
            self.client.switch_api_mac_table_entry_delete(device, vlan,
                                                          '00:22:22:22:22:22')

            self.client.switch_api_vlan_member_remove(device, vlan, if1)
            self.client.switch_api_vlan_member_remove(device, vlan, if2)

            self.client.switch_api_interface_delete(device, if1)
            self.client.switch_api_interface_delete(device, if2)

            self.client.switch_api_vlan_delete(device, vlan)
            self.client.switch_api_port_qos_group_ingress_set(
                  device=0, port_handle=port1, qos_handle=0)
            self.client.switch_api_meter_delete(0, meter)
            self.client.switch_api_qos_map_ingress_delete(0, ingress_qos_handle)
            self.client.switch_api_port_trust_dscp_set(device=0, port_handle=port1,trust_dscp=0)

@group('qos')
class PfcPriorityToQueueTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[
            2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])
        port3 = self.client.switch_api_port_id_to_handle_get(device, swports[3])
        port_list = [port1, port2, port3]
        qos_map1 = switcht_qos_map_t(pfc_prio=0, qid=0)
        qos_map2 = switcht_qos_map_t(pfc_prio=1, qid=1)
        qos_map3 = switcht_qos_map_t(pfc_prio=2, qid=2)
        qos_map4 = switcht_qos_map_t(pfc_prio=3, qid=3)
        egress_qos_map_list = [qos_map1, qos_map2, qos_map3, qos_map4]
        egress_qos_handle = self.client.switch_api_qos_map_egress_create(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_EGRESS_PFC_PRIORITY_TO_QUEUE,
            qos_map=egress_qos_map_list)
        for port in port_list:
          self.client.switch_api_port_pfc_queue_set(
              device=0, port_handle=port, qos_handle=egress_qos_handle)

        egress_qos_map_list.remove(qos_map4)
        qos_map4 = switcht_qos_map_t(pfc_prio=3, qid=4)
        egress_qos_map_list.append(qos_map4)
        for qmap in egress_qos_map_list:
          print qmap
        egress_qos_handle = self.client.switch_api_qos_map_set(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_EGRESS_PFC_PRIORITY_TO_QUEUE,
            qos_handle=egress_qos_handle,
            qos_map=egress_qos_map_list)
@group('qos')
class PfcPriorityToPPGTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[
            2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"

        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port2 = self.client.switch_api_port_id_to_handle_get(device, swports[2])
        port3 = self.client.switch_api_port_id_to_handle_get(device, swports[3])
        port_list = [port1]
        qos_map1 = switcht_qos_map_t(icos=0, ppg=0)
        qos_map2 = switcht_qos_map_t(icos=1, ppg=0)
        qos_map3 = switcht_qos_map_t(icos=2, ppg=0)
        qos_map4 = switcht_qos_map_t(icos=3, ppg=1)
        ingress_qos_map_list = [qos_map1, qos_map2, qos_map3, qos_map4]
        ingress_qos_handle = self.client.switch_api_qos_map_ingress_create(
            device=0,
            qos_map_type=SWITCH_QOS_MAP_INGRESS_ICOS_TO_PPG,
            qos_map=ingress_qos_map_list)
        for port in port_list:
          self.client.switch_api_port_icos_to_ppg_set(
              device=0, port_handle=port, qos_handle=ingress_qos_handle)

        for port in port_list:
          self.client.switch_api_port_icos_to_ppg_set(
              device=0, port_handle=port, qos_handle=0)

