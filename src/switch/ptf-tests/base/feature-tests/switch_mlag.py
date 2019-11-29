###############################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2015-2016 Barefoot Networks, Inc.

# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks,
# Inc.
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
##############################################################################
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
sys.path.append(os.path.join(this_dir, '../../base'))
sys.path.append(os.path.join(this_dir, '../../base/api-tests'))
sys.path.append(os.path.join(this_dir, '../../base/common'))
import api_base_tests
import pd_base_tests
from common.utils import *
from common.api_utils import *
from common.api_adapter import ApiAdapter

device = 0
cpu_port = 64

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)

if swports == []:
    swports = [x for x in range(65)]


###############################################################################
@group('mlag')
class MLAGFloodTest(ApiAdapter):
    def setUp(self):
        super(self.__class__, self).setUp()
        print
        print "mLAG flooding - peer-link[1,2], mlag1[3,4], mlag2[5], normal lag[6,7], port 8"
        self.vlan_id = 10
        self.fp_ports = [swports[0], swports[1], swports[2], swports[3], swports[4], swports[5], swports[6], swports[7], swports[8], swports[9]]
        self.port_h = [0] * len(self.fp_ports)
        self.intf_h = [0] * len(self.fp_ports)
        
        self.vlan_h = self.add_vlan(device, self.vlan_id)

        port = [0]*10
        for pnum in range(1, len(self.fp_ports)):
            self.port_h[pnum] = self.select_port(device, swports[pnum])

        # Create peer-link
        self.peer_lag = self.add_lag(device)
        self.add_lag_member(device, self.peer_lag, self.port_h[1])
        self.add_lag_member(device, self.peer_lag, self.port_h[2])
        peer_link_if = self.add_logical_l2lag(device, self.peer_lag)
        
        self.client.switch_api_lag_peer_link_set(device, self.peer_lag, True);

        # create a mLAG with two member ports on current switch
        self.mlag1 = self.add_lag(device)
        self.add_lag_member(device, self.mlag1, self.port_h[3])
        self.add_lag_member(device, self.mlag1, self.port_h[4])
        mlag1_if = self.add_logical_l2lag(device, self.mlag1)
        
        self.client.switch_api_lag_mlag_set(device, self.mlag1, True);

        # create a mLAG with a single member port on current switch
        self.mlag2 = self.add_lag(device)
        self.add_lag_member(device, self.mlag2, self.port_h[5])
        mlag2_if = self.add_logical_l2lag(device, self.mlag2)
        
        self.client.switch_api_lag_mlag_set(device, self.mlag2, True);

        # create a regular LAG with two member ports
        self.lag3 = self.add_lag(device)
        self.add_lag_member(device, self.lag3, self.port_h[6])
        self.add_lag_member(device, self.lag3, self.port_h[7])
        lag3_if = self.add_logical_l2lag(device, self.lag3)
        
        # non-mLAG port
        if4 = self.cfg_l2intf_on_port(device, self.port_h[8])

        self.add_vlan_member(device, self.vlan_h, peer_link_if)
        self.add_vlan_member(device, self.vlan_h, mlag1_if)
        self.add_vlan_member(device, self.vlan_h, mlag2_if)
        self.add_vlan_member(device, self.vlan_h, lag3_if)
        self.add_vlan_member(device, self.vlan_h, if4)
        
    def runTest(self):
            # Send from peer_link, should not be received on mlag ports
            pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:22:22:22:22:22',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)
            exp_pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:22:22:22:22:22',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)

            print "Sending packet from peer_lag port1 -> mlag1, mlag2, lag_if3, if4"
            send_packet(self, swports[1], str(pkt))
            verify_any_packet_on_ports_list(self, [exp_pkt], [[swports[6], swports[7]], [swports[8]]])
            
            # Send from mlag1, should be received everywhere
            pkt = simple_tcp_packet(
                eth_dst='00:33:33:33:33:33',
                eth_src='00:22:22:22:22:22',
                ip_dst='172.16.0.3',
                ip_id=107,
                ip_ttl=33)
            exp_pkt = simple_tcp_packet(
                eth_dst='00:33:33:33:33:33',
                eth_src='00:22:22:22:22:22',
                ip_dst='172.16.0.3',
                ip_id=107,
                ip_ttl=33)

            print "Sending packet from mlag1 port3 -> peer_lag, mlag2, lag_if3, if4"
            send_packet(self, swports[3], str(pkt))
            verify_any_packet_on_ports_list(self, [exp_pkt], [[swports[1], swports[2]], [swports[5]], [swports[6], swports[7]], [swports[8]]])

            # Remove a member port from mlag1 and add it to lag3
            self.remove_lag_member(device, self.mlag1, self.port_h[3])
            self.remove_lag_member(device, self.lag3, self.port_h[6])
            self.add_lag_member(device, self.lag3, self.port_h[3])
            print "After moving port 3 from mlag 1 to lag 3 members - peer-link[1,2], mlag1[4], mlag2[5], normal lag[3,7], port 8"

            # Send from peer_link, should not be received on mlag ports
            pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:33:33:33:33:33',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)
            exp_pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:33:33:33:33:33',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)

            print "Sending packet from peer_lag port2 -> mlag1, mlag2, lag_if3, if4"
            send_packet(self, swports[2], str(pkt))
            verify_any_packet_on_ports_list(self, [exp_pkt], [[swports[3], swports[7]], [swports[8]]])
            
            # Add port 6 to peer lag
            self.add_lag_member(device, self.peer_lag, self.port_h[6])
            print "After adding port 6 to peer lag - peer-link[1,2,6], mlag1[4], mlag2[5], normal lag[3,7], port 8"

            # Send from peer_link, should not be received on mlag ports
            pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:33:33:33:33:33',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)
            exp_pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:33:33:33:33:33',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)

            print "Sending packet from peer_lag port6 -> mlag1, mlag2, lag_if3, if4"
            send_packet(self, swports[6], str(pkt))
            verify_any_packet_on_ports_list(self, [exp_pkt], [[swports[3], swports[7]], [swports[8]]])
            
            # Send a known unicast packet from peer_link to one of the mlag ports, should be dropped
            pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:22:22:22:22:22',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)
            exp_pkt = simple_tcp_packet(
                eth_src='00:11:11:11:11:11',
                eth_dst='00:22:22:22:22:22',
                ip_dst='172.16.0.1',
                ip_id=107,
                ip_ttl=33)

            print "Sending packet from peer_lag port1 -> expecting it to be dropped"
            send_packet(self, swports[1], str(pkt))
            verify_no_other_packets(self, timeout=1)
            
    def tearDown(self):
        self.client.switch_api_lag_mlag_set(device, self.mlag1, False);
        self.client.switch_api_lag_mlag_set(device, self.mlag2, False);
        self.client.switch_api_lag_peer_link_set(device, self.peer_lag, False);
        self.cleanup();
        self.client.switch_api_mac_table_entry_flush(
            device, SWITCH_MAC_FLUSH_TYPE_ALL, 0x0, 0x0)
        api_base_tests.ThriftInterfaceDataPlane.tearDown(self)

