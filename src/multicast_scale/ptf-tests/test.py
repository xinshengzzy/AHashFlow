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
Thrift PD interface basic tests
"""

import time
import datetime
import sys
import logging
import copy
import pdb

import unittest
import random

import pd_base_tests

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
import ptf.dataplane as dataplane

import os

from pal_rpc.ttypes import *
from multicast_scale.p4_pd_rpc.ttypes import *
from conn_mgr_pd_rpc.ttypes import *
from mc_pd_rpc.ttypes import *
from tm_api_rpc.ttypes import *
from devport_mgr_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from ptf_port import *

from multicast import *

dev_id = 0







"""
Scaling
 - Use all MGIDs
 - Use all RDM
 - Use all LAGs
 - Long L1 chains
 - ECMP group
 - Reconfigure w/ traffic
 - Fast reconfig
"""

def get_num_pipes():
    x = test_param_get('num_pipes')
    if x is None:
        return 4
    return int(x)

g_all_ports = []
g_ports_by_pipe = []
for pipe in range( get_num_pipes() ):
    pipe_ports = [make_port(pipe, local_port) for local_port in range(0,64,4)]
    g_ports_by_pipe.append( pipe_ports )
    g_all_ports += pipe_ports

def update_progress(now, total):
    progress = float(now) / float(total)
    barLength = 10 # Modify this to change the length of the progress bar
    status = ""
    if progress < 0:
        progress = 0
        status = "Halt...\r\n"
    if progress >= 1:
        progress = 1
        status = "Done...\r\n"
    block = int(round(barLength*progress))
    text = "\rPercent: [{0}] {1:.2f}% {2}/{3} {4}".format( "#"*block + "-"*(barLength-block), progress*100, now, total, status)
    sys.stdout.write(text)
    sys.stdout.flush()


def has_ports_in_pipe(pipe, ports):
    for port in ports:
        if pipe == port_to_pipe(port):
            return True
    return False

def calculateExpectedCounts(trees):
    rid_port_cnts = {}
    for tree in trees:
        ports = tree.get_ports(0, 0, 0, 0, 0)
        #tree.print_tree()
        for rid, port_list in ports:
            for pipe in range(get_num_pipes()):
                ports_in_pipe = [x for x in port_list if pipe == portToPipe(x)]
                if 0 == len(ports_in_pipe):
                    continue

                for i,port in enumerate(ports_in_pipe):
                    if (rid,port) in rid_port_cnts:
                        c = rid_port_cnts[(rid,port)]
                    else:
                        c = (0,0)
                    if i == 0:
                        c = (c[0] + 1, c[1])
                    else:
                        c = (c[0], c[1] + 1)
                    rid_port_cnts[(rid,port)] = c
    return rid_port_cnts

def addEgressEntries(test, trees):
    rid_to_ports = {}
    egr_key_to_hdl = {}
    egr_hdl_to_dt = {}
    for tree in trees:
        ports = tree.get_ports(0, 0, 0, 0, 0)
        for rid, port_list in ports:
            if rid in rid_to_ports:
                rid_to_ports[rid] = rid_to_ports[rid] | set(port_list)
            else:
                rid_to_ports[rid] = set(port_list)
    for rid in rid_to_ports:
        for port in rid_to_ports[rid]:
            h = test.client.egr_table_add_with_log_only( test.shdl,
                                                         test.dts[portToPipe(port)],
                                                         multicast_scale_egr_match_spec_t(port, hex_to_i16(rid)),
                                                         0 )
            egr_key_to_hdl[ (rid,port) ] = h
            egr_hdl_to_dt[ h ] = test.dts[portToPipe(port)]
    for dt in test.dts:
        zero = multicast_scale_counter_value_t(0,0)
        test.client.counter_write_cntr(test.shdl, dt, 0, zero)
        test.client.counter_write_cntr(test.shdl, dt, 1, zero)
    return (egr_key_to_hdl, egr_hdl_to_dt)

def rmv_ports(test):
    test.pal.pal_port_del_all(dev_id)
def add_ports(test):
    # Remove any existing ports.
    rmv_ports(test)
    # Add all front panel ports as 100g
    speed = pal_port_speed_t.BF_SPEED_100G
    fec = pal_fec_type_t.BF_FEC_TYP_REED_SOLOMON
    for port in g_all_ports:
        test.pal.pal_port_add(dev_id, port, speed, fec)
        test.tm.tm_set_q_guaranteed_min_limit(dev_id, port, 0, 100000)
    test.pal.pal_port_enable_all(dev_id)
    for port in g_all_ports:
        test.pal.pal_port_loopback_mode_set(dev_id, port, pal_loopback_mod_t.BF_LPBK_MAC_NEAR)


class Test1(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, ["multicast_scale"])
        setup_random()
        num_pipes = get_num_pipes()
        print "Using", num_pipes, "pipes"
        self.lags = set(range(255))
        self.dt = DevTarget_t(dev_id, hex_to_i16(0xFFFF))
        self.dts = [DevTarget_t(dev_id, p) for p in range(num_pipes)]
        self.reg_async = multicast_scale_register_flags_t(read_hw_sync = False)
        self.cntr_sync = multicast_scale_counter_flags_t(read_hw_sync = True)
        self.cntr_async = multicast_scale_counter_flags_t(read_hw_sync = False)
        self.ing_port = 0

        self.ing_hdls = {}
        self.egr_key_to_hdl = {}
        self.rid_port_cnts = {}
        self.egr_hdl_to_dt = {}
        self.trees = set()

    def setUp(self):
        pd_base_tests.ThriftInterfaceDataPlane.setUp(self)
        add_ports(self)
        shdl = self.conn_mgr.client_init()
        prop_val = tbl_property_value_t.ENTRY_SCOPE_SINGLE_PIPELINE
        self.client.egr_set_property(shdl, dev_id, tbl_property_t.TBL_PROP_TBL_ENTRY_SCOPE, prop_val, 0)
        self.conn_mgr.client_cleanup(shdl)
        self.shdl = self.conn_mgr.client_init()
        x = self.mc.mc_create_session()
        y = self.mc.mc_create_session()
        self.mc_shdl = [x,y]

    def tearDown(self):
        for x in self.mc_shdl:
            self.mc.mc_destroy_session( x )
        self.conn_mgr.client_cleanup(self.shdl)
        rmv_ports(self)


    def configMGIDsWithLAG(self, mgid_count):
        t.setup(self, dev_id, self.mc_shdl[0])

        # For each LAG, add 8 ports
        print datetime.datetime.now(), "Adding ports to LAGs"
        for i in range(255):
            port_list = random.sample( g_all_ports, 8 )
            t.get_lag_tbl().getLag(i).addMbr( port_list )

        # Allocate all the MGIDs
        print datetime.datetime.now(), "Allocating all MGIDs"
        for _ in range(mgid_count):
            mgid = t.next_mgid()
            mct = MCTree(self, self.mc_shdl[0], dev_id, mgid)
            self.trees.add( mct )
            if 0 == len(self.trees) % 64: update_progress( len(self.trees), mgid_count )
        self.assertEqual(len(self.trees), mgid_count)
        print datetime.datetime.now(), "  Done allocating all MGIDs"

        # Add nodes to the MGIDs
        # Each MGID will use 1 L1 node and 1 LAG node.
        print datetime.datetime.now(), "Adding a node to each MGID"
        rid = 0
        for tree in self.trees:
            ports = []
            lags = [ random.randint(0, 254) ]
            tree.add_node(rid, None, ports, lags)
            rid = rid + 1
            if 0 == rid % 64: update_progress( rid, len(self.trees) )
        print datetime.datetime.now(), "  Done adding a node to each MGID"

        # Set up the packet generator
        for p in range(68,72):
            try:
                self.devport_mgr.devport_mgr_remove_port(dev_id, p)
            except InvalidDevportMgrOperation as e:
                pass
        speed_100g = 64
        self.devport_mgr.devport_mgr_add_port(dev_id, 68, speed_100g, 0)
        self.conn_mgr.pktgen_enable( self.shdl, dev_id, 68) # Pipe0, Port 68, Chan 0
        pga = PktGenAppCfg_t( trigger_type=PktGenTriggerType_t.TIMER_ONE_SHOT,
                              batch_count=0,
                              pkt_count=hex_to_i16(len(self.trees)/2-1),
                              #pkt_count=0,
                              pattern_key=0,
                              pattern_msk=0,
                              timer=1,
                              ibg=0,
                              ibg_jitter=0,
                              ipg=0,
                              ipg_jitter=0,
                              src_port=self.ing_port,
                              src_port_inc=0,
                              buffer_offset=0,
                              length=64 )
        self.conn_mgr.pktgen_cfg_app( self.shdl, self.dts[0], 0, pga )
        pkt = simple_eth_packet(pktlen=64, eth_type=0xFEED)
        self.conn_mgr.pktgen_write_pkt_buffer( self.shdl, self.dts[0], 0, len(str(pkt))-6, str(pkt)[6:] )

        # Add ingress entries to map packets to all MGIDs
        print datetime.datetime.now(), "Adding ingress entries"
        self.conn_mgr.begin_batch( self.shdl )
        for i in range( len(self.trees)/2 ):
            mgid1 = 2*i
            mgid2 = mgid1 + 1
            dmac = "00:00:00:00:%02x:%02x" % (i >> 8, i & 0xFF)
            aspec = multicast_scale_mcast_both_action_spec_t( hex_to_i16(mgid1), hex_to_i16(mgid2), 0, 0, 0, 0, 0 )
            mspec = multicast_scale_ing_match_spec_t( hex_to_i16(self.ing_port), macAddr_to_string( dmac ) )
            h = self.client.ing_table_add_with_mcast_both( self.shdl, self.dt, mspec, aspec)
            self.ing_hdls[h] = (mgid1, mgid2)
        print datetime.datetime.now(), "  Done adding ingress entries"

        # Add egress entries to match all generated multicast copies.
        print datetime.datetime.now(), "Adding egress entries"
        self.egr_key_to_hdl, self.egr_hdl_to_dt = addEgressEntries(self, self.trees)
        self.conn_mgr.end_batch( self.shdl, False )
        print datetime.datetime.now(), "  Done adding egress entries"

        # Calculate the expected egress counts.
        self.rid_port_cnts = calculateExpectedCounts(self.trees)

        self.conn_mgr.complete_operations( self.shdl )


    def shuffleMGIDsWithLAG(self):
        # Remove some multicast trees
        to_pop = len(self.trees)/2
        for _ in range(to_pop):
            mct = self.trees.pop()
            mgid = mct.mgid
            mct.cleanUp()
            t.release_mgid(mgid)
        # Add them back again.
        rid = 0
        for _ in range(to_pop):
            mgid = t.next_mgid()
            mct = MCTree(self, self.mc_shdl[0], dev_id, mgid)
            ports = []
            lags = [ random.randint(0, 254) ]
            mct.add_node(rid, None, ports, lags)
            rid = rid + 1
            self.trees.add( mct )
        for h in self.mc_shdl:
            self.mc.mc_complete_operations(h)

        # Fix up the egress match entries
        self.conn_mgr.begin_batch( self.shdl )
        for key in self.egr_key_to_hdl:
            self.client.egr_table_delete( self.shdl, dev_id, self.egr_key_to_hdl[key] )
        self.egr_key_to_hdl = {}
        self.egr_key_to_hdl, self.egr_hdl_to_dt = addEgressEntries(self, self.trees)
        self.conn_mgr.end_batch( self.shdl, True )

        # Recalculate the expected egress counter values.
        self.rid_port_cnts = calculateExpectedCounts(self.trees)

    def cleanUp(self):
        print datetime.datetime.now(), "Starting cleanup"
        self.mc.mc_begin_batch( self.mc_shdl[0] )
        for mct in self.trees:
            mct.cleanUp()
        print datetime.datetime.now(), "\tTrees done"
        t.cleanUp()
        print datetime.datetime.now(), "\tUtil done"
        self.mc.mc_end_batch( self.mc_shdl[0], False )

        self.conn_mgr.begin_batch( self.shdl )
        for h in self.ing_hdls:
            self.client.ing_table_delete( self.shdl, dev_id, h )
        print datetime.datetime.now(), "\tIngress entries done"
        for key in self.egr_key_to_hdl:
            self.client.egr_table_delete( self.shdl, dev_id, self.egr_key_to_hdl[key] )
        print datetime.datetime.now(), "\tEgress entries done"
        self.conn_mgr.end_batch( self.shdl, False )

        self.trees = set()
        self.ing_hdls = {}
        print datetime.datetime.now(), "  Done with cleanup"

    def checkWithTraffic(self):
        # Start the traffic with pkt-gen.
        print datetime.datetime.now(), "Sending a packet to each MGID"
        pgen_cntr_base = self.conn_mgr.pktgen_get_pkt_counter(self.shdl, self.dts[0], 0)
        self.conn_mgr.pktgen_app_enable( self.shdl, self.dts[0], 0 )

        # Wait for it to finish.
        pgen_cntr_done = pgen_cntr_base + len(self.trees)/2
#        while True:
        for i in range(5):
            pgen_cntr = self.conn_mgr.pktgen_get_pkt_counter(self.shdl, self.dts[0], 0)
            update_progress( pgen_cntr, pgen_cntr_done )
            if pgen_cntr_done <= pgen_cntr:
                break
            else:
                time.sleep(5)
        self.conn_mgr.pktgen_app_disable( self.shdl, self.dts[0], 0 )
        print datetime.datetime.now(), "  Done sending a packet to each MGID"

        print datetime.datetime.now(), "Waiting for all packets to be processed"
        hit = 0
        miss = 0
#        while hit+miss < len(self.trees):
        for i in range(5):
            hit = 0
            miss = 0
            for dt in self.dts:
                hit  += self.client.counter_read_cntr(self.shdl, dt, 0, self.cntr_sync).packets
                miss += self.client.counter_read_cntr(self.shdl, dt, 1, self.cntr_sync).packets
            update_progress( hit+miss, len(self.trees) )
            time.sleep(5)
        print datetime.datetime.now(), "All packets are processed"
        print datetime.datetime.now(), "Hit: ", hit
        print datetime.datetime.now(), "Miss:", miss

        print datetime.datetime.now(), "Syncing registers"
        self.client.register_hw_sync_log( self.shdl, self.dt )
        print datetime.datetime.now(), "  Done syncing registers"
        fail = False
        for key in self.rid_port_cnts:
            hdl = self.egr_key_to_hdl[key]
            r = self.client.register_read_log(self.shdl, self.egr_hdl_to_dt[hdl], hdl, self.reg_async)
            print "register:", r
            r_cnt = (r[0] >> 8, r[0] & 0xFF)
            c = self.rid_port_cnts[key]
            if r_cnt != c:
                rid,port = key
                print "0x%04x %3d: (%d %d) != (%d %d)" % (rid, port, c[0], c[1], r_cnt[0], r_cnt[1])
                fail = True
        self.assertFalse( fail )

    def runTest(self):
        self.configMGIDsWithLAG(64*1024)
        self.checkWithTraffic()
        self.shuffleMGIDsWithLAG()
        self.checkWithTraffic()
        self.cleanUp()
