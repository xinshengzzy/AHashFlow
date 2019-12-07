import time
import sys
import logging
import copy

import unittest
import random

import pd_base_tests

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
import ptf.dataplane as dataplane

import os

from mc_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from ptf_port import *


class IdGen:
    def __init__(self, min_id, max_id):
        self.available = range(min_id, max_id+1)
        self.used = set()
    def get(self):
        x = random.choice( self.available )
        self.available.remove( x )
        self.used.add( x )
        return x
    def get_first(self):
        x = self.available.pop(0)
        self.used.add( x )
        return x
    def free(self, x):
        self.used.remove( x )
        self.available.append( x )
        self.available.sort()

class TestUtil:
    def __init__(self):
        self.test = None
        self.lag_tbl = None
        self.yid_tbl = None
        self.sw_mask = [0 for x in range(288)]
        self.hw_mask = [0 for x in range(288)]
        self.mgid = IdGen(0, 0xFFFF)
        self.rid  = IdGen(0, 0xFFFF)
        self.yid  = IdGen(0, 288)
        self.xid  = IdGen(0, 0xFFFF)
        self.lag  = IdGen(0, 255)
    def setup(self, test, dev, mc_shdl):
        self.dev = dev
        self.test = test
        self.mc_shdl = mc_shdl
        self.lag_tbl = LagTable(self.test, self.mc_shdl, self.dev)
        self.yid_tbl = YidTable(self.test, self.mc_shdl, self.dev, 0)
        self.sw_mask = [0 for x in range(288)]
        self.hw_mask = [0 for x in range(288)]
        self.backup_ports = [0 for x in range(288)]
        for x in range(288):
            self.backup_ports[x] = BitIdxToPort(x)
    def cleanUp(self):
        self.lag_tbl.cleanUp()
        self.yid_tbl.cleanUp()
        self.sw_mask = [0 for x in range(288)]
        self.hw_mask = [0 for x in range(288)]
        for x in range(288):
            self.clr_backup_port( BitIdxToPort(x) )
        #self.disable_port_ff()
        self.lag_tbl = None
        self.yid_tbl = None
        self.test = None
    def new_mgid(self):
        return self.mgid.get()
    def next_mgid(self):
        return self.mgid.get_first()
    def release_mgid(self, mgid):
        self.mgid.free(mgid)
    def get_lag_tbl(self):
        return self.lag_tbl
    def get_yid_tbl(self):
        return self.yid_tbl
    def get_sw_mask(self):
        return self.sw_mask
    def get_hw_mask(self):
        return self.hw_mask
    def sw_port_down(self, port):
        self.sw_mask[ portToBitIdx(port) ] = 1
        self.test.mc.mc_set_port_mc_fwd_state(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev), hex_to_i16(port), hex_to_byte(0))
    def sw_port_up(self, port):
        self.sw_mask[ portToBitIdx(port) ] = 0
        self.test.mc.mc_set_port_mc_fwd_state(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev), hex_to_i16(port), hex_to_byte(1))
    def enable_port_ff(self):
        self.test.mc.mc_enable_port_ff(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev))
    def disable_port_ff(self):
        self.test.mc.mc_disable_port_ff(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev))
    def enable_backup_ports(self):
        self.test.mc.mc_enable_port_protection(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev))
    def disable_backup_ports(self):
        self.test.mc.mc_disable_port_protection(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev))
    def set_backup_port(self, pport, bport):
        self.backup_ports[ portToBitIdx(pport) ] = bport
        self.test.mc.mc_set_port_protection(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev), hex_to_i16(pport), hex_to_i16(bport))
    def clr_backup_port(self, port):
        self.backup_ports[ portToBitIdx(port) ] = port
        self.test.mc.mc_clear_port_protection(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev), hex_to_i16(port))
    def clr_hw_port_down(self, port):
        self.hw_mask[ portToBitIdx(port) ] = 0
        self.test.mc.mc_clr_port_ff_state(hex_to_i32(self.mc_shdl), hex_to_i32(self.dev), hex_to_i16(port))
    def set_port_down(self, port):
        self.hw_mask[ portToBitIdx(port) ] = 1
        take_port_down(port)
    def set_port_up(self, port):
        bring_port_up(port)

t = TestUtil()


def setup_random(seed_val=0):
    if 0 == seed_val:
        seed_val = int(time.time())
    #seed_val = 1464037393
    print "Seed is:", seed_val
    random.seed(seed_val)

def make_port(pipe, local_port):
    assert(pipe >= 0 and pipe < 4)
    assert(local_port >= 0 and local_port < 72)
    return (pipe << 7) | local_port

def portToPipe(port):
    return port >> 7

def portToPipeLocalId(port):
    return port & 0x7F

def portToBitIdx(port):
    pipe = portToPipe(port)
    index = portToPipeLocalId(port)
    return 72 * pipe + index

def BitIdxToPort(index):
    pipe = index / 72
    local_port = index % 72
    return (pipe << 7) | local_port

def set_port_map(indicies):
    bit_map = [0] * ((288+7)/8)
    for i in indicies:
        index = portToBitIdx(i)
        bit_map[index/8] = (bit_map[index/8] | (1 << (index%8))) & 0xFF
    return bytes_to_string(bit_map)
def set_lag_map(indicies):
    bit_map = [0] * ((256+7)/8)
    for i in indicies:
        bit_map[i/8] = (bit_map[i/8] | (1 << (i%8))) & 0xFF
    return bytes_to_string(bit_map)

def verify_packet_list(test, port_ll, pkt_ll):
    more_to_rx = False
    for port_list in port_ll:
        if len(port_list) != 0:
            more_to_rx = True
    while more_to_rx:
        found_port = False
        found_pkt  = False
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll( timeout=1.0 )
        #print "Rx on port", rcv_port
        #print format_packet( rcv_pkt )

        if rcv_port is None:
            print "Didn't receive packet!!!"
            print "Expected ports remaining:", port_ll
            test.assertTrue(rcv_port is not None)

        # See if the received port+packet pair is in any of the lists passed in.
        for port_list, pkt_list in zip(port_ll, pkt_ll):
            if rcv_port in port_list:
                found_port = True
                for exp_pkt in pkt_list:
                    if dataplane.match_exp_pkt(exp_pkt, rcv_pkt):
                        pkt_list.remove(exp_pkt)
                        found_pkt = True
                        break
                if found_pkt:
                    port_list.remove(rcv_port)
                    break

        if found_port != True or found_pkt != True:
            print "Unexpected Rx: port", rcv_port
            print format_packet(rcv_pkt)
            print "Expected the following:"
            for port_list, pkt_list in zip(port_ll, pkt_ll):
                print "  Ports:", sorted(port_list)
                for pkt in pkt_list:
                    print"  Pkt:  ", format_packet(pkt)
            test.assertTrue(found_port == True, "Unexpected port %r" % rcv_port)
            test.assertTrue(found_pkt  == True, "Unexpected pkt on port %r" % rcv_port)

        more_to_rx = False
        for port_list in port_ll:
            if len(port_list) != 0:
                more_to_rx = True

    (rcv_device, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll( timeout=0.1 )
    if rcv_port != None:
        print "Extra Rx: port", rcv_port, "Packet", format_packet(rcv_pkt)
        test.assertTrue(rcv_pkt == None, "Receive extra packet")

def build_rx_packet_list(port_list, pkt):
    pkt_list = []
    tmp_port_list = sorted(port_list)
    last_pipe = -1
    for port in tmp_port_list:
        if last_pipe == portToPipe(port):
            pkt.tos = 0
            pkt_list.append(copy.deepcopy(pkt))
        else:
            pkt.tos = 1
            last_pipe = portToPipe(port)
            pkt_list.append(copy.deepcopy(pkt))

    return pkt_list

class MCNode:
    def __init__(self, test, shdl, rid, dev, ports=[], lags=[]):
        self.shdl      = shdl
        self.rid       = rid
        self.dev       = dev
        self.mgid_hdl  = None
        self.xid       = None
        self.l2_hdl    = None
        self.mbr_ports = sorted(ports)
        self.mbr_lags  = sorted(lags)
        for i in self.mbr_lags:
            assert i >= 0 and i <= 255
        p = set_port_map(self.mbr_ports)
        l  = set_lag_map(self.mbr_lags)
        self.node_hdl = test.mc.mc_node_create(hex_to_i32(shdl), hex_to_i32(dev), hex_to_i16(rid), p, l)
        assert(0 != self.node_hdl)
    def __repr__(self):
        return "MCNode_" + str(hex(self.node_hdl))
    def __str__(self):
        return str(hex(self.node_hdl))
    def node_hdl(self):
        return self.node_hdl
    def get_rid(self):
        return self.rid
    def get_mbr_ports(self):
        return list(self.mbr_ports)
    def associate(self, test, mgrp_hdl, xid):
        self.mgid_hdl = mgrp_hdl
        self.xid = xid
        if xid is None:
            xid = 0
            use_xid = 0
        else:
            use_xid = 1
        test.mc.mc_associate_node(hex_to_i32(self.shdl),
                                  hex_to_i32(self.dev),
                                  hex_to_i32(self.mgid_hdl),
                                  hex_to_i32(self.node_hdl),
                                  hex_to_i16(xid), use_xid)
    def dissociate(self, test):
        test.mc.mc_dissociate_node(hex_to_i32(self.shdl),
                                   hex_to_i32(self.dev),
                                   hex_to_i32(self.mgid_hdl),
                                   hex_to_i32(self.node_hdl))
    def addMbrs(self, test, port_list, lag_list):
        if port_list is None and lag_list is None:
            return 0
        if port_list is not None:
            self.mbr_ports += port_list
            self.mbr_ports.sort()
        if lag_list is not None:
            for i in lag_list:
                assert i >= 0 and i <= 255
            self.mbr_lags += lag_list
            self.mbr_lags.sort()
        ports = set_port_map(self.mbr_ports)
        lags  = set_lag_map(self.mbr_lags)
        test.mc.mc_node_update(hex_to_i32(self.shdl),
                               hex_to_i32(self.dev),
                               hex_to_i32(self.node_hdl),
                               ports, lags)
    def replaceMbrs(self, test, port_list, lag_list):
        self.mbr_ports = sorted(port_list)
        self.mbr_lags = sorted(lag_list)
        for i in self.mbr_lags:
            assert i >= 0 and i <= 255
        ports = set_port_map(self.mbr_ports)
        lags  = set_lag_map(self.mbr_lags)
        test.mc.mc_node_update(hex_to_i32(self.shdl),
                               hex_to_i32(self.dev),
                               hex_to_i32(self.node_hdl),
                               ports, lags)
    def getPorts(self, rid, yid, h2):
        global t
        # Start with the individual ports on the L1 and then apply pruning
        port_list = self.get_mbr_ports()
        if self.rid == rid or rid == t.get_yid_tbl().global_rid():
            t.get_yid_tbl().prune_ports(yid, port_list)
        # If any ports are down, replace them with their backup
        # Since the backup table is initialized such that each port backups up
        # itself we can blindly take the backup table contents if the port is
        # down.
        if port_list:
            for x in range(len(port_list)):
                pport = port_list[x]
                pport_idx = portToBitIdx(pport)
                if t.sw_mask[pport_idx] == 1 or t.hw_mask[pport_idx] == 1:
                    port_list[x] = t.backup_ports[pport_idx]
        # For each LAG on the L1, pick the correct member port
        for lag_id in self.mbr_lags:
            lag = t.get_lag_tbl().getLag( lag_id )
            port = lag.getMbrByHash(h2, rid, self.rid, yid)
            if port is not None:
                port_list.append(port)
        return port_list

    def cleanUp(self, test):
        if self.mgid_hdl is not None:
            test.mc.mc_dissociate_node(hex_to_i32(self.shdl),
                                       hex_to_i32(self.dev),
                                       hex_to_i32(self.mgid_hdl),
                                       hex_to_i32(self.node_hdl))
            self.mgid_hdl = None
        test.mc.mc_node_destroy(hex_to_i32(self.shdl), hex_to_i32(self.dev), hex_to_i32(self.node_hdl))
        self.node_hdl = 0

class LagGrp:
    def __init__(self, test, shdl, dev, lag_id):
        assert lag_id >= 0 and lag_id <= 255
        self.shdl = shdl
        self.dev = dev
        self.test = test
        self.lag_id = lag_id
        self.left_cnt = 0
        self.right_cnt = 0
        self.mbrs = []
    def setRmtCnt(self, left, right):
        self.left_cnt = left
        self.right_cnt = right
        self.test.mc.mc_set_remote_lag_member_count(hex_to_i32(self.shdl), hex_to_i32(self.dev),
                                                    hex_to_byte(self.lag_id), hex_to_i32(left), hex_to_i32(right))
    def addMbr(self, port_list):
        self.mbrs = list(set(self.mbrs + port_list))
        self.mbrs.sort()
        bit_map = set_port_map(self.mbrs)
        self.test.mc.mc_set_lag_membership(hex_to_i32(self.shdl), hex_to_i32(self.dev), hex_to_byte(self.lag_id), bit_map)
    def rmvMbr(self, port_list):
        l = [x for x in self.mbrs if x not in port_list]
        self.mbrs = list(set(l))
        bit_map = set_port_map(self.mbrs)
        self.test.mc.mc_set_lag_membership(hex_to_i32(self.shdl), hex_to_i32(self.dev), hex_to_byte(self.lag_id), bit_map)
    def getMbrByHash(self, h, pkt_rid, node_rid, yid):
        global t
        len_pack = self.left_cnt + len(self.mbrs) + self.right_cnt
        if len_pack == 0: # No members at all
            return None
        index_pack = h % len_pack
        vec_pack = sorted(self.mbrs)

        vec_pack_mask = []
        for m in vec_pack:
            if t.get_sw_mask()[portToBitIdx(m)] == 1:
                continue
            if t.get_hw_mask()[portToBitIdx(m)] == 1:
                continue
            vec_pack_mask.append(m)
        len_pack_mask = len(vec_pack_mask)
        if len_pack_mask == 0:
            index_pack_mask = 0
        else:
            index_pack_mask = h % len_pack_mask

        if index_pack < self.right_cnt: # Hashed to remote right member
            return None
        if index_pack >= (len(self.mbrs) + self.right_cnt): # Hashed to remote left member
            return None

        if len_pack_mask == 0: # No live ports
            port = vec_pack[index_pack-self.right_cnt]
        elif vec_pack[index_pack-self.right_cnt] in vec_pack_mask:
            port = vec_pack[index_pack-self.right_cnt]
        else:
            port = vec_pack_mask[index_pack_mask]

        # Apply pruning to the selected port.
        if pkt_rid == node_rid or pkt_rid == t.get_yid_tbl().global_rid():
            if t.get_yid_tbl().is_port_pruned(yid, port):
                return None
        if port in vec_pack_mask:
            # Port is up
            return port
        else:
            # Port is down, use the backup instead.
            return t.backup_ports[ portToBitIdx(port) ]
    def cleanUp(self):
        self.setRmtCnt(0,0)
        self.rmvMbr(self.mbrs)
class LagTable:
    def __init__(self, test, shdl, dev):
        self.shdl = shdl
        self.dev = dev
        self.test = test
        self.lags = []
        for i in range(255):
            lag = LagGrp(self.test, self.shdl, self.dev, i)
            self.lags.append(lag)
    def getLag(self, lag_id):
        assert lag_id >= 0 and lag_id <= 255
        return self.lags[lag_id]
    def cleanUp(self):
        for lag in self.lags:
            lag.cleanUp()

class EcmpGrp:
    def __init__(self, test, shdl, dev):
        self.shdl = shdl
        self.dev = dev
        self.test = test
        self.mbrs = [None for _ in range(32)]
        self.mgrp_hdls = []
        self.hdl = test.mc.mc_ecmp_create(hex_to_i32(self.shdl), self.dev)
        assert(self.hdl != 0)
    def addMbr(self, rid, port_list, lag_list):
        n = MCNode(self.test, self.shdl, rid, self.dev)
        n.addMbrs(self.test, port_list, lag_list)
        self.test.mc.mc_ecmp_mbr_add(hex_to_i32(self.shdl), hex_to_i32(self.dev), hex_to_i32(self.hdl), hex_to_i32(n.node_hdl))
        self.mbrs[ self.mbrs.index(None) ] = n
    def rmvMbr(self, index):
        n = self.mbrs[index]
        self.test.mc.mc_ecmp_mbr_rem(hex_to_i32(self.shdl), hex_to_i32(self.dev), hex_to_i32(self.hdl), hex_to_i32(n.node_hdl))
        self.mbrs[index] = None
        n.cleanUp(self.test)
    def associate(self, mgrp_hdl, xid):
        if xid is None:
            xid = 0
            use_xid = 0
        else:
            use_xid = 1
        self.test.mc.mc_associate_ecmp(hex_to_i32(self.shdl),
                                             hex_to_i32(self.dev),
                                             hex_to_i32(mgrp_hdl),
                                             hex_to_i32(self.hdl),
                                             hex_to_i16(xid), use_xid)
        self.mgrp_hdls.append(mgrp_hdl)
    def dissociate(self, mgrp_hdl):
        self.mgrp_hdls.remove(mgrp_hdl)
        self.test.mc.mc_dissociate_ecmp(hex_to_i32(self.shdl),
                                              hex_to_i32(self.dev),
                                              hex_to_i32(mgrp_hdl),
                                              hex_to_i32(self.hdl))
    def getMbrByHash(self, val):
        #print "Group", hex(self.hdl), "getting member for hash", val
        #print "  MBRS", self.mbrs
        live_cnt = 32 - self.mbrs.count(None)
        #print "  Live:", live_cnt
        idx1 = val % 32
        #print "  Select1:", idx1
        idx2 = idx1
        if live_cnt != 0:
            idx2 = val % live_cnt
        #print "  Select2:", idx2
        if self.mbrs[idx1] is not None:
            #print "  Taking member at", idx1
            return self.mbrs[idx1]
        idx = 0
        for node in self.mbrs:
            if node is not None and idx == idx2:
                #print "  Taking member at", idx2
                return node
            if node is not None:
                idx = idx + 1
        #print "  NO MEMBERS!"
        return None
    def getRid(self, h):
        node = self.getMbrByHash(h)
        if node is not None:
            return node.get_rid()
        return 0xDEAD
    def cleanUp(self):
        # Remove members
        for i in range(len(self.mbrs)):
            if self.mbrs[i] is not None:
                self.rmvMbr(i)
        # Dissociate mgids
        for mgrp_hdl in  self.mgrp_hdls:
            self.test.mc.mc_dissociate_ecmp(hex_to_i32(self.shdl),
                                            hex_to_i32(self.dev),
                                            hex_to_i32(mgrp_hdl),
                                            hex_to_i32(self.hdl))
        self.mgrp_hdls = []
        # Clean up ECMP group
        self.test.mc.mc_ecmp_destroy(hex_to_i32(self.shdl), hex_to_i32(self.dev), hex_to_i32(self.hdl))
        self.hdl = 0


class YidTable:
    def __init__(self, test, shdl, dev, global_rid):
        self.shdl = shdl
        self.dev = dev
        self.prune_list = []
        self.test = test
        for x in range(288):
            self.prune_list.append([])
        self.set_global_rid(global_rid)
    def set_global_rid(self, grid):
        self.grid = grid
        self.test.mc.mc_set_global_rid(hex_to_i32(self.shdl), self.dev, hex_to_i16(grid))
    def global_rid(self):
        return self.grid
    def set_pruned_ports(self, yid, new_prune_list):
        self.prune_list[yid] = list(new_prune_list)
        prune_map = set_port_map(self.prune_list[yid])
        self.test.mc.mc_update_port_prune_table(hex_to_i32(self.shdl), self.dev, yid, prune_map)
    def get_pruned_ports(self, yid):
        return list(self.prune_list[yid])
    def prune_ports(self, yid, port_list):
        l = list(port_list)
        for p in l:
            if p in self.prune_list[yid]:
                port_list.remove(p)
    def is_port_pruned(self, yid, port):
        if port in self.prune_list[yid]:
            return True
        return False
    def cleanUp(self):
        for yid in range(288):
            self.set_pruned_ports(yid, [])
        self.set_global_rid(0)

class MCTree:
    def __init__(self, test, shdl, dev, mgid):
        self.shdl = shdl
        self.dev  = dev
        self.mgid = mgid
        self.test = test
        self.mgid_hdl = self.test.mc.mc_mgrp_create(hex_to_i32(self.shdl), self.dev, hex_to_i16(mgid))
        self.nodes = []
        self.ecmps = []
    def get_mgid(self):
        return self.mgid
    def add_node(self, rid, xid, mbr_ports, mbr_lags):
        n = MCNode(self.test, self.shdl, rid, self.dev, mbr_ports, mbr_lags)
        n.associate(self.test, self.mgid_hdl, xid)
        self.nodes.append(n)
    def rmv_node(self, rid, xid):
        """
        Find the first node with the given rid/xid and remove it from the tree.
        """
        for node in self.nodes:
            if node.rid == rid and node.xid == xid:
                node.cleanUp(self.test)
                self.nodes.remove(node)
                break
    def update_node(self, rid, xid, mbr_ports, mbr_lags):
        """
        Find the first node with the given rid/xid and replace it's members
        with the ports and lags provided.
        """
        for node in self.nodes:
            if node.rid == rid and node.xid == xid:
                node.replaceMbrs(self.test, mbr_ports, mbr_lags)
                break
    def add_ecmp(self, grp, xid):
        grp.associate(self.mgid_hdl, xid)
        grp_tup = (grp, xid)
        self.ecmps.append(grp_tup)
    def reprogram(self):
        for n in self.nodes:
            n.dissociate(self.test)
        for grp, xid in self.ecmps:
            grp.dissociate(self.mgid_hdl)
        for n in self.nodes:
            n.associate(self.test, self.mgid_hdl, n.xid)
        for grp, xid in self.ecmps:
            grp.associate(self.mgid_hdl, xid)
    def cleanUp(self):
        for n in self.nodes:
            n.cleanUp(self.test)
        self.test.mc.mc_mgrp_destroy(hex_to_i32(self.shdl), hex_to_i32(self.dev), hex_to_i32(self.mgid_hdl))
        for grp, _ in self.ecmps:
            grp.dissociate(self.mgid_hdl)
        self.nodes = []
        self.ecmps = []
    def get_node_ids(self):
        ret = [(n.rid,n.xid) for n in self.nodes]
        return ret
    def get_ports(self, pkt_rid, pkt_xid, pkt_yid, pkt_hash1=0, pkt_hash2=0):
        port_data = []
        ecmp_data = []
        for n in self.nodes:
            if n.xid is not None and pkt_xid == n.xid:
                continue
            ports = n.getPorts(pkt_rid, pkt_yid, pkt_hash2)
            port_data.append( (n.rid, ports) )

        for grp, xid in self.ecmps:
            if xid is not None and pkt_xid == xid:
                continue
            n = grp.getMbrByHash(pkt_hash1)
            if n is not None:
                ports = n.getPorts(pkt_rid, pkt_yid, pkt_hash2)
                ecmp_data.append( (n.rid, ports) )
        return port_data + ecmp_data
    def print_tree(self):
        print "Dev:", self.dev, "MGID:", hex(self.mgid), "Num L1 Nodes:", len(self.nodes), "Num ECMPs:", len(self.ecmps)
        for n in self.nodes:
            if n.xid is not None:
                print "  Hdl:", hex(n.node_hdl), "RID:", hex(n.rid), "XID:", hex(n.xid), "Ports:", n.mbr_ports, "LAGs:", n.mbr_lags
            else:
                print "  Hdl:", hex(n.node_hdl), "RID:", hex(n.rid), "Ports:", n.mbr_ports, "LAGs:", n.mbr_lags
        for grp, xid in self.ecmps:
            if xid is not None:
                print "  ECMP Hdl:", hex(grp), "XID:", hex(xid)
            else:
                print "  ECMP Hdl:", hex(grp)


