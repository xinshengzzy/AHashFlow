import time
import sys
import logging
import unittest
import random
import pd_base_tests
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
import os
from emulation.p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from mc_pd_rpc.ttypes import *
from mirror_pd_rpc.ttypes import *
this_dir = os.path.dirname(os.path.abspath(__file__))

#import switchapi_thrift
#from switchapi_thrift.ttypes import *

g_start_mcidx = 2000
g_flood_mcidx = 5000
g_num_pipes = 1
g_chan_per_port = 1
g_first_port = 0
g_last_port = 0

if test_param_get("arch") is None:
    raise "Missing test parameter 'arch'"

if test_param_get("arch").lower() == "tofino":
    g_first_port = 0
    g_last_port = 64

if test_param_get("arch").lower() == "tofino":
    port_mode = "25g"
    if test_param_get("port_mode") is not None:
        port_mode = test_param_get("port_mode").lower()
    if port_mode == "100g":
        g_chan_per_port = 4
    elif port_mode == "50g":
        g_chan_per_port = 2
    elif port_mode == "25g":
        g_chan_per_port = 1
    else:
        g_chan_per_port = 1

print "Port Mode:", port_mode
print "First port:", g_first_port
print "Last port:", g_last_port
print "Chan per port:", g_chan_per_port

def pipe_port_to_asic_port(pipe, port):
    return (pipe << 7) | port
def port_to_pipe(port):
    return port >> 7
def port_to_pipe_local_id(port):
    return port & 0x7F
def port_to_bit_idx(port):
    pipe = port_to_pipe(port)
    index = port_to_pipe_local_id(port)
    return 72 * pipe + index
def set_port_or_lag_bitmap(bit_map_size, indicies):
    bit_map = [0] * ((bit_map_size+7)/8)
    for i in indicies:
        index = port_to_bit_idx(i)
        bit_map[index/8] = (bit_map[index/8] | (1 << (index%8))) & 0xFF
    return bytes_to_string(bit_map)

def init_pre(mc, sess_hdl):
    dev_id = 0
    lag_map = set_port_or_lag_bitmap(256, [])
    for pipe in range(0, g_num_pipes):
        for port in range(0, 72):
            asic_port = pipe_port_to_asic_port(pipe, port)
            mcidx = g_start_mcidx + asic_port
            mc_grp_hdl = mc.mc_mgrp_create(sess_hdl, dev_id, mcidx)
            port_map = set_port_or_lag_bitmap(288, [asic_port])
            mc_node_hdl = mc.mc_node_create(sess_hdl, dev_id, 0, port_map,
                                            lag_map)
            mc.mc_associate_node(sess_hdl, dev_id, mc_grp_hdl, mc_node_hdl, 0, 0)

    # program flood mcidx
    flood_ports = []
    for pipe in range(0, g_num_pipes):
        first_port = (pipe << 7) + g_first_port
        last_port = (pipe << 7) + g_last_port
        flood_ports += range(first_port, last_port, g_chan_per_port)

    print "Flood MGID sends to:", flood_ports
    mc_grp_hdl = mc.mc_mgrp_create(sess_hdl, dev_id, g_flood_mcidx)
    port_map = set_port_or_lag_bitmap(288, flood_ports)
    mc_node_hdl = mc.mc_node_create(sess_hdl, dev_id, 0, port_map, lag_map)
    mc.mc_associate_node(sess_hdl, dev_id, mc_grp_hdl, mc_node_hdl, 0, 0)


def init_mac_table(client, sess_hdl):
    dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
    action_spec = emulation_dmac_miss_action_spec_t(
        action_flood_mc_index=g_flood_mcidx)
    client.dmac_set_default_action_dmac_miss(sess_hdl, dev_tgt, action_spec)

def init_recirc_table(client, sess_hdl):
    dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
    match_spec = emulation_recirc_tbl_match_spec_t(hex_to_i16(0x44))
    client.recirc_tbl_table_add_with_noop(sess_hdl, dev_tgt, match_spec)
    client.recirc_tbl_set_default_action_do_recirc(sess_hdl, dev_tgt)

def init_mirror_sessions(test, sess_hdl):
    dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
    base_port = g_first_port
    for sid in range(1,65):
        if sid & 1:
            mir_dir = Direction_e.PD_DIR_INGRESS
            mir_dir_str = "I"
        else:
            mir_dir = Direction_e.PD_DIR_EGRESS
            mir_dir_str = "E"
        egr_port = base_port + ((sid-1) / g_chan_per_port) * g_chan_per_port
        egr_port_v = True
        mir_ses = MirrorSessionInfo_t(MirrorType_e.PD_MIRROR_TYPE_NORM,
                                      mir_dir,
                                      sid,
                                      egr_port,
                                      egr_port_v,
                                      0, #egr_port_queue,
                                      0, #packet_color,
                                      0, #mcast_grp_a,
                                      0, #mcast_grp_a_v,
                                      0, #mcast_grp_b,
                                      0, #mcast_grp_b_v,
                                      0, #max_pkt_len,
                                      0, #level1_mcast_hash,
                                      0, #level2_mcast_hash,
                                      0, #cos,
                                      0, #c2c,
                                      0, #extract_len,
                                      0, #timeout,
                                      [], #int_hdr,
                                      0) #len(int_hdr))
        test.mirror.mirror_session_create(sess_hdl, dev_tgt, mir_ses)
        print "Mirror Session", sid, "Direction", mir_dir_str, "Port", egr_port

"""
 *
 * VLAN Range   Even/Odd    Mirroring   Egress_Bypass
 * ==========   ========    =========   =============
 * 0..511       Odd         Egress      No
 * 0..511       Even        Ingress     Yes
 * 512..1023    Dont-Care   None        No
 * 1023..4095   Dont-Care   None        Yes
 *
 *  Mirroring as per the following
 *  VLAN & 0x3f  mirror_id   DestPort(25G)  DestPort(50G)  DestPort(100G)
 *  =========    =========   =============  =============  ==============
 *  0            1  (IG)     0              0              0
 *  1            2  (EG)     1              0              0
 *  2            3  (IG)     2              2              0
 *  3            4  (EG)     3              2              0
 *  4            5  (IG)     4              4              4
 *  5            6  (EG)     5              4              4
 *  6            7  (IG)     6              6              4
 *  7            8  (EG)     7              6              4
 *  8            9  (IG)     8              8              8
 *  9            10 (EG)     9              8              8
 *  10           11 (IG)     10             10             8
 *  11           12 (EG)     11             10             8
 *  12           13 (IG)     12             12             12
 *  13           14 (EG)     13             12             12
 *  14           15 (IG)     14             14             12
 *  15           16 (EG)     15             14             12
 *  16           17 (IG)     16             16             16
 *  17           18 (EG)     17             16             16
 *  18           19 (IG)     18             18             16
 *  19           20 (EG)     19             18             16
 *  20           21 (IG)     20             20             20
 *  21           22 (EG)     21             20             20
 *  22           23 (IG)     22             22             20
 *  23           24 (EG)     23             22             20
 *  24           25 (IG)     24             24             24
 *  25           26 (EG)     25             24             24
 *  26           27 (IG)     26             26             24
 *  27           28 (EG)     27             26             24
 *  28           29 (IG)     28             28             28
 *  29           30 (EG)     29             28             28
 *  30           31 (IG)     30             30             28
 *  31           32 (EG)     31             30             28
 *  32           33 (IG)     32             32             32
 *  33           34 (EG)     33             32             32
 *  34           35 (IG)     34             34             32
 *  35           36 (EG)     35             34             32
 *  36           37 (IG)     36             36             36
 *  37           38 (EG)     37             36             36
 *  38           39 (IG)     38             38             36
 *  39           40 (EG)     39             38             36
 *  40           41 (IG)     40             40             40
 *  41           42 (EG)     41             40             40
 *  42           43 (IG)     42             42             40
 *  43           44 (EG)     43             42             40
 *  44           45 (IG)     44             44             44
 *  45           46 (EG)     45             44             44
 *  46           47 (IG)     46             46             44
 *  47           48 (EG)     47             46             44
 *  48           49 (IG)     48             48             48
 *  49           50 (EG)     49             48             48
 *  50           51 (IG)     50             50             48
 *  51           52 (EG)     51             50             48
 *  52           53 (IG)     52             52             52
 *  53           54 (EG)     53             52             52
 *  54           55 (IG)     54             54             52
 *  55           56 (EG)     55             54             52
 *  56           57 (IG)     56             56             56
 *  57           58 (EG)     57             56             56
 *  58           59 (IG)     58             58             56
 *  59           60 (EG)     59             58             56
 *  60           61 (IG)     60             60             60
 *  61           62 (EG)     61             60             60
 *  62           63 (IG)     62             62             60
 *  63           64 (EG)     63             62             60
 *
 * if vlan.pcp == 1 the packet is resubmitted to parser once
 * if vlan.pcp == 2 the packet is marked for deflect-on-drop
 * if vlan.pcp == 3 the packet is recirculated through port 68 once
 *
"""

def init_qos_table(client, sess_hdl):
    dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
    for vlanid in range(0, 4096):
        match_spec = emulation_ingress_qos_match_spec_t(
            vlan_tag__valid=1, vlan_tag__vid=vlanid)
        if ((vlanid < 0x200)):
            # vlan < 512 ; do not bypass egress
            if ((vlanid & 0x1)):
                # odd vlan e2e
                action_spec = emulation_qos_hit_e2e_mirror_action_spec_t(
                                                  action_mirror_id=((vlanid & 0x3f) + 1))
                client.egress_qos_table_add_with_qos_hit_e2e_mirror(sess_hdl, dev_tgt,
                                                                    match_spec, action_spec)


            else:
                # even vlan i2e
                client.ingress_qos_set_default_action_qos_miss(sess_hdl, dev_tgt)
                action_spec = emulation_qos_hit_eg_bypass_i2e_mirror_action_spec_t(
                                action_qid=(vlanid & 0x1F), action_mirror_id=((vlanid & 0x3f) + 1))
                client.ingress_qos_table_add_with_qos_hit_eg_bypass_i2e_mirror(sess_hdl, dev_tgt,
                                                                              match_spec, action_spec)

        elif ((vlanid < 0x400)):
            # > 512 and less than 1024, no mirroring, no warp
            action_spec = emulation_qos_hit_no_eg_bypass_no_mirror_action_spec_t(
                                action_qid=(vlanid & 0x1F), action_color=((vlanid & 0xc0) >> 6))
            client.ingress_qos_set_default_action_qos_miss(sess_hdl, dev_tgt)
            client.ingress_qos_table_add_with_qos_hit_no_eg_bypass_no_mirror(sess_hdl, dev_tgt,
                                                                          match_spec, action_spec)
        else:
            # no mirroring, warp
            action_spec = emulation_qos_hit_eg_bypass_no_mirror_action_spec_t(
                                action_qid=(vlanid & 0x1F), action_color=((vlanid & 0xc0) >> 6))
            client.ingress_qos_set_default_action_qos_miss(sess_hdl, dev_tgt)
            client.ingress_qos_table_add_with_qos_hit_eg_bypass_no_mirror(sess_hdl, dev_tgt,
                                                                          match_spec, action_spec)


def add_unicast_mac(client, sess_hdl, mac, port):
    print 'Unicast MAC: MAC = ', mac, ' port = ', port
    dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
    match_spec = emulation_dmac_match_spec_t(
        ethernet_dstAddr=macAddr_to_string(mac))
    action_spec = emulation_dmac_unicast_hit_action_spec_t(
        action_egress_port=port)
    client.dmac_table_add_with_dmac_unicast_hit(sess_hdl, dev_tgt,
                                                match_spec, action_spec)


def add_multicast_mac(client, sess_hdl, mac, mcidx):
    dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
    mcidx = g_start_mcidx + mcidx
    print 'Multicast MAC: MAC = ', mac, ' mcidx = ', mcidx
    match_spec = emulation_dmac_match_spec_t(
        ethernet_dstAddr=macAddr_to_string(mac))
    action_spec = emulation_dmac_multicast_hit_action_spec_t(
        action_mc_index=mcidx)
    client.dmac_table_add_with_dmac_multicast_hit(sess_hdl, dev_tgt,
                                                  match_spec, action_spec)

def add_multicast_mac_uc_mc(client, sess_hdl, mac, port, mcidx):
    dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
    mcidx = g_start_mcidx + mcidx
    print 'Multicast MAC: MAC = ', mac, ' mcidx = ', mcidx
    match_spec = emulation_dmac_match_spec_t(
        ethernet_dstAddr=macAddr_to_string(mac))
    action_spec = emulation_dmac_uc_mc_hit_action_spec_t(
        action_egress_port=port, action_mc_index=mcidx)
    client.dmac_table_add_with_dmac_uc_mc_hit(sess_hdl, dev_tgt,
                                                  match_spec, action_spec)


class Config(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, ["emulation"])

    def setUp(self):
        pd_base_tests.ThriftInterfaceDataPlane.setUp(self)
        print
        print 'Configuring the devices'
        if test_param_get("port_mode") == "100G":
            g_chan_per_port = 1
        elif test_param_get("port_mode") == "50G":
            g_chan_per_port = 2
        elif test_param_get("port_mode") == "25G":
            g_chan_per_port = 4
        else:
            g_chan_per_port = 1
        sess_hdl = self.conn_mgr.client_init()
        mc_sess_hdl = self.mc.mc_create_session()
        init_pre(self.mc, mc_sess_hdl)
        init_mac_table(self.client, sess_hdl)
        init_qos_table(self.client, sess_hdl)
        init_recirc_table(self.client, sess_hdl)
        init_mirror_sessions(self, sess_hdl)
        for pipe in range(0,g_num_pipes):
            for port in range(0,72):
                asic_port = pipe_port_to_asic_port(pipe, port)
                mac_addr = '00:00:00:00:' + hex(pipe)[2:].zfill(2)
                mac_addr = mac_addr + ':' + hex(port)[2:].zfill(2)
                add_unicast_mac(self.client, sess_hdl, mac=mac_addr,
                                port=asic_port)
                mac_addr = '01:00:5e:00:' + hex(pipe)[2:].zfill(2)
                mac_addr = mac_addr + ':' + hex(port)[2:].zfill(2)
                add_multicast_mac(self.client, sess_hdl, mac=mac_addr,
                                  mcidx=asic_port)
                """
                add_multicast_mac_uc_mc(self.client, sess_hdl, mac=mac_addr,
                                        port=asic_port+1, mcidx=asic_port)
                """
        self.mc.mc_complete_operations(mc_sess_hdl)
        self.conn_mgr.complete_operations(sess_hdl)

    def runTest(self):
        print
        print 'Running test'
        for pipe in range(0,g_num_pipes):
            for port in range(0,8,4):
                exp_asic_port = pipe_port_to_asic_port(pipe, port)

                # unicast packet
                mac_addr = '00:00:00:00:' + hex(pipe)[2:].zfill(2)
                mac_addr = mac_addr + ':' + hex(port)[2:].zfill(2)
                pkt = simple_tcp_packet(eth_dst=mac_addr,
                                        eth_src='00:00:00:00:01:01',
                                        dl_vlan_enable=True,
                                        vlan_vid=512,
#                                        vlan_pcp=7,
                                        vlan_pcp=3,
                                        ip_dst='10.10.3.3',
                                        ip_src='10.10.1.1',
                                        ip_id=105,
                                        ip_ttl=4)
                exp_pkt = simple_tcp_packet(eth_dst=mac_addr,
                                            eth_src='00:00:00:00:01:01',
                                            ip_dst='10.10.3.3',
                                            ip_src='10.10.1.1',
                                            ip_id=105,
                                            dl_vlan_enable=True,
                                            vlan_vid=512,
                                            vlan_pcp=7,
                                            ip_ttl=4)
                k = 2
                for i in range(k):
                    send_packet(self, 0, str(pkt))
#                verify_packets(self, exp_pkt, [exp_asic_port])
                return

                # multicast packet
                mac_addr = '01:00:5e:00:' + hex(pipe)[2:].zfill(2)
                mac_addr = mac_addr + ':' + hex(port)[2:].zfill(2)
                pkt = simple_tcp_packet(eth_dst=mac_addr,
                                        eth_src='00:00:00:00:01:01',
                                        dl_vlan_enable=True,
                                        vlan_vid=512,
                                        vlan_pcp=7,
                                        ip_dst='10.10.3.3',
                                        ip_src='10.10.1.1',
                                        ip_id=105,
                                        ip_ttl=4)
                exp_pkt = simple_tcp_packet(eth_dst=mac_addr,
                                            eth_src='00:00:00:00:01:01',
                                            ip_dst='10.10.3.3',
                                            dl_vlan_enable=True,
                                            vlan_vid=512,
                                            vlan_pcp=7,
                                            ip_src='10.10.1.1',
                                            ip_id=105,
                                            ip_ttl=4)
                send_packet(self, 0, str(pkt))
                verify_packets(self, exp_pkt, [exp_asic_port])

