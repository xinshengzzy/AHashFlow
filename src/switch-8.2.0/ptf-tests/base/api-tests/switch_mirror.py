################################################################################
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
###############################################################################
"""
Mirror tests
"""

import switchapi_thrift

import os
import time
import sys
import logging

import unittest
import random

import api_base_tests
import pd_base_tests
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from ptf.mask import *

from switchapi_thrift.ttypes import *
from switchapi_thrift.switch_api_headers import *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '..'))
from common.utils import *

device=0
cpu_port=64

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)

if swports == []:
    swports = [x for x in range(65)]

###############################################################################
@group('l3')
@group('l2')
@group('maxsizes')
@group('ent')
class MirrorPortTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "create mirror sessions"
        port1 = self.client.switch_api_port_id_to_handle_get(device, swports[1])
        port3 = self.client.switch_api_port_id_to_handle_get(device, swports[3])
        minfo1 = switcht_mirror_info_t(
            session_id=1,
            direction=1,
            egress_port_handle=port3,
            mirror_type=SWITCH_MIRROR_TYPE_LOCAL,
            session_type=0,
            cos=0,
            max_pkt_len=0,
            ttl=0,
            nhop_handle=0)
        mirror1 = self.client.switch_api_mirror_session_create(0, minfo1)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror1)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror1)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror1)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror1)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror1)
        tmp_mirror = self.client.switch_api_port_ingress_mirror_get(device, port1)
        print hex(mirror1), hex(tmp_mirror)

        minfo2 = switcht_mirror_info_t(
            session_id=101,
            direction=1,
            egress_port_handle=port3,
            mirror_type=SWITCH_MIRROR_TYPE_LOCAL,
            session_type=0,
            cos=0,
            max_pkt_len=0,
            ttl=0,
            nhop_handle=0)
        mirror2 = self.client.switch_api_mirror_session_create(0, minfo2)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror2)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror2)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror2)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror2)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror2)
        tmp_mirror = self.client.switch_api_port_ingress_mirror_get(device, port1)
        print hex(mirror2), hex(tmp_mirror)

        minfo3 = switcht_mirror_info_t(
            session_id=201,
            direction=1,
            egress_port_handle=port3,
            mirror_type=SWITCH_MIRROR_TYPE_LOCAL,
            session_type=0,
            cos=0,
            max_pkt_len=0,
            ttl=0,
            nhop_handle=0)
        mirror3 = self.client.switch_api_mirror_session_create(0, minfo3)
        self.client.switch_api_port_ingress_mirror_set(device, port1, mirror3)
        tmp_mirror = self.client.switch_api_port_ingress_mirror_get(device, port1)
        print hex(mirror3), hex(tmp_mirror)

        print "delete mirror sessions"
        self.client.switch_api_mirror_session_delete(0, mirror1)
        self.client.switch_api_mirror_session_delete(0, mirror2)
        self.client.switch_api_mirror_session_delete(0, mirror3)
        self.client.switch_api_port_ingress_mirror_set(device, port1, 0)
        self.client.switch_api_port_ingress_mirror_set(device, port1, 0)
        self.client.switch_api_port_ingress_mirror_set(device, port1, 0)
        self.client.switch_api_port_ingress_mirror_set(device, port1, 0)
        self.client.switch_api_port_ingress_mirror_set(device, port1, 0)
        tmp_mirror = self.client.switch_api_port_ingress_mirror_get(device, port1)
        print hex(tmp_mirror)
