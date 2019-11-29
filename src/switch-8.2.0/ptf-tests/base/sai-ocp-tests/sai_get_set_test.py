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
Thrift SAI get/set tests
"""

import switchsai_thrift

import time
import sys
import logging

import unittest
import random
import os

this_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(this_dir, os.pardir))

sys.path.append(os.path.join(this_dir, '..'))
sys.path.append(os.path.join(parent_dir, 'base'))
sys.path.append(os.path.join(parent_dir, 'base/sai-tests'))

import sai_base_test
import pd_base_tests

try:
    import pltfm_pm_rpc
    from pltfm_pm_rpc.ttypes import *
except ImportError:
    pass


from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *

import ptf.mask

from switchsai_thrift.ttypes import *
from switchsai_thrift.sai_headers import *
from switch_utils import *
from erspan3 import *

this_dir = os.path.dirname(os.path.abspath(__file__))

@group('l2')
@group('l2-ocp')
class PortDropUntaggedPacketAttribute(sai_base_test.ThriftInterfaceDataPlane):
    def checkPortAttribute(self, port, dropUntagged):
        thrift_attr_list = self.client.sai_thrift_get_port_attribute(port)
        port_attr_list = thrift_attr_list.attr_list
        for attr in port_attr_list:
          if attr.id == SAI_PORT_ATTR_DROP_UNTAGGED: 
             if attr.value.booldata == dropUntagged:
               return 1
             else:
               print "Get/Set attribute: SAI_PORT_ATTR_DROP_UNTAGGED doesn't match, got %d, expeceted %d"                                       %(attr.value.booldata, dropUntagged)
               return 0
        print "attribute SAI_PORT_ATTR_DROP_UNTAGGED not found in port_attr_list" 
        return 0
         
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[0]

        try: 
          sai_thrift_set_port_attribute(self.client, port1,
                                      SAI_PORT_ATTR_DROP_UNTAGGED,
                                      True)
          ret = PortDropUntaggedPacketAttribute.checkPortAttribute(self, port1, True)
          if ret == 0:
            print " Set/Get test failed for port attribute: SAI_PORT_ATTR_DROP_UNTAGGED"
            self.fail_flag = True
            self.assertFalse(self.fail_flag, 'port attribute SAI_PORT_ATTR_DROP_UNTAGGE Set/Get test failed')

        finally:
          sai_thrift_set_port_attribute(self.client, port1,
                                      SAI_PORT_ATTR_DROP_UNTAGGED,
                                      False)

@group('l2')
@group('l2-ocp')
class PortDropTaggedPacketAttribute(sai_base_test.ThriftInterfaceDataPlane):
    def checkPortAttribute(self, port, dropTagged):
        thrift_attr_list = self.client.sai_thrift_get_port_attribute(port)
        port_attr_list = thrift_attr_list.attr_list
        for attr in port_attr_list:
          if attr.id == SAI_PORT_ATTR_DROP_TAGGED:
             if attr.value.booldata == dropTagged:
               return 1
             else:
               print "Get/Set attribute: SAI_PORT_ATTR_DROP_TAGGED doesn't match, got %d, expeceted %d"                                       %(attr.value.booldata, dropTagged)
               return 0
        print "attribute SAI_PORT_ATTR_DROP_TAGGED not found in port_attr_list"
        return 0

    def runTest(self):
        switch_init(self.client)
        port1 = port_list[0]

        try:
          sai_thrift_set_port_attribute(self.client, port1,
                                      SAI_PORT_ATTR_DROP_TAGGED,
                                      True)
          ret = PortDropTaggedPacketAttribute.checkPortAttribute(self, port1, True)
          if ret == 0:
            print " Set/Get test failed for port attribute: SAI_PORT_ATTR_DROP_TAGGED"
            self.fail_flag = True
            self.assertFalse(self.fail_flag, 'port attribute SAI_PORT_ATTR_DROP_TAGGED Set/Get test failed')

        finally:
          sai_thrift_set_port_attribute(self.client, port1,
                                      SAI_PORT_ATTR_DROP_TAGGED,
                                      False)

@group('l2')
@group('l2-ocp')
class LagDropUntaggedPacketAttribute(sai_base_test.ThriftInterfaceDataPlane):
    def checkLagAttribute(self, lag_id1, dropUntagged):
        thrift_attr_list = self.client.sai_thrift_get_lag_attribute(lag_id1)
        lag_attr_list = thrift_attr_list.attr_list
        for attr in lag_attr_list:
          if attr.id == SAI_LAG_ATTR_DROP_UNTAGGED:
             if attr.value.booldata == dropUntagged:
               return 1
             else:
               print "Get/Set attribute: SAI_LAG_ATTR_DROP_UNTAGGED doesn't match, got %d, expeceted %d"                                       %(attr.value.booldata, dropUntagged)
               return 0
        print "attribute SAI_LAG_ATTR_DROP_UNTAGGED not found in lag_attr_list"
        return 0

    def runTest(self):
        switch_init(self.client)
        lag_id1 = self.client.sai_thrift_create_lag([]) 

        try:
          sai_thrift_set_lag_attribute(self.client, lag_id1,
                                      SAI_LAG_ATTR_DROP_UNTAGGED,
                                      True)
          ret = LagDropUntaggedPacketAttribute.checkLagAttribute(self, lag_id1, True)
          if ret == 0:
            print " Set/Get test failed for lag attribute: SAI_LAG_ATTR_DROP_UNTAGGED"
            self.fail_flag = True
            self.assertFalse(self.fail_flag, 'Lag attribute SAI_LAG_ATTR_DROP_UNTAGGE Set/Get test failed')
        finally:
          sai_thrift_set_lag_attribute(self.client, lag_id1,
                                      SAI_LAG_ATTR_DROP_UNTAGGED,
                                      False)
          self.client.sai_thrift_remove_lag(lag_id1)
           
@group('l2')
@group('l2-ocp')
class LagDropTaggedPacketAttribute(sai_base_test.ThriftInterfaceDataPlane):
    def checkLagAttribute(self, lag_id1, dropTagged):
        thrift_attr_list = self.client.sai_thrift_get_lag_attribute(lag_id1)
        lag_attr_list = thrift_attr_list.attr_list
        for attr in lag_attr_list:
          if attr.id == SAI_LAG_ATTR_DROP_TAGGED:
             if attr.value.booldata == dropTagged:
               return 1
             else:
               print "Get/Set attribute: SAI_LAG_ATTR_DROP_TAGGED doesn't match, got %d, expeceted %d"                                       %(attr.value.booldata, dropTagged)
               return 0
        print "attribute SAI_LAG_ATTR_DROP_TAGGED not found in lag_attr_list"
        return 0

    def runTest(self):
        switch_init(self.client)
        lag_id1 = self.client.sai_thrift_create_lag([])

        try:
          sai_thrift_set_lag_attribute(self.client, lag_id1,
                                      SAI_LAG_ATTR_DROP_TAGGED,
                                      True)
          ret = LagDropTaggedPacketAttribute.checkLagAttribute(self, lag_id1, True)
          if ret == 0:
            print " Set/Get test failed for lag attribute: SAI_LAG_ATTR_DROP_TAGGED"
            self.fail_flag = True
            self.assertFalse(self.fail_flag, 'lag attribute SAI_LAG_ATTR_DROP_TAGGED Set/Get test failed')

        finally:
          sai_thrift_set_lag_attribute(self.client, lag_id1,
                                      SAI_LAG_ATTR_DROP_TAGGED,
                                      False)
          self.client.sai_thrift_remove_lag(lag_id1)

@group('l2')
@group('l2-ocp')
class LagPortVlanIdAttribute(sai_base_test.ThriftInterfaceDataPlane):
    def checkLagAttribute(self, lag_id1, vlan_id):
        thrift_attr_list = self.client.sai_thrift_get_lag_attribute(lag_id1)
        lag_attr_list = thrift_attr_list.attr_list
        for attr in lag_attr_list:
          if attr.id == SAI_LAG_ATTR_PORT_VLAN_ID:
             if attr.value.u16 == vlan_id:
               return 1
             else:
               print "Get/Set attribute: SAI_LAG_ATTR_PORT_VLAN_ID doesn't match, got %d, expeceted %d"                                       %(attr.value.u16, vlan_id)
               return 0
        print "attribute SAI_LAG_ATTR_PORT_VLAN_ID not found in lag_attr_list"
        return 0

    def runTest(self):
        switch_init(self.client)
        vlan_id = 10;
        lag_id1 = self.client.sai_thrift_create_lag([])

        try:
          sai_thrift_set_lag_attribute(self.client, lag_id1,
                                      SAI_LAG_ATTR_PORT_VLAN_ID,
                                      vlan_id)
          ret = LagPortVlanIdAttribute.checkLagAttribute(self, lag_id1, vlan_id)
          if ret == 0:
            print " Set/Get test failed for lag attribute: SAI_LAG_ATTR_PORT_VLAN_ID"
            self.fail_flag = True
            self.assertFalse(self.fail_flag, 'lag attribute SAI_LAG_ATTR_PORT_VLAN_ID Set/Get test failed')

        finally:
          self.client.sai_thrift_remove_lag(lag_id1)


