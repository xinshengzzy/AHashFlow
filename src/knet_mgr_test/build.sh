#!/bin/bash
cd $BUILD
./autogen.sh
./configure --prefix=$SDE_INSTALL --with-tofino P4_NAME=knet_mgr_test P4_PATH=$SRC/knet_mgr_test/knet_mgr_test.p4 --enable-thrift
make clean
make
make install
