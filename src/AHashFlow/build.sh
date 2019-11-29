#!/bin/bash
cd $BUILD
./autogen.sh
./configure --prefix=$SDE_INSTALL --with-tofino P4_NAME=AHashFlow P4_PATH=$SRC/AHashFlow/AHashFlow.p4 --enable-thrift
make clean
make
make install
#cd ../p4-examples
#source ./genconf.sh
