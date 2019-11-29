#!/usr/bin/env bash

if [ "5.8.0 (7069cde)" == "V5" ]; then
    PYTHONPATH=/root/bf-sde-8.2.0/install/lib/python2.7/site-packages:$PYTHONPATH /root/bf-sde-8.2.0/install/bin/p4c-tofino --gen-deps $1
else
    # no support for Brig at this point, dependency tracking won't work
    echo $1
fi
