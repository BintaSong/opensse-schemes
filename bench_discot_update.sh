#!/bin/bash
# 设定c的值

c=10
N=10000
db="discot.csdb"
#r=`expr $N / $c`
client="./discot_client"

$client -b $db -r $N -e $c