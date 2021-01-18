#!/bin/bash
# 设定c的值

c=10
N=10000000
db="discot.csdb"
#r=`expr $N / $c`
client="./discot_client"
e=$[$c-1]
$client -b $db -r $N -e 1
$client -b $db -r 0 -e $e