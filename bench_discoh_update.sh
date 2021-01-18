#!/bin/bash
# 设定c的值

c=10
N=10000000
db="discoh.csdb"
#r=`expr $N / $c`
client="./discoh_client"

e=$[$c-1]
$client -b $db -r $N -e 1
$client -b $db -r 0 -e $e