#!/bin/bash
# 设定c的值

c=10
N=10000000
db="discog.csdb"
#r=`expr $N / $c`
client="./discog_client"
d=1
e=$[$c-1]

$client -b $db -r $N -e 1
$client -b $db -r 0 -e $e