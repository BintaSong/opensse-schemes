#!/bin/bash
# 设定c的值

c=10
N=10000
db="discog.csdb"
#r=`expr $N / $c`
client="./discog_client"


$client -b $db -r $N -e $c
