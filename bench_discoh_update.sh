#!/bin/bash
# 设定c的值

c=10
N=10000
db="discoh.csdb"
#r=`expr $N / $c`
client="./discoh_client"

echo $r

for k in $( seq 1 $c )
do
    $client -b $db -r $N -e $c
done