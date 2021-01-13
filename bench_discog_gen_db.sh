#!/bin/bash
# 设定c的值

c=10
N=10000
db="discog.csdb"
r=`expr $N / $c`

echo $r

for k in $( seq 1 $c )
do
    ./discog_client -b $db -r $r -e
done