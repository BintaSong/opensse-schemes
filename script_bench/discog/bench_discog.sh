#!/bin/bash
db="discog.csdb"
for k in $( seq 1 10 )
do
    ./discog_client -b $db -q "Group-10^1_1_0" 
done

for k in $( seq 1 10 )
do
    ./discog_client -b $db -q "Group-10^2_1_0"
done

for k in $( seq 1 10 )
do
    ./discog_client -b $db -q "Group-10^3_1_0"
done

for k in $( seq 1 10 )
do
    ./discog_client -b $db -q "Group-10^4_1_0"
done

for k in $( seq 1 10 )
do
    ./discog_client -b $db -q "Group-10^5_1_0"
done

for k in $( seq 1 10 )
do
    ./discog_client -b $db -q "Group-10^6_1_0"
done