#!/bin/bash

FILE=$1 # input file
cd /output # workdir


ipfixprobe -i "pcap;file=$FILE" -p "pstats" -p "nettisa" -o "unirec;i=f:$FILE.trapcap:timeout=WAIT;p=(pstats,nettisa)"
/usr/bin/nemea/logger -t -i "f:$FILE.trapcap"  -w "$FILE.csv"
rm $FILE.trapcap
