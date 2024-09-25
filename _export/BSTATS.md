---
title: BSTATS
description: List of fields exported together with basic flow fields on the interface by BSTATS plugin. The plugin is compiled to export the first BSTATS_MAXELENCOUNT (15 by default) burst in each direction. The bursts are computed separately for each direction. Burst is defined by MINIMAL_PACKETS_IN_BURST (3 by default) and by MAXIMAL_INTERPKT_TIME (1000 ms by default) between packets to be included in a burst. When the flow contains less then MINIMAL_PACKETS_IN_BURST packets, the fields are not exported to reduce output bandwidth.    
fields: 
  -
    name: "SBI_BRST_PACKETS"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	SRC->DST: Number of packets transmitted in ith burst"
  -
    name: "SBI_BRST_BYTES"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	SRC->DST: Number of bytes transmitted in ith burst"
  -
    name: "SBI_BRST_TIME_START"
    type: "time*"
    ipfix: "0/291"
    value: " 	SRC->DST: Start time of the ith burst"
  -
    name: "SBI_BRST_TIME_STOP"
    type: "time*"
    ipfix: "0/291"
    value: " 	SRC->DST: End time of the ith burst"
  -
    name: "DBI_BRST_PACKETS"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	DST->SRC: Number of packets transmitted in ith burst"
  -
    name: "DBI_BRST_BYTES"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	DST->SRC: Number of bytes transmitted in ith burst"
  -
    name: "DBI_BRST_TIME_START"
    type: "time*"
    ipfix: "0/291"
    value: " 	DST->SRC: Start time of the ith burst"
  -
    name: "DBI_BRST_TIME_STOP"
    type: "time*"
    ipfix: "0/291"
    value: " 	DST->SRC: End time of the ith burst"
---