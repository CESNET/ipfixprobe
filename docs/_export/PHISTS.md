---
title: PHISTS
description: List of fields exported together with basic flow fields on the interface by PHISTS plugin. The plugin exports the histograms of Payload sizes and Inter-Packet-Times for each direction. The histograms bins are scaled logarithmicaly and are shown in following table.    
fields: 
  -
    name: "D_PHISTS_IPT"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	DST->SRC: Histogram of interpacket times"
  -
    name: "D_PHISTS_SIZES"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	DST->SRC: Histogram of packet sizes"
  -
    name: "S_PHISTS_IPT"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	SRC->DST: Histogram of interpacket times"
  -
    name: "S_PHISTS_SIZES"
    type: "uint32*"
    ipfix: "0/291"
    value: " 	SRC->DST: Histogram of packet sizes"

---