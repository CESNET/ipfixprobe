---
title: PSTATS
description: "List of unirec fields exported on interface by PSTATS plugin. The plugin is compiled to gather statistics for the first PSTATS_MAXELEMCOUNT (30 by default) packets in the biflow record. Note: the following fields are UniRec arrays (or basicList in IPFIX)."
fields:
  -
    name: "PPI_PKT_LENGTHS"
    type: "uint16*"
    ipfix: "0/291"
    value: " 	sizes of the first packets"
  -
    name: "PPI_PKT_TIMES"
    type: "time*"
    ipfix: "0/291"
    value: " 	timestamps of the first packets"
  -
    name: "PPI_PKT_DIRECTIONS"
    type: "int8*"
    ipfix: "0/291"
    value: " 	directions of the first packets"
  -
    name: "PPI_PKT_FLAGS"
    type: "uint8*"
    ipfix: "0/291"
    value: " 	TCP flags for each packet"
---
