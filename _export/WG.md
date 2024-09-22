---
title: WG
description: List of fields exported together with basic flow fields on interface by WG plugin.    
fields: 
  -
    name: "WG_CONF_LEVEL"
    type: "uint8"
    ipfix: "8057/1100"
    value: " 	level of confidence that the flow record is a WireGuard tunnel"
  -
    name: "WG_SRC_PEER"
    type: "uint32"
    ipfix: "8057/1101"
    value: " 	ephemeral SRC peer identifier"
  -
    name: "WG_DST_PEER"
    type: "uint32"
    ipfix: "8057/1102"
    value: " 	ephemeral DST peer identifier"

---