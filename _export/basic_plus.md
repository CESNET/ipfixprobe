---
title: Basic plus
description: List of unirec fields exported together with basic flow fields on interface by basicplus plugin. Fields without _REV suffix are fields from source flow. Fields with _REV are from the opposite direction.    
fields: 
  -
    name: "IP_TTL"
    type:  "uint8"
    ipfix: "0/192"
    value:   "IP TTL field"
  -
    name: "IP_TTL_REV"
    type:  "uint8"
    ipfix: "29305/192"
    value:   "IP TTL field"
  -
    name: "IP_FLG"
    type:  "uint8"
    ipfix: "0/197"
    value:   "IP FLAGS"
  -
    name: "IP_FLG_REV"
    type:  "uint8"
    ipfix: "29305/197"
    value:   "IP FLAGS"
  -
    name: "TCP_WIN"
    type:   "uint16"
    ipfix: "0/186"
    value:  "TCP window size"
  -
    name: "TCP_WIN_REV"
    type:   "uint16"
    ipfix: "29305/186"
    value:  "TCP window size"
  -
    name: "TCP_OPT"
    type:   "uint64"
    ipfix: "0/209"
    value:  "TCP options bitfield"
  -
    name: "TCP_OPT_REV"
    type:   "uint64"
    ipfix: "29305/209"
    value:  "TCP options bitfield"
  -
    name: "TCP_MSS"
    type:   "uint32"
    ipfix: "8057/900"
    value:  "TCP maximum segment size"
  -
    name: "TCP_MSS_REV"
    type:   "uint32"
    ipfix: "8057/901"
    value:  "TCP maximum segment size"
  -
    name: "TCP_SYN_SIZE"
    type:  "uint16"
    ipfix: "8057/902"
    value:  "TCP SYN packet size"
---