---
title: Basic
description: Basic unirec fields exported on interface with basic (pseudo) plugin. These fields are also exported on interfaces where HTTP, DNS, SIP and NTP plugins are active.
fields:
  -
    name: "DST_MAC"
    type: "macaddr"
    ipfix: "0/80"
    value: "destination MAC address"
  -
    name: "SRC_MAC"
    type: "macaddr"
    ipfix: "0/56"
    value:   "source MAC address"
  -
    name: "DST_IP"
    type: "ipaddr"
    ipfix: "0/12 or 0/28"
    value:  "destination IP address"
  -
    name: "SRC_IP"
    type: "ipaddr"
    ipfix: "0/8 or 0/27"
    value:  "source IP address"
  -
    name: "BYTES"
    type: "uint64"
    ipfix: "0/1"
    value:  "number of bytes in data flow (src to dst)"
  -
    name: "BYTES_REV"
    type: "uint64"
    ipfix: "29305/1"
    value:  "number of bytes in data flow (dst to src)"
  -
    name: "LINK_BIT_FIELD or ODID"
    type: "uint64 or uint32"
    ipfix: "-"
    value:  "exporter identification"
  -
    name: "TIME_FIRST"
    type: "time"
    ipfix: "0/152"
    value:  "first time stamp"
  -
    name: "TIME_LAST"
    type: "time"
    ipfix: "0/153"
    value:  "last time stamp"
  -
    name: "PACKETS"
    type: "uint32"
    ipfix: "0/2"
    value:  "number of packets in data flow (src to dst)"
  -
    name: "PACKETS_REV"
    type: "uint32"
    ipfix: "29305/2"
    value:  "number of packets in data flow (dst to src)"
  -
    name: "DST_PORT"
    type: "uint16"
    ipfix: "0/11"
    value:  "transport layer destination port"
  -
    name: "SRC_PORT"
    type: "uint16"
    ipfix: "0/7"
    value:  "transport layer source port"
  -
    name: "DIR_BIT_FIELD"
    type: "uint8"
    ipfix: "0/10"
    value:   "bit field for determining outgoing/incoming traffic"
  -
    name: "PROTOCOL"
    type: "uint8"
    ipfix: "0/60"
    value:   "transport protocol"
  -
    name: "TCP_FLAGS"
    type: "uint8"
    ipfix: "0/6"
    value:   "TCP protocol flags (src to dst)"
  -
    name: "TCP_FLAGS_REV"
    type: "uint8"
    ipfix: "29305/6"
    value:   "TCP protocol flags (dst to src)"
---
