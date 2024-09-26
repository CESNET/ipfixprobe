---
title: NTP
description: List of unirec fields exported together with basic flow fields on interface by NTP plugin.    
fields: 
  -
    name: "NTP_LEAP"
    type: "uint8"
    ipfix: "8057/18"
    value: " 	NTP leap field"
  -
    name: "NTP_VERSION"
    type: "uint8"
    ipfix: "8057/19"
    value: " 	NTP message version"
  -
    name: "NTP_MODE"
    type: "uint8"
    ipfix: "8057/20"
    value: " 	NTP mode field"
  -
    name: "NTP_STRATUM"
    type: "uint8"
    ipfix: "8057/21"
    value: " 	NTP stratum field"
  -
    name: "NTP_POLL"
    type: "uint8"
    ipfix: "8057/22"
    value: " 	NTP poll interval"
  -
    name: "NTP_PRECISION"
    type: "uint8"
    ipfix: "8057/23"
    value: " 	NTP precision field"
  -
    name: "NTP_DELAY"
    type: "uint32"
    ipfix: "8057/24"
    value: " 	NTP root delay"
  -
    name: "NTP_DISPERSION"
    type: "uint32"
    ipfix: "8057/25"
    value: " 	NTP root dispersion"
  -
    name: "NTP_REF_ID"
    type: "string"
    ipfix: "8057/26"
    value: " 	NTP reference ID"
  -
    name: "NTP_REF"
    type: "string"
    ipfix: "8057/27"
    value: " 	NTP reference timestamp"
  -
    name: "NTP_ORIG"
    type: "string"
    ipfix: "8057/28"
    value: " 	NTP origin timestamp"
  -
    name: "NTP_RECV"
    type: "string"
    ipfix: "8057/29"
    value: " 	NTP receive timestamp"
  -
    name: "NTP_SENT"
    type: "string"
    ipfix: "8057/30"
    value: " 	NTP transmit timestamp"
---