---
title: SSDP
description: List of unirec fields exported together with basic flow fields on interface by SSDP plugin.
fields:
  -
    name: "SSDP_LOCATION_PORT"
    type: "uint16"
    ipfix: "8057/821"
    value: " 	service port"
  -
    name: "SSDP_NT"
    type: "string"
    ipfix: "8057/824"
    value: " 	list of advertised service urns"
  -
    name: "SSDP_SERVER"
    type: "string"
    ipfix: "8057/822"
    value: " 	server info"
  -
    name: "SSDP_ST"
    type: "string"
    ipfix: "8057/825"
    value: " 	list of queried service urns"
  -
    name: "SSDP_USER_AGENT"
    type: "string"
    ipfix: "8057/823"
    value: " 	list of user agents"
---
