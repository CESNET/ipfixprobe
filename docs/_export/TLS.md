---
title: TLS
description: List of unirec fields exported together with basic flow fields on interface by TLS plugin.
fields:
  -
    name: "TLS_SNI"
    type:   "string"
    ipfix: "8057/808"
    value:  "TLS server name indication field from client"
  -
    name: "TLS_ALPN"
    type:  "string"
    ipfix: "39499/337"
    value:  "TLS application protocol layer negotiation field from server"
  -
    name: "TLS_VERSION"
    type:   "uint16"
    ipfix: "39499/333"
    value:  "TLS client protocol version"
  -
    name: "TLS_JA3"
    type:   "string"
    ipfix: "39499/357"
    value:  "TLS client JA3 fingerprint"
  -
    name: "TLS_EXT_TYPE"
    type:  "uint16"
    ipfix: "0/291"
    value:  "TLS extensions in the TLS Client Hello"
  -
    name: "TLS_EXT_LEN"
    type:   "uint16"
    ipfix: "0/291"
    value:   "Length of each TLS extension"
---
