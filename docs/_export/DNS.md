---
title: DNS
description: List of unirec fields exported together with basic flow fields on interface by DNS plugin.   
fields: 
  - 
    name: "DNS_ID"
    type:  "uint16"
    ipfix: "8057/10"
    value:  "transaction ID"
  - 
    name: "DNS_ANSWERS"
    type:   "uint16"
    ipfix: "8057/14"
    value:  "number of DNS answer records"
  - 
    name: "DNS_RCODE"
    type:   "uint8"
    ipfix: "8057/1"
    value:   "response code field"
  - 
    name: "DNS_NAME"
    type:  "string"
    ipfix: "8057/2"
    value:  "question domain name"
  - 
    name: "DNS_QTYPE"
    type:   "uint16"
    ipfix: "8057/3"
    value:  "question type field"
  - 
    name: "DNS_CLASS"
    type:   "uint16"
    ipfix: "8057/4"
    value:  "class field of DNS question"
  - 
    name: "DNS_RR_TTL"
    type:  "uint32"
    ipfix: "8057/5"
    value:  "resource record TTL field"
  - 
    name: "DNS_RLENGTH"
    type:   "uint16"
    ipfix: "8057/6"
    value:  "length of DNS_RDATA"
  - 
    ipfix: "8057/7"
    name: "DNS_RDATA"
    type:   "bytes"
    value:   "resource record specific data"
  - 
    name: "DNS_PSIZE"
    type:   "uint16"
    ipfix: "8057/8"
    value:  "requestor's payload size"
  - 
    name: "DNS_DO"
    type:  "uint8"
    ipfix: "8057/9"
    value:   "DNSSEC OK bit"
---