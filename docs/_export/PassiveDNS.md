---
title: PassiveDNS
description: List of unirec fields exported together with basic flow fields on interface by PassiveDNS plugin.
fields:
  -
    name: "DNS_ID"
    type: "uint16"
    ipfix: "8057/10"
    value: "  transaction ID"
  -
    name: "DNS_ATYPE"
    type: "uint8"
    ipfix: "8057/11"
    value: "  response record type"
  -
    name: "DNS_NAME"
    type: "string"
    ipfix: "8057/2"
    value: "  question domain name"
  -
    name: "DNS_RR_TTL"
    type: "uint32"
    ipfix: "8057/5"
    value: "  resource record TTL field"

---
