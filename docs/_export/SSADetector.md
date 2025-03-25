---
title: SSADetector
description: List of fields exported together with basic flow fields on interface by ssadetector plugin. The detector search for the SYN SYN-ACK ACK pattern in packet lengths. Multiple occurrences of this pattern suggest a tunneled connection.
fields:
  -
    name: "SSA_CONF_LEVEL"
    type: "uint8"
    ipfix: "8057/903"
    value: " 	1 if SSA sequence detected, 0 otherwise"
---
