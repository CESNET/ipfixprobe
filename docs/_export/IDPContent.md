---
title: IDPContent
description: List of fields exported together with basic flow fields on the interface by IDPContent plugin. The plugin is compiled to export IDPCONTENT_SIZE (100 by default) bytes from the first data packet in SRC -> DST direction, and the first data packet in DST -> SRC direction.
fields:
  -
    name: "IDP_CONTENT"
    type: "bytes"
    ipfix: "8057/850"
    value: "  Content of first data packet from SRC -> DST"
  -
    name: "IDP_CONTENT_REV"
    type: "bytes"
    ipfix: "8057/851"
    value: "  Content of first data packet from DST -> SRC"
---
