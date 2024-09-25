---
title: MQTT
description: List of unirec fields exported together with basic flow fields on interface by MQTT plugin.    
fields: 	
  -
    name: "MQTT_TYPE_CUMULATIVE"
    type: "uint16"
    ipfix: "8057/1033"
    value: "  types of packets and session present flag cumulative"
  -
    name: "MQTT_VERSION"
    type: "uint8"
    ipfix: "8057/1034"
    value: "  MQTT version"
  -
    name: "MQTT_CONNECTION_FLAGS"
    type: "uint8"
    ipfix: "8057/1035"
    value: "  last CONNECT packet flags"
  -
    name: "MQTT_KEEP_ALIVE"
    type: "uint16"
    ipfix: "8057/1036"
    value: "  last CONNECT keep alive"
  -
    name: "MQTT_CONNECTION_RETURN_CODE"
    type: "uint8"
    ipfix: "8057/1037"
    value: "  last CONNECT return code"
  -
    name: "MQTT_PUBLISH_FLAGS"
    type: "uint8"
    ipfix: "8057/1038"
    value: "  cumulative of PUBLISH packet flags"
  -
    name: "MQTT_TOPICS"
    type: "string"
    ipfix: "8057/1039"
    value: "  topics from PUBLISH packets headers"
---