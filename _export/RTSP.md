---
title: RTSP
description: List of unirec fields exported together with basic flow fields on interface by RTSP plugin.    
fields: 
  -
    name: "RTSP_REQUEST_METHOD"
    type:   "string"
    ipfix: "16982/600"
    value:  "RTSP request method name"
  -
    name: "RTSP_REQUEST_AGENT"
    type:  "string"
    ipfix: "16982/601"
    value:  "RTSP request user agent"
  -
    name: "RTSP_REQUEST_URI"
    type:  "string"
    ipfix: "16982/602"
    value:  "RTSP request URI"
  -
    name: "RTSP_RESPONSE_STATUS_CODE"
    type:   "uint16"
    ipfix: "16982/603"
    value:  "RTSP response status code"
  -
    name: "RTSP_RESPONSE_SERVER"
    type:  "string"
    ipfix: "16982/605"
    value:  "RTSP response server field"
  -
    name: "RTSP_RESPONSE_CONTENT_TYPE"
    type:  "string"
    ipfix: "16982/604"
    value:  "RTSP response content type"
---