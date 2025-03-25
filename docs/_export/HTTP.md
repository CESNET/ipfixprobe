---
title: HTTP
description: List of unirec fields exported together with basic flow fields on interface by HTTP plugin.
fields:
  -
    name: "HTTP_DOMAIN"
    type:   "string"
    ipfix: "39499/1"
    value: "HTTP request host"
  -
    name: "HTTP_URI"
    type:  "string"
    ipfix: "39499/2"
    value: "HTTP request url"
  -
    name: "HTTP_USERAGENT"
    type:  "string"
    ipfix: "39499/20"
    value: "HTTP request user agent"
  -
    name: "HTTP_REFERER"
    type:  "string"
    ipfix: "39499/3"
    value: "HTTP request referer"
  -
    name: "HTTP_STATUS"
    type:   "uint16"
    ipfix: "39499/12"
    value: "HTTP response code"
  -
    name: "HTTP_CONTENT_TYPE"
    type:  "string"
    ipfix: "39499/10"
    value: "HTTP response content type"
  -
    name: "HTTP_METHOD"
    type:  "string"
    ipfix: "39499/200"
    value: "HTTP request method"
  -
    name: "HTTP_SERVER"
    type:  "string"
    ipfix: "39499/201"
    value: "HTTP response server"
  -
    name: "HTTP_SET_COOKIE_NAMES"
    type:  "string"
    ipfix: "39499/202"
    value: "HTTP response all set-cookie names separated by a delimiter"
---
