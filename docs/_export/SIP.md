---
title: SIP
description: List of unirec fields exported together with basic flow fields on interface by SIP plugin.
fields:
  -
    name: "SIP_MSG_TYPE"
    type: "uint16"
    ipfix: "8057/100"
    value: " 	SIP message code"
  -
    name: "SIP_STATUS_CODE"
    type: "uint16"
    ipfix: "8057/101"
    value: " 	status of the SIP request"
  -
    name: "SIP_CSEQ"
    type: "string"
    ipfix: "8057/108"
    value: " 	CSeq field of SIP packet"
  -
    name: "SIP_CALLING_PARTY"
    type: "string"
    ipfix: "8057/103"
    value: " 	calling party (from) URI"
  -
    name: "SIP_CALLED_PARTY"
    type: "string"
    ipfix: "8057/104"
    value: " 	called party (to) URI"
  -
    name: "SIP_CALL_ID"
    type: "string"
    ipfix: "8057/102"
    value: " 	call ID"
  -
    name: "SIP_USER_AGENT"
    type: "string"
    ipfix: "8057/106"
    value: " 	user agent field of SIP packet"
  -
    name: "SIP_REQUEST_URI"
    type: "string"
    ipfix: "8057/107"
    value: " 	SIP request URI"
  -
    name: "SIP_VIA"
    type: "string"
    ipfix: "8057/105"
    value: " 	via field of SIP packet"
---
