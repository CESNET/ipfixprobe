---
title: SMTP
description: List of unirec fields exported on interface by SMTP plugin.
fields:
  -
    name: "SMTP_2XX_STAT_CODE_COUNT"
    type: "uint32"
    ipfix: "8057/816"
    value: " 	number of 2XX status codes"
  -
    name: "SMTP_3XX_STAT_CODE_COUNT"
    type: "uint32"
    ipfix: "8057/817"
    value: " 	number of 3XX status codes"
  -
    name: "SMTP_4XX_STAT_CODE_COUNT"
    type: "uint32"
    ipfix: "8057/818"
    value: " 	number of 4XX status codes"
  -
    name: "SMTP_5XX_STAT_CODE_COUNT"
    type: "uint32"
    ipfix: "8057/819"
    value: " 	number of 5XX status codes"
  -
    name: "SMTP_COMMAND_FLAGS"
    type: "uint32"
    ipfix: "8057/810"
    value: " 	bit array of commands present"
  -
    name: "SMTP_MAIL_CMD_COUNT"
    type: "uint32"
    ipfix: "8057/811"
    value: " 	number of MAIL commands"
  -
    name: "SMTP_RCPT_CMD_COUNT"
    type: "uint32"
    ipfix: "8057/812"
    value: " 	number of RCPT commands"
  -
    name: "SMTP_STAT_CODE_FLAGS"
    type: "uint32"
    ipfix: "8057/815"
    value: " 	bit array of status codes present"
  -
    name: "SMTP_DOMAIN"
    type: "string"
    ipfix: "8057/820"
    value: " 	domain name of the SMTP client"
  -
    name: "SMTP_FIRST_SENDER"
    type: "string"
    ipfix: "8057/813"
    value: " 	first sender in MAIL command"
  -
    name: "SMTP_FIRST_RECIPIENT"
    type: "string"
    ipfix: "8057/814"
    value: " 	first recipient in RCPT command"
---
