---
title: Output plugin
description: Output plugin defines how flows are expoted. Use <b>-o</b> to specify output plugin.

options:
-
  title: "Text"
  description: "Provides human readable output to the terminal or file."
  parameters:
    -
      name: "f or file"
      description: "Defines path to savefile to write output in instead of stdout."
    -
      name: "m or mac"
      description: "Boolean flag. Mac addresses are hidden if set."

  runs:
    -
      explanation: "Print expoted flows to the terminal without mac adresses "
      code: "./ipfixprobe -o 'text;mac'-i 'pcap;file=...;' -s 'cache'"
    -
      explanation: "Print expoted flows to the FILE"
      code: "./ipfixprobe -o 'text;f=FILE'-i 'pcap;file=...;' -s 'cache'"
-
  title: "IPFIX"
  description: "Exports data in the IPFIX format"
  parameters:
    -
      name: "h or host"
      description: "Defines ip address of remote collector."
    -
      name: "p or port "
      description: "Defines collector port to send data to."
    -
      name: "m or mtu"
      description: "Defines maximum size of ipfix packet payload sent."
    -
      name: "u or udp"
      description: "Boolean flag. UDP is used if set."
    -
      name: "n or non-blocking-tcp"
      description: "Boolean flag. Non-blocking-tcp socket is used if set."
    -
      name: "I or id"
      description: "Defines exporter id."
    -
      name: "t or template"
      description: "Defines template refresh rate in seconds."
  runs:
    -
      explanation: "Send exported data to the localhost using UDP as an exporter 3."
      code: "./ipfixprobe -o 'ipfix;h=127.0.0.1,u,I=3'-i 'pcap;file=...;' -s 'cache'"
    -
      explanation: "Send exported data to the localhost:4739 using non-blocking tcp as an exporter 3 with maximal transfer unit set to 2000."
      code: "./ipfixprobe -o 'ipfix;h=127.0.0.1,p=4739,n,mtu=2000'-i 'pcap;file=...;' -s 'cache'"
-
  title: "UNIREC"
  description: "Exports data in the UNIREC format"
  parameters:
    -
      name: "i or ifc"
      description: "Defines unirec interface to use."
    -
      name: "p or plugins"
      description: "Defines plugin-interface mapping. Plugins can be grouped like '(p1,p2,p3),p4,(p5,p6)."
    -
      name: "o or odid"
      description: "Boolean flag.If set exports ODID field."
    -
      name: "e or eof"
      description: "Boolean flag.If set sends eof messag on exit."
    -
      name: "I or id"
      description: "Defines exporter id."
    -
      name: "h or help"
      description: "Prints libtrap help."
  runs:
    -
      explanation: "Send exported data to the Unix socket 'ipfixprobe'"
      code: "./ipfixprobe -o 'unirec;i=u:ipfixprobe'-i 'pcap;file=...;' -s 'cache'"
    -
      explanation: "Same as previous, but should be used with small pcap files to avoid not sending data"
      code: "./ipfixprobe -o 'unirec;i=u:ipfixprobe:timeout=WAIT:buffer=off'-i 'pcap;file=...;' -s 'cache'"
    -
      explanation: "Save exported data to the data.trapcap"
      code: "./ipfixprobe -o 'unirec;i=f:data.trapcap'-i 'pcap;file=...;' -s 'cache'"
---
