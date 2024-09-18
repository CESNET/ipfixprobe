---
title: Input plugin
description: Input plugin defines source of incoming packets. Use <b>-i</b> to specify input plugin.  

options: 
    - 
      title: "Pcap reader"
      description: "Input plugin for reading packets from a pcap file or a network interface"
      parameters:
        - 
          name: "f or file" 
          description: "Defines path to pcap file."
        - 
          name: "i or ifc" 
          description: "Defines interface name."
        - 
          name: "F or filter" 
          description: "Defines filter string."
        - 
          name: "s or snaplen" 
          description: "Defines snapshot length in bytes (live capture only)."
        - 
          name: "l or list" 
          description: "Print list of available interfaces."
      runs:  
        - 
            explanation: "Read the pcap file specified by PATH value. Possible PATH value 'pcaps/bstats.pcap' "
            code: "./ipfixprobe -i 'pcap;file=PATH;' -s 'cache'"
        -
            explanation: "Read packets from interface specified by IFC value. Possible IFC value 'eth0'"
            code: "./ipfixprobe -i 'pcap;i=IFC;' -s 'cache'"
    -
      title: "Raw"
      description: "Input plugin for reading packets from raw interface"
      parameters:
        - 
          name: "i or ifc" 
          description: "Defines network interface name."
        - 
          name: "b or blocks" 
          description: "Defines number of packet blocks."
        - 
          name: "f or fanout" 
          description: "Enables packet fanout."
        - 
          name: "p or pkts" 
          description: "Defines number of packets in block."
        - 
          name: "l or list" 
          description: "Print list of available interfaces."  
      runs:
        -
          explanation: "Read packets from interface specified by IFC value. Possible IFC value 'eth0'"
          code: "./ipfixprobe -i 'raw;ifc=IFC;' -s 'cache'"
    -
      title: "Benchmark"
      description: "Input plugin for various benchmarking purposes."
      parameters:
        - 
          name: "m or mode" 
          description: "Defines benchmark mode: 1f (1x N-packet flow) or nf (Nx 1-packet flow)."
        - 
          name: "S or seed" 
          description: "Defines string seed for random generator."
        - 
          name: "d or duration" 
          description: "Defines duration in seconds." 
        - 
          name: "p or count"  
          description: "Defines packet count."
        - 
          name: "s or size" 
          description: "Defines packet size."  
        - 
          name: "I or id" 
          description: "Defines link identifier number."
      runs:
        -
          explanation: "Read packets from interface specified with DPDK ports 0 and 1"
          code: "`./ipfixprobe -i 'dpdk;p=0,1;' -s 'cache'"
   
---