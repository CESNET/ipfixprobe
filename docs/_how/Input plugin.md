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
      title: "DPDK"
      description: "Input plugin for reading packets using DPDK interface"
      parameters:
        - 
          name: "b or bsize" 
          description: "Size of the MBUF packet buffer. Default: 64."
        - 
          name: "p or port" 
          description: "DPDK port to be used as an input interface."
        - 
          name: "m or mem" 
          description: "Size of the memory pool for received packets. Default: 16384."
        - 
          name: "q or queue" 
          description: "Number of RX queues. Default: 1."
        - 
          name: "e or eal" 
          description: "DPDK eal."
        - 
          name: "M or mtu" 
          description: "Input interface MTU. Default: 1518."
      runs:  
        - 
            explanation: "Read packets using DPDK input interface and 1 DPDK queue, enable plugins for basic statistics, http and tls, output to IPFIX on a local machine
						DPDK EAL parameters are passed in `e, eal` parameters
						 DPDK plugin configuration has to be specified in the first input interface.
						 The following `dpdk` interfaces are given without parameters; their configuration is inherited from the first one.
						 Example for the queue of 3 DPDK input plugins (q=3): "
            code: "./ipfixprobe -i 'dpdk;p=0;q=3;e=-c 0x1 -a  <[domain:]bus:devid.func>' -i dpdk -i dpdk -p http -p bstats -p tls -o 'ipfix;h=127.0.0.1'"
        -
            explanation: "Same example for the multiport read from ports 0 and 1, note comma separated ports:"
            code: "./ipfixprobe -i 'dpdk;p=0,1;q=3;e=-c 0x1 -a  <[domain:]bus:devid.func>' -i dpdk -i dpdk -p http -p bstats -p tls -o 'ipfix;h=127.0.0.1'"
    - 
      title: "DPDK-ring"
      description: "DPDK ring input interface for ipfixprobe (secondary DPDK app)."
      parameters:
        - 
          name: "b or bsize" 
          description: "Size of the MBUF packet buffer. Default: 64."
        - 
          name: "r or ring" 
          description: "Name of the ring to read packets from. Need to be specified explicitly thus no default provided."
        - 
          name: "e or eal" 
          description: "DPDK eal."
      runs:  
        -
            explanation: "Read packets using DPDK input interface as secondary process with shared memory (DPDK rings) - in this case, 4 DPDK rings are used"
            code: "./ipfixprobe -i 'dpdk-ring;r=rx_ipfixprobe_0;e= --proc-type=secondary' -i 'dpdk-ring;r=rx_ipfixprobe_1' -i 'dpdk-ring;r=rx_ipfixprobe_2' -i 'dpdk-ring;r=rx_ipfixprobe_3' -o 'text'"
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