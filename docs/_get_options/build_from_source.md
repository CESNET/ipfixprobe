---
title: Build ipfixprobe from source!
description: You can build ipfixprobe from source codes available at <a href="https://github.com/CESNET/ipfixprobe">github</a>. 

instructions: 
    - 
      description: "Install requirements"
      code: 
        - "yum -y install wget curl net-tools gcc gcc-c++ git libtool libpcap-devel libunwind libssl-devel libpcap-devel"
    - 
       description: "Now get the ipfixprobe source codes"
       code: 
        - "git clone https://github.com/CESNET/ipfixprobe.git"
        - cd ipfixprobe
        - autoreconf -i
    - 
       description: "Ipfixprobe uses autotools to setup the build process. We encourage you to explore <code>./configure.sh -h </code> to see all the available options. Nevertheless, for standard (max 1Gbps) network monitoroing without any specialized tools, you should use following configuration."
       code: 
        - "./configure.sh --with-pcap --with-quic --with-unwind"
    - 
       description: "Then just make the ipfixprobe and install it. You might need root privileges for installation."
       code: 
        - "make -j 2"
        - "sudo make install"

    - 
       description: "Optional NEMEA plugin. Ipfixprobe can export data directly to NEMEA framework. If you want to use this feature, you need to install NEMEA dependencies and enable this feature in autotools script."
       code: 
        - "dnf install libtrap-devel unirec-devel"
        - "./configure.sh --with-pcap --with-quic --with-unwind --with-nemea"
        - "make -j 2"
        - sudo make install
---