---
title: Get ipfixprobe from repository!
description: We use COPR infrastructure to build and serve ipfixprobe packages. Currently, we generate RPM packages for RHEL-based distributions

instructions: 
    - 
      description: "Install copr repository. Here is the example for EPEL 8."
      code: 
        - "wget -O /etc/yum.repos.d/cesnet-nemea.repo https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/repo/epel-8/group_CESNET-NEMEA-epel-8.repo"
        - "rpm --import https://copr-be.cloud.fedoraproject.org/results/@CESNET/NEMEA/pubkey.gpg"
    - 
       description: "After succesfull instalation of COPR, you can install the ipfixprobe via yum or dnf."
       code: 
        - "dnf install ipfixprobe"


---