---
title: Get ipfixprobe from repository!
description: We use COPR infrastructure to build and serve ipfixprobe packages. Currently, we generate RPM packages for RHEL-based distributions

instructions: 
    - 
      description: "Install copr repository."
      code:
        - "dnf install -y dnf-plugins-core && dnf copr -y enable @CESNET/NEMEA"

    - 
       description: "After succesfull instalation of COPR, you can install the ipfixprobe via yum or dnf."
       code: 
        - "dnf install ipfixprobe"


---