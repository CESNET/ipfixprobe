---
title: Installation from binary packages (RPM) (recommended)
description: We use <a href="https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA-stable/">COPR infrastructure</a> to build and serve ipfixprobe packages. Currently, we support packages for RPM-based distributions, such as OracleLinux, RockyLinux, ... EPEL version 8 or 9.

instructions:
    -
      description: "Install copr repository."
      code:
        - "dnf install -y dnf-plugins-core && dnf copr -y enable @CESNET/NEMEA-stable"

    -
       description: "After succesfull instalation of COPR, you can install the ipfixprobe via yum or dnf."
       code:
        - "dnf install ipfixprobe"

---
