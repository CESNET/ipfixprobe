---
title: Installation on Turris (OpenWrt routers)
description: CESNET feed is officially supported by CZ.NIC, so installation on Turris devices is easy! Contrary for other OpenWrt devices, it is most likely necessary to compile a package; see our <a href="">NEMEA-OpenWrt feed</a> for more details or contact us.  Installation on Turris can be done via SSH, which is described bellow, or using LUCI intuitive interface.

instructions: 
    - 
      description: "Update repository metadata"
      code:
        - opkg update

    - 
       description: "Install ipfixprobe"
       code: 
        - opkg install ipfixprobe

    -
       description: "Optionally for LUCI configuration page, install luci-app-ipfixprobe"
       code:
        - opkg install luci-app-ipfixprobe


---

