---
title: <strong>Storage plugin</strong>
description: Storage plugin defines how flows are internally stored. Use <strong>-s</strong> to specify storage plugin.

options:
-
  title: "Cache"
  description: "Currently only available plugin. Hash table is used to keep flows. Hash table is divided into rows. Each row is managed as LRU. "
  parameters:
    -
      name: "s or size"
      description: "Defines count of flows that are kept in the cache at once. Cache size is 2<sup>s</sup>."
    -
      name: "l or line"
      description: "Defines length of the cache line. Line length is 2<sup>l</sup>."
    -
      name: "a or active"
      description: "Defines active timeout. When there is a flow, that is active for more than <b>-a</b> seconds, its exported."
    -
      name: "i or inactive"
      description: "Defines inactive timeout. When there is a flow, that is inactive for more than <b>-i</b> seconds, its exported."
    -
      name: "S or split "
      description: "Boolean flag. Defines if the bidirectional flow between two nodes is splitted into 2 separate unidirectional flows."
    -
      name: "fe/frag-enable, fs/frag-size, ft/frag-timeout"
      description: "Used to enable completing fragmented packets into one packet. Framentation cache size is <b>fs</b> and timeout to consider fragments belong to same packet is <b>ft</b>."
  runs:
    -
      explanation: "Store flows using 'cache' "
      code: "./ipfixprobe -s 'cache' -i 'pcap;file=PATH;'"
---
