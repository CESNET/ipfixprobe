# NFB (input plugin)

Receive packets over nfb (Netcope FPGA Board). Requires a special network card with compatible
firmware for high-speed packet processing. Suitable for speeds of 100 Gbps and above.

## Parameters
```
  d, dev=PATH    Path to the NFB device to be used and queue ID. (required)
                 Typically /dev/nfbX:ID or /dev/nfb/by-pci-slot/.... [path:id]
````
