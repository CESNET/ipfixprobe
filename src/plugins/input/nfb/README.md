# NFB (input plugin)

Receive packets over nfb (Netcope FPGA Board). Requires a special network card with compatible
firmware for high-speed packet processing. Suitable for speeds of 100 Gbps and above.

## Example configuration

```yaml
input_plugin:
  ndp:
    device: "/dev/nfb0"
    queues: "0,1,2,3-15"
```

## Parameters

**Mandatory parameters:**

|Parameter | Description |
|---|---|
|__device__| Path to the NFB device to be used. Typically /dev/nfb0 or /dev/nfb/by-serial-no/{card-serial} |
|__queues__| List of queues to be used for packet reception. The queues can be specified as a comma-separated list (e.g., 0,1,2) or a range (e.g., 3-15). This is required to determine which specific receive queues to use on the NFB device. |
