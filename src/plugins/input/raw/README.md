# Raw (Input Plugin)

The Raw input plugin allows you to capture network traffic from a specified interface using raw sockets. It uses a circular buffer to hold the captured packets and can be optimized for specific traffic processing needs.

## Example Configuration

```yaml
input_plugin:
  raw:
    interface: "eth0"
	### Optional parameters
    blocks_count: 2048
	packets_in_block: 32
```

## Parameters

**Mandatory Parameters**

|Parameter | Description |
|---|---|
|__interface__| Network interface name (e.g., eth0) from which to capture traffic |

**Optional parameters:**

|Parameter | Default | Description |
|---|---|---|
|__blocks_count__   | 2048 | Number of blocks in the circular buffer, must be a power of 2. |
|__packets_in_block__   | 2048 | Number of packets per block, must be a power of 2. |
