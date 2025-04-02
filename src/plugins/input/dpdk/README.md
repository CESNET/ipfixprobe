# DPDK (input plugin)

DPDK (Data Plane Development Kit) is used for high-performance packet processing. It enables
direct access to network interfaces, bypassing the kernel, and is suitable for use in environments
requiring high throughput, low latency, and high packet processing rates.

## Example configuration

```yaml
input_plugin:
  dpdk:
    allowed_nics: "0000:ca:00.0"
    ### Optional parameters
    burst_size: 64
    mempool_size: 8192
    rx_queues: 8
    eal_opts: null
    mtu: 1518
```

## Parameters

**Mandatory parameters:**

|Parameter | Description |
|---|---|
|__allowed_nics__|List of allowed NICs in PCI address format `0000:XX:YY.Z` separated with `,` |

**Optional parameters:**
|Parameter | Default | Description |
|---|---|---|
|__burst_size__   | 64 | Number of packets processed in each burst cycle. Affects batch processing efficiency. |
|__mempool_size__ | 8192 | Size of the memory pool used for buffering incoming packets. Must be a power of 2.|
|__rx_queues__    | 1|  Number of RX queues workers. Increasing this can help distribute load across multiple CPU cores. |
|__eal_opts__     | null | Extra options to be passed to the DPDK EAL (Environment Abstraction Layer). Can be used for fine-tuning DPDK behavior.|
|__mtu__          | 1518 | Maximum Transmission Unit size for the interface. Defines the maximum packet size that can be received.|

## How to use

To use the DPDK input plugin, you must ensure that your system is properly configured for DPDK operation. This includes the following steps:

### 1. Install DPDK Tools

To begin with, you will need to install DPDK and its associated tools. Follow the installation instructions for your operating system:

- **On RHEL/CentOS**:
```sh
dnf install dpdk-tools
```

- **On Debian/Ubuntu**:
```sh
apt-get install dpdk
```

### 2. Configure the DPDK Driver

TODO Mellanox, broadcom, intel

### 3. Allocate Hugepages

DPDK requires hugepages for optimal performance. Instead of manually configuring hugepages, you can use the `dpdk-hugepages` tool, which simplifies the process.

To allocate hugepages, run:
```sh
dpdk-hugepages.py -p 1G --setup 2G
```

This allocates 2GB of hugepages with a default page size of 1GB. You can adjust these values based on your memory requirements.

To verify the allocated hugepages:

```sh
dpdk-hugepages -s
```

Recommended hugepages configuration for 100G probe is:

```sh
dpdk-hugepages.py -p 1G --setup 4G
```

### 4. Validate with dpdk-testpmd

TODO

## FAQ

|Q: | How many `rx_queues` should I configure? |
|---|---|
|A: | TODO |

|Q: | ??? |
|---|---|
|A: | TODO |



