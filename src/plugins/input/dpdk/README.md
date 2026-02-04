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
    workers_cpu_list: []
    eal_opts: null
    mtu: 1518
    rss_offload: null
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
|__workers_cpu_list__| [] (autofill) | List of CPU cores assigned to RX queues (must match number of rx_queues) |
|__eal_opts__     | null | Extra options to be passed to the DPDK EAL (Environment Abstraction Layer). Can be used for fine-tuning DPDK behavior.|
|__mtu__          | 1518 | Maximum Transmission Unit size for the interface. Defines the maximum packet size that can be received.|
|__rss_offload__  | null | RSS offload configuration. Can be used to override the default RSS offload configuration.|

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

### 2. Identify the PCI Address of the Network Interface
DPDK operates directly with network interfaces identified by their PCI addresses, not by traditional interface names like `eth0` or `ens3`.

A PCI address looks like this:

```
0000:ca:00.0
```

This format includes:
- Domain: `0000` – typically 0000 on most systems
- Bus: `ca`
- Device: `00`
- Function: `0`

Each network interface has a unique PCI address, and this is how DPDK identifies which interface to bind and use.

🔍 How to find the PCI address of a network interface
The recommended way to identify the PCI address is using the DPDK helper tool, dpdk-devbind.py. This tool lists all the NICs in the system with their PCI addresses and shows which drivers are currently bound to them.

```
dpdk-devbind.py --status
```

This shows the PCI addresses of all detected NICs along with the drivers they're bound to. If the NIC is not already bound to a DPDK-compatible driver (e.g., `vfio-pci`), you can bind it using this tool.

### 3. Identify the Numa node of the Network interface

DPDK operates efficiently on systems with multiple **NUMA (Non-Uniform Memory Access)** nodes, and it is essential to know which NUMA node a network interface belongs to, as this affects memory locality and performance.

Each physical device (like a network interface card) is associated with a specific NUMA node, which influences the memory accesses and CPU affinity during packet processing. You can use the NUMA node information to optimize the performance of your application by binding the NIC to a NUMA node that is also closest to the processing CPU cores.

**🔍 How to find the NUMA node of a network interface?**

You can identify the NUMA node to which a specific network interface is attached by directly checking the /sys filesystem.

Using the `/sys/bus/pci/devices/{pci_address}/numa_node` path:

The most direct method to get the NUMA node for a network interface is by querying the numa_node file in the /sys directory.

First, you need to know the PCI address of your network interface. Once you have the PCI address (e.g., 0000:ca:00.0), you can check the NUMA node for that interface by reading the numa_node file:

```
cat /sys/bus/pci/devices/0000:ca:00.0/numa_node
```

This will output the NUMA node number where the NIC is located. For example:
```
0
```

This indicates that the NIC is attached to NUMA node 0.


If the output is -1, it means that the device does not have an associated NUMA node or the system does not have NUMA support.

### 4. Allocate Hugepages

DPDK requires hugepages for optimal performance, as they provide large, contiguous memory blocks that reduce overhead and improve data throughput. Hugepages are critical for performance in high-speed networking environments, such as those used by DPDK, where low latency and high throughput are required.

**🛠️ Configuring Hugepages via Kernel Parameters [Recommended]**

You can configure hugepages directly at the kernel level using the grubby tool. This approach is recommended if you want to make the hugepages configuration persistent across system reboots.

To configure hugepages via grubby, use the following command:

```
grubby --update-kernel ALL --args "default_hugepagesz=1GB hugepagesz=1G hugepages=4"
```
This command will:

- Set the default hugepage size to 1GB (default_hugepagesz=1GB).
- Set the hugepage size to 1GB (hugepagesz=1G).
- Allocate 4 hugepages (hugepages=4).

**⚠️ Important Note:** When using this method, it is not possible to specify a particular NUMA node. The hugepages will be distributed evenly across all available NUMA nodes on the system. This means the memory for hugepages will be shared equally among the NUMA nodes without considering any specific NUMA affinity for your application.

After running the command, you need to reboot the system for the changes to take effect.

---
**📌 Allocating Hugepages Using dpdk-hugepages.py**

Alternatively, you can use the dpdk-hugepages.py script to allocate hugepages at runtime. This method allows you to allocate hugepages dynamically and specify NUMA nodes.

To allocate hugepages using dpdk-hugepages.py, you can run the following command:

```
dpdk-hugepages.py -p 1G --setup 2G --node 0
```

This command allocates 2GB of hugepages with a 1GB page size on NUMA node 0. You can adjust these values based on your system's memory requirements and the NUMA node of your NIC.

If you require more hugepages, you can increase the amount by modifying the --setup parameter, as follows:

```
dpdk-hugepages.py -p 1G --setup 4G --node 0
```

This will allocate 4GB of hugepages with a 1GB page size on NUMA node 0.

**📌 Recommended Hugepages Configuration for High-Speed Links (100G, 200G, 400G)**

For high-speed links such as 100G, 200G, or 400G, it is crucial to allocate enough hugepages to handle the massive packet processing and memory requirements. The following values are recommended based on typical usage for each type of link:

**100G link:**
For 100G links, you should allocate at least 4GB of hugepages with a 1GB page size. This is generally sufficient for moderate traffic and packet processing needs.

Recommended command:
```
dpdk-hugepages.py -p 1G --setup 4G --node 0
```
---
***200G link:***
For 200G links, you will likely need 8GB of hugepages with a 1GB page size, as the traffic and memory bandwidth requirements will be higher.

Recommended command:
```
dpdk-hugepages.py -p 1G --setup 8G --node 0
```

---

***400G link:***
For 400G links, a significant increase in hugepages is required. You should allocate 16GB of hugepages with a 1GB page size to handle the higher throughput and memory demands.

Recommended command:
```
dpdk-hugepages.py -p 1G --setup 16G --node 0
```

**🖥️ Verify the allocated Hugepages**

To verify that the hugepages were allocated successfully, you can use the following command:

``` dpdk-hugepages -s ```

This command shows the status of the hugepages and confirms how much memory has been allocated.

---

### 5. Configure the DPDK Driver

TODO Mellanox, broadcom, intel
TODO Lukas

### 6. Isolate CPUs (optionally)

Isolating specific CPUs can enhance the performance of DPDK applications by dedicating certain processors to networking tasks, reducing interference from other system processes. This isolation minimizes context switching and ensures that the CPUs are dedicated to packet processing.

**🛠️ How to Isolate CPUs?**

To isolate CPUs on a system, you can use the tuned package and adjust kernel parameters. The steps below demonstrate how to set up CPU isolation using tuned profiles and kernel boot parameters. These steps apply to both Intel and AMD systems, with specific configuration examples for both.

1. **Install the necessary package**

    First, install the tuned-profiles-cpu-partitioning package, which contains CPU isolation profiles:

    ```bash
    dnf install tuned-profiles-cpu-partitioning
    ```

2. **Enable IOMMU and Isolate CPUs Using GRUB**

    **For Intel Systems**: Enable Intel IOMMU for direct device access in DPDK. Update your GRUB configuration by adding the following arguments for Intel processors:
    ```
    grubby --update-kernel ALL --args "iommu=pt intel_iommu=on"
    ```

    **For AMD Systems**: Enable AMD IOMMU for direct device access in DPDK. Update your GRUB configuration by adding the following arguments for AMD processors:

    ```
    grubby --update-kernel ALL --args "iommu=pt amd_iommu=on"
    ```

3. Isolate CPUs for DPDK

    Once IOMMU is enabled, you can isolate specific CPUs for DPDK using the isolcpus parameter. This ensures that only the isolated CPUs are used for networking tasks.

    To isolate CPUs 2-19 and 22-39 on an Intel system, use the following command:

```
grubby --update-kernel ALL --args "isolcpus=2-19,22-39"
```


### 4. Troubleshooting

⚠️ RSS on Intel X710 (i40e)

We observed that RSS on Intel X710 (i40e) may not distribute packets across multiple RX queues with the default RTE_ETH_RSS_IP.
For X710 (i40e) we use full RSS offload provided by the driver. If you experience similar issues, try to set `rss_offload` explicitly to override the default RSS offload configuration.

## FAQ

|Q: | How many `rx_queues` should I configure? |
|---|---|
|A: | TODO |

|Q: | ??? |
|---|---|
|A: | TODO |



