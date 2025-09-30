# Pcap Live (input plugin)

The Pcap Live input plugin allows for real-time packet capture on a specified network interface.

## Example configuration

```yaml
input_plugin:
  pcap_live:
    interface: "eth0"
    ### Optional parameters
    snap_length: 65535
    bpf_filter: null
```

## Parameters

**Mandatory parameters:**

|Parameter | Description |
|---|---|
|__interface__| The network interface to capture packets from (e.g., eth0, ens33, etc.). This is required for the plugin to know which network interface to monitor. |

-----

**Optional parameters:**
|Parameter | Default | Description |
|---|---|---|
|__snap_length__   | 65535 | Maximum packet capture length in bytes. It defines the size of the packet that will be captured. The default value captures full packets (up to 65535 bytes). |
|__bpf_filter__ | null | A Berkeley Packet Filter (BPF) string for packet filtering. If null, no filter is applied. If a filter is specified, only packets matching the filter criteria will be captured. |

# Pcap File (input plugin)

The Pcap File input plugin allows you to read and process packets from an existing .pcap file. This is useful for analyzing historical packet captures or testing with predefined data.

## Example configuration

```yaml
input_plugin:
  pcap_file:
    file: "input.pcap"
    ### Optional parameters
    bpf_filter: null
```

## Parameters

**Mandatory parameters:**

|Parameter | Description |
|---|---|
|__file__| 	Path to the pcap file that contains the packet data to be read. |

-----

**Optional parameters:**
|Parameter | Default | Description |
|---|---|---|
|__bpf_filter__ | null | A Berkeley Packet Filter (BPF) string for packet filtering. If null, no filter is applied. If a filter is specified, only packets matching the filter criteria will be captured. |
