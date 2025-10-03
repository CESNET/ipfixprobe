# BurstStats Plugin

The **BurstStats Plugin** extends flow records with burst packet statistics to provide analysis of bursty traffic patterns.

## Features

- Consider packet to be a part of burst if it arrives within short time interval after previous packet.
- Extracts and exports burst statistics from network flows.

## Output Fields

| Field Name            | Data Type   | Description                                                 |
| --------------------- | ----------- | ----------------------------------------------------------- |
| `SBI_BRST_PACKETS`    | `uint32_t`  | Array of packet counts in each burst (source → destination) |
| `SBI_BRST_BYTES`      | `uint32_t`  | Array of bytes in each burst (source → destination)         |
| `SBI_BRST_TIME_START` | `Timestamp` | Array of burst start times (source → destination)           |
| `SBI_BRST_TIME_STOP`  | `Timestamp` | Array of burst end times (source → destination)             |
| `DBI_BRST_PACKETS`    | `uint32_t`  | Array of packets in each burst (destination → source)       |
| `DBI_BRST_BYTES`      | `uint32_t`  | Array of bytes in each burst (destination → source)         |
| `DBI_BRST_TIME_START` | `Timestamp` | Array of burst start times (destination → source)           |
| `DBI_BRST_TIME_STOP`  | `Timestamp` | Array of burst end times (destination → source)             |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - bstats
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p bstats ...`
