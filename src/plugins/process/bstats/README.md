# BurstStats Plugin

The **BurstStats Plugin** extends flow records with burst packet statistics to provide analysis of bursty traffic patterns.

## Features

- Consider packet to be a part of burst if it arrives within short time interval after previous packet.
- Extracts and exports burst statistics from network flows. 

## Output Fields

| Field Name      | Data Type | Description                                                 |
|-----------------|-----------|-------------------------------------------------------------|
| `SBI_BRST_PACKETS`| `uint32_t`  | Array of packet counts in each burst (source -> destination)                  |
| `SBI_BRST_BYTES`  | `uint32_t`  | Array of bytes in each burst in source-to-destination direction                    |
| `SBI_BRST_TIME_START` | `Timestamp` | Array of burst start times in source-to-destination direction                   |
| `SBI_BRST_TIME_STOP`  | `Timestamp` | Array of burst end times in source-to-destination direction                     |
| `DBI_BRST_PACKETS`| `uint32_t`  | Array of packets in each burst in destination-to-source direction                  |
| `DBI_BRST_BYTES`  | `uint32_t`  | Array of bytes in each burst in destination-to-source direction                    |
| `DBI_BRST_TIME_START` | `Timestamp` | Array of burst start times in destination-to-source direction                   |
| `DBI_BRST_TIME_STOP`  | `Timestamp` | Array of burst end times in destination-to-source direction                     |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - bstats
```

### CLI Usage

You can also enable the plugin directly from the command line:

```ipfixprobe -p bstats ...```
