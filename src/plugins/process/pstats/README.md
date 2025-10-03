# PacketStats Plugin

The **PacketStats Plugin** collects and exports properties of packet sequences from network flows.

## Features

- Does not export flows considered to be TCP scans.
- Uses a memory-efficient storage mechanism to reduce memory usage for short flows (under 5 packets).

## Parameters

| Long name | Short name      | Type   | Default | Description                                                                 |
| --------- | --------------- | ------ | ------- | --------------------------------------------------------------------------- |
| `i`       | `includezeroes` | `bool` | false   | Whether to include zero-length packets in the analysis                      |
| `s`       | `skipdup`       | `bool` | false   | Whether to skip packet duplicates. Compares every packet length to previous |

## Output Fields

| Field Name           | Data Type             | Description                                             |
| -------------------- | --------------------- | ------------------------------------------------------- |
| `PPI_PKT_LENGTHS`    | `array of uint16_t`   | Lengths of the processed packets                        |
| `PPI_PKT_TIMES`      | `array of timestamps` | Timestamps of the processed packets                     |
| `PPI_PKT_FLAGS`      | `array of uint8_t`    | TCP flags of the processed packets                      |
| `PPI_PKT_DIRECTIONS` | `array of int8_t`     | 1 for source → destination, -1 for destination → source |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - pstats
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p pstats ...`
