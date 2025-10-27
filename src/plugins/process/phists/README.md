# PacketHistogram Plugin

The **PacketHistogram Plugin** builds histograms based on packet sizes and inter-arrival times.

## Features

- Builds and exports packet histograms.
- Histograms are built based on packet sizes and inter-arrival times.
- Bins are separated exponentially. Every next bin has double size of the previous one.

## Output Fields

| Field Name       | Data Type           | Description                                           |
| ---------------- | ------------------- | ----------------------------------------------------- |
| `S_PHISTS_SIZES` | `array of uint32_t` | Packet sizes histogram (source → destination).        |
| `S_PHISTS_IPT`   | `array of uint32_t` | Inter-arrival times histogram (source → destination). |
| `D_PHISTS_SIZES` | `array of uint32_t` | Packet sizes histogram (destination → source).        |
| `D_PHISTS_IPT`   | `array of uint32_t` | Inter-arrival times histogram (destination → source). |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - phists
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p phists ...`
