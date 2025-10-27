# SSADetector Plugin

Analyzes connections to identify encrypted tunnels.

## Features

- Calculates and exports confidence that given flow is a tunnel.
- Detection is base on identification of encrypted TCP syn-synack-ack tuples.

## Output Fields

| Field Name       | Data Type | Description                                                     |
| ---------------- | --------- | --------------------------------------------------------------- |
| `SSA_CONF_LEVEL` | `uint8_t` | Confidence that given flow is a tunnel as a percentage (0-100). |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - ssadetector
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p ssadetector ...`
