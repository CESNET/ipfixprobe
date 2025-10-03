# OpenVPN Plugin

Analyzes connections to identify OpenVPN traffic.

## Features

- Calculates and exports confidence that given flow is OpenVPN.

## Output Fields

| Field Name        | Data Type | Description                                                    |
| ----------------- | --------- | -------------------------------------------------------------- |
| `OVPN_CONF_LEVEL` | `uint8_t` | Confidence that given flow is OpenVPN as a percentage (0-100). |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - ovpn
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p ovpn ...`
