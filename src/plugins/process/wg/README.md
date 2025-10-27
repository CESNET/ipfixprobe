# Wireguard Plugin

Analyzes connections to identify WireGuard traffic.

## Features

- Calculates and exports confidence that given flow is WireGuard with extracted peer information.

## Output Fields

| Field Name      | Data Type  | Description                                                      |
| --------------- | ---------- | ---------------------------------------------------------------- |
| `WG_CONF_LEVEL` | `uint8_t`  | Confidence that given flow is WireGuard as a percentage (0-100). |
| `WG_SRC_PEER`   | `uint32_t` | Extracted WireGuard peer identifier from source IP address.      |
| `WG_DST_PEER`   | `uint32_t` | Extracted WireGuard peer identifier from destination IP address. |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - wg
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p wg ...`
