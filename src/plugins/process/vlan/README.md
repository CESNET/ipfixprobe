# VLAN Plugin

The **VLAN Plugin** parses VLAN tags and exports extracted values.

## Features

- Extracts and exports VLAN ID.

## Output Fields

| Field Name | Data Type  | Description                        |
| ---------- | ---------- | ---------------------------------- |
| `VLAN_ID`  | `uint16_t` | VLAN ID extracted from the packet. |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - vlan
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p vlan ...`
