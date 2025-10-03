# ICMP Plugin

Plugin extracts and exports ICMP type and code if present.

## Output Fields

| Field Name          | Data Type  | Description                                         |
| ------------------- | ---------- | --------------------------------------------------- |
| `L4_ICMP_TYPE_CODE` | `uint16_t` | ICMP type in first byte and code in the second byte |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - icmp
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p icmp ...`
