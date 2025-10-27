# MPLS Plugin

Plugin extracts and exports MPLS top label if present.

## Output Fields

| Field Name                     | Data Type  | Description                    |
| ------------------------------ | ---------- | ------------------------------ |
| `MPLS_TOP_LABEL_STACK_SECTION` | `uint32_t` | MPLS top label from the packet |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - mpls
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p mpls ...`
