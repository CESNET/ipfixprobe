# FlowHash Plugin

The **FlowHash Plugin** extends flow records with flow hashing information.

## Features

- Extracts and exports flow hash that ipfixprobe storage plugin assigned to given flow.

## Output Fields

| Field Name | Data Type  | Description        |
| ---------- | ---------- | ------------------ |
| `FLOW_ID`  | `uint64_t` | Assigned flow hash |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - flowhash
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p flowhash ...`
