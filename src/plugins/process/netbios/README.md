# NetBIOS Plugin

This plugin provides in-depth analysis of NetBIOS traffic by capturing and exporting fields from NetBIOS packets.

## Features

- Extracts and exports NetBIOS name and suffix fields from NetBIOS packets.
- Expects traffic to be on port 137.

## Output Fields

| Field Name  | Data Type | Description                              |
| ----------- | --------- | ---------------------------------------- |
| `NB_NAME`   | `string`  | NetBIOS name extracted from the packet   |
| `NB_SUFFIX` | `char`    | NetBIOS suffix extracted from the packet |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - netbios
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p netbios ...`
