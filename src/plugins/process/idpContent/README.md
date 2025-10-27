# IDPContent Plugin

Plugin captures and exports the payloads of the first packets.

## Features

- Extracts and exports payloads of the first packets in both directions.

## Output Fields

| Field Name        | Data Type | Description                                    |
| ----------------- | --------- | ---------------------------------------------- |
| `IDP_CONTENT`     | `bytes`   | Payload of first packet (source → destination) |
| `IDP_CONTENT_REV` | `bytes`   | Payload of first packet (destination → source) |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - idpcontent
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p idpcontent ...`
