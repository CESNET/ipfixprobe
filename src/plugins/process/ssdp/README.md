# SSDP Plugin

Plugin enables detailed analysis of SSDP traffic by extracting key fields from SSDP packets.

## Features

- Detection is based on the expected port (1900).

## Output Fields

| Field Name           | Data Type  | Description                                           |
| -------------------- | ---------- | ----------------------------------------------------- |
| `SSDP_LOCATION_PORT` | `uint16_t` | Port from SSDP location header                        |
| `SSDP_NT`            | `string`   | Type of announced device                              |
| `SSDP_SERVER`        | `string`   | Information about the SSDP server (e.g., OS, version) |
| `SSDP_ST`            | `string`   | What devices are being searched for                   |
| `SSDP_USER_AGENT`    | `string`   | Client user agent                                     |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - ssdp
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p ssdp ...`
