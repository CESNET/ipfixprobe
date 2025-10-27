# PassiveDNS Plugin

The **PassiveDNS Plugin** extends flow records with DNS response information.

## Features

- Extracts and exports DNS response data if flow contains DNS information.
- Immediately removes flow after response is parsed.
- Expects DNS communication on standard port (53).

## Output Fields

| Field Name   | Data Type  | Description                                     |
| ------------ | ---------- | ----------------------------------------------- |
| `DNS_ID`     | `uint16_t` | Unique identifier of the processed DNS response |
| `DNS_NAME`   | `string`   | Domain name in the DNS response                 |
| `DNS_RR_TTL` | `uint32_t` | Time-to-live of the response                    |
| `DNS_IP`     | `uint8_t`  | Obtained IP address from the DNS response       |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - passivedns
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p passivedns ...`
