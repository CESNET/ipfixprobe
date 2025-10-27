# DNS Plugin

The **DNS Plugin** extends flow records with DNS query and response information.

## Features

- Immediately removes flow if DNS query or response has been parsed.
- Extracts and exports DNS fields if flow contains DNS information.

## Output Fields

| Field Name    | Data Type  | Description                                                     |
| ------------- | ---------- | --------------------------------------------------------------- |
| `DNS_ID`      | `uint16_t` | Unique identifier of the processed DNS query                    |
| `DNS_ANSWERS` | `uint16_t` | Number of answers in the processed DNS response                 |
| `DNS_RCODE`   | `uint8_t`  | Response code of the processed DNS response                     |
| `DNS_QTYPE`   | `uint16_t` | Type of the DNS query                                           |
| `DNS_CLASS`   | `uint16_t` | Class of the DNS query                                          |
| `DNS_NAME`    | `string`   | Domain name in the DNS query                                    |
| `DNS_RR_TTL`  | `uint32_t` | Time-to-live of the first DNS response                          |
| `DNS_RLENGTH` | `uint16_t` | Length of the first DNS response                                |
| `DNS_RDATA`   | `bytes`    | Data of the first DNS response                                  |
| `DNS_PSIZE`   | `uint16_t` | Length of the first DNS additional record from response         |
| `DNS_DO`      | `uint8_t`  | DNSSEC OK flag of the first DNS additional record from response |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - dns
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p dns ...`
