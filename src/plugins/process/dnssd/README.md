# DNSSD Plugin

The **DNSSD Plugin** extends flow records with DNS-SD (DNS Service Discovery) query and response information.

## Features

- Extracts and exports DNS-SD fields if flow contains DNS-SD information.

## Parameters

| Long name | Short name | Type   | Default | Description                                                 |
|-----------|------------|--------|---------|-------------------------------------------------------------|
| `txt`     | `t`       | `Path to file`   | **Disabled** | If no file provided, processes all DNSSD TXT records. If a file is provided, only processes TXT records listed in the file. Whitelist format is `service.domain,txt_key1,txt_key2,...` |

## Output Fields

| Field Name      | Data Type | Description                                                 |
|-----------------|-----------|----------------------------------------|
| `DNS_ID`| `uint16_t`  | Unique identifier of the processed DNS query |
| `DNS_ANSWERS`| `uint16_t`  | Number of answers in the processed DNS response |
| `DNS_RCODE`| `uint8_t`  | Response code of the processed DNS response |
| `DNS_QTYPE`| `uint16_t`  | Type of the DNS query |
| `DNS_CLASS`| `uint16_t`  | Class of the DNS query |
| `DNS_NAME`| `string`  | Domain name in the DNS query |
| `DNS_RR_TTL`| `uint32_t`  | Time-to-live of the first DNS response |
| `DNS_RLENGTH`| `uint16_t`  | Length of the first DNS response |
| `DNS_RDATA`| `bytes`  | Data of the first DNS response |
| `DNS_PSIZE`| `uint16_t`  | Length of the first DNS additional record from response |
| `DNS_DO`| `uint8_t`  | DNSSEC OK flag of the first DNS additional record from response |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - dns
```

### CLI Usage

You can also enable the plugin directly from the command line:

```ipfixprobe -p dns ...```