# DNSSD Plugin

The **DNSSD Plugin** extends flow records with DNS-SD (DNS Service Discovery) query and response information.

## Features

- Extracts and exports DNS-SD fields if flow contains DNS-SD information.

## Parameters

| Long name | Short name | Type           | Default      | Description                                                                                                                                                                            |
| --------- | ---------- | -------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `txt`     | `t`        | `Path to file` | **Disabled** | If no file provided, processes all DNSSD TXT records. If a file is provided, only processes TXT records listed in the file. Whitelist format is `service.domain,txt_key1,txt_key2,...` |

## Output Fields

| Field Name        | Data Type | Description                                                                                             |
| ----------------- | --------- | ------------------------------------------------------------------------------------------------------- |
| `DNSSD_QUERIES`   | `string`  | Concatenated list of requested services                                                                 |
| `DNSSD_RESPONSES` | `string`  | Concatenated list of processed DNS responses: name, src port, cpu, operating system, TXT record content |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - dnssd
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p dnssd ...`
`ipfixprobe -p "dnssd;txt" ...`
`ipfixprobe -p "dnssd;txt=<path_to_file>" ...`
