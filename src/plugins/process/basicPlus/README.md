# BasicPlus Plugin

The **BasicPlus** plugin extends flow records with additional basic network information to provide richer visibility into network flows.

## Features

- Extends standard flow export data with additional fields.
- Extracts and exports key network-level fields for both directions of a flow.

## Output Fields

| Field Name     | Data Type  | Description                                           |
| -------------- | ---------- | ----------------------------------------------------- |
| `IP_TTL`       | `uint8_t`  | IP time-to-live (source → destination)                |
| `IP_TTL_REV`   | `uint8_t`  | IP time-to-live (destination → source)                |
| `IP_FLG`       | `uint8_t`  | IP flags (source → destination)                       |
| `IP_FLG_REV`   | `uint8_t`  | IP flags (destination → source)                       |
| `TCP_WIN`      | `uint16_t` | TCP window size (source → destination)                |
| `TCP_WIN_REV`  | `uint16_t` | TCP window size (destination → source)                |
| `TCP_OPT`      | `uint64_t` | TCP options (source → destination)                    |
| `TCP_OPT_REV`  | `uint64_t` | TCP options (destination → source)                    |
| `TCP_MSS`      | `uint32_t` | TCP maximum segment size (source → destination)       |
| `TCP_MSS_REV`  | `uint32_t` | TCP maximum segment size (destination → source)       |
| `TCP_SYN_SIZE` | `uint16_t` | TCP SYN packet size (only one per bidirectional flow) |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - basicplus
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p basicplus ...`
