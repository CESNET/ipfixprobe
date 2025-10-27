# SMTP Plugin

The **SMTP Plugin** parses SMTP data and exports relevant fields.

## Features

- Decision about the communication direction is made based on the SMTP port (25).

## Output Fields

| Field Name                 | Data Type  | Description                                        |
| -------------------------- | ---------- | -------------------------------------------------- |
| `SMTP_2XX_STAT_CODE_COUNT` | `uint32_t` | Count of SMTP status codes between 200 and 300     |
| `SMTP_3XX_STAT_CODE_COUNT` | `uint32_t` | Count of SMTP status codes between 300 and 400     |
| `SMTP_4XX_STAT_CODE_COUNT` | `uint32_t` | Count of SMTP status codes between 400 and 500     |
| `SMTP_5XX_STAT_CODE_COUNT` | `uint32_t` | Count of SMTP status codes between 500 and 600     |
| `SMTP_COMMAND_FLAGS`       | `uint32_t` | Cumulative representing the SMTP commands used     |
| `SMTP_MAIL_CMD_COUNT`      | `uint32_t` | Count of MAIL commands received                    |
| `SMTP_RCPT_CMD_COUNT`      | `uint32_t` | Count of RCPT commands received                    |
| `SMTP_STAT_CODE_FLAGS`     | `uint32_t` | Cumulative representing observed SMTP status codes |
| `SMTP_DOMAIN`              | `string`   | Domain of the SMTP session                         |
| `SMTP_FIRST_RECIPIENT`     | `string`   | First recipient of the SMTP session                |
| `SMTP_FIRST_SENDER`        | `string`   | First sender of the SMTP session                   |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - smtp
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p smtp ...`
