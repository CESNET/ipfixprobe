# SIP Plugin

The **SIP Plugin** parses SIP data and exports relevant fields.

## Features

- Reinserts the flow after the second SIP message is received.

## Output Fields

| Field Name                   | Data Type  | Description                              |
| ---------------------------- | ---------- | ---------------------------------------- |
| `RTSP_REQUEST_METHOD`        | `string`   | Method of the RTSP request               |
| `RTSP_REQUEST_AGENT`         | `string`   | User-Agent header of the RTSP request    |
| `RTSP_REQUEST_URI`           | `string`   | URI of the RTSP request                  |
| `RTSP_RESPONSE_STATUS_CODE`  | `uint16_t` | Status code of the RTSP response         |
| `RTSP_RESPONSE_SERVER`       | `string`   | Server header of the RTSP response       |
| `RTSP_RESPONSE_CONTENT_TYPE` | `string`   | Content-Type header of the RTSP response |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - rtsp
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p rtsp ...`
