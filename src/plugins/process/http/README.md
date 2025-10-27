# HTTP Plugin

Plugin enables detailed analysis of HTTP traffic by extracting key fields from HTTP headers.

## Features

- Extracts and exports HTTP request and response fields if flow contains HTTP information.
- Terminates the flow if both HTTP request or response have been parsed.
- Reinserts the flow if the second request or response is detected.

## Output Fields

| Field Name                       | Data Type  | Description                                 |
| -------------------------------- | ---------- | ------------------------------------------- |
| `HTTP_REQUEST_METHOD`            | `string`   | HTTP request method (e.g., GET, POST)       |
| `HTTP_REQUEST_HOST`              | `string`   | Requested HTTP host                         |
| `HTTP_REQUEST_URL`               | `string`   | Requested URL                               |
| `HTTP_REQUEST_AGENT`             | `string`   | User agent of the requester                 |
| `HTTP_REQUEST_REFERER`           | `string`   | HTTP request referer                        |
| `HTTP_RESPONSE_STATUS_CODE`      | `uint16_t` | Response status code                        |
| `HTTP_RESPONSE_CONTENT_TYPE`     | `string`   | Response content type                       |
| `HTTP_RESPONSE_SERVER`           | `string`   | Response server                             |
| `HTTP_RESPONSE_SET_COOKIE_NAMES` | `string`   | Concatenated names of cookies that were set |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - http
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p http ...`
