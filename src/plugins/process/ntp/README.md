# NetworkTime Plugin

Plugin extract and export various data from NTP packets.

## Features

- Calculates and exports statistical properties of the flow based on packet lengths.
- Expects traffic to be on port 123.
- Immediately terminates the flow after processing the first NTP packet.

## Output Fields

| Field Name       | Data Type  | Description                                                                                                                                |
| ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `NTP_LEAP`       | `uint8_t`  | Leap from Network Time header.                                                                                                             |
| `NTP_MODE`       | `uint8_t`  | Mode from Network Time header.                                                                                                             |
| `NTP_VERSION`    | `uint8_t`  | Version from Network Time header.                                                                                                          |
| `NTP_STRATUM`    | `uint8_t`  | Stratum used to identify the distance from the reference clock.                                                                            |
| `NTP_POLL`       | `int8_t`   | The poll interval in seconds (as a power of 2) indicating how often the client queries the server.                                         |
| `NTP_PRECISION`  | `int8_t`   | The precision of the local clock, i.e., the smallest distinguishable time interval, usually expressed as a negative power of 2 in seconds. |
| `NTP_DELAY`      | `uint32_t` | The round-trip network delay between the client and the NTP server, measured in milliseconds or seconds.                                   |
| `NTP_DISPERSION` | `uint32_t` | The estimated error or uncertainty of the server's time relative to the true time, increases over time since last update.                  |
| `NTP_REF_ID`     | `string`   | Identifier of the reference clock or server the NTP server is synchronized to as a string.                                                 |
| `NTP_REF`        | `string`   | Timestamp of the last time the server clock was set or corrected as a string.                                                              |
| `NTP_ORIG`       | `string`   | Timestamp sent by the client in the request packet as a string.                                                                            |
| `NTP_RECV`       | `string`   | Timestamp when the request was received by the server as a string.                                                                         |
| `NTP_SENT`       | `string`   | Timestamp when the response was sent by the server as a string.                                                                            |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - ntp
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p ntp ...`
