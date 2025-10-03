# NetworkTime Plugin

Plugin extract and export various data from NTP packets.

## Features

- Calculates and exports statistical properties of the flow based on packet lengths.
- Expects traffic to be on port 123.
- Immediately terminates the flow after processing the first NTP packet.

## Output Fields

NTP_LEAP = 0,

    NTP_VERSION,
    NTP_MODE,
    NTP_STRATUM,
    NTP_POLL,
    NTP_PRECISION,
    NTP_DELAY,
    NTP_DISPERSION,
    NTP_REF_ID,
    NTP_REF,
    NTP_ORIG,
    NTP_RECV,
    NTP_SENT

| Field Name | Data Type | Description     |
| ---------- | --------- | --------------- |
| `NTP_LEAP` | `uint8_t` | Leap indicator. |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - nettisa
```

### CLI Usage

You can also enable the plugin directly from the command line:

```
ipfixprobe -p nettisa ...
```
