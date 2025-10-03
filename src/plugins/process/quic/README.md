# QUIC Plugin

The **QUIC Plugin** parses QUIC packets and exports extracted values.

## Features

- Removes plugin data if some parsing fails.
- Allocates memory only if the flow is considered to belong to QUIC.

## Output Fields

| Field Name            | Data Type           | Description                                                     |
| --------------------- | ------------------- | --------------------------------------------------------------- |
| `QUIC_SNI`            | `string`            | Subject Name Indentifier (SNI) from the QUIC handshake          |
| `QUIC_USER_AGENT`     | `string`            | User Agent from the QUIC handshake                              |
| `QUIC_VERSION`        | `uint32_t`          | QUIC version used in the connection                             |
| `QUIC_CLIENT_VERSION` | `uint32_t`          | QUIC version used by the client                                 |
| `QUIC_TOKEN_LENGTH`   | `uint16_t`          | Length of the token used in the handshake                       |
| `QUIC_OCCID`          | `string`            | Original Connection ID used in the handshake                    |
| `QUIC_OSCID`          | `string`            | Original Source Connection ID used in the handshake             |
| `QUIC_SCID`           | `string`            | Source Connection ID used in the handshake                      |
| `QUIC_RETRY_SCID`     | `string`            | Source Connection ID from the Retry packet                      |
| `QUIC_MULTIPLEXED`    | `uint8_t`           | Whether the connection is multiplexed (1) or not (0)            |
| `QUIC_ZERO_RTT`       | `uint8_t`           | Whether 0-RTT was used (1) or not (0)                           |
| `QUIC_SERVER_PORT`    | `uint16_t`          | Server port used in the connection                              |
| `QUIC_PACKETS`        | `array of uint8_t`  | Cumulative of header types observed in each QUIC packet         |
| `QUIC_CH_PARSED`      | `uint8_t`           | Whether the Client Hello was successfully parsed (1) or not (0) |
| `QUIC_TLS_EXT_TYPE`   | `array of uint16_t` | Types of TLS extensions in the Client Hello                     |
| `QUIC_TLS_EXT_LEN`    | `array of uint16_t` | Lengths of TLS extensions in the Client Hello                   |
| `QUIC_TLS_EXT`        | `array of bytes`    | Data of TLS extensions in the Client Hello                      |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - quic
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p quic ...`
