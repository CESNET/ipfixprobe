# QUIC Plugin

The **QUIC Plugin** parses QUIC packets and exports extracted values.

## Output Fields

| Field Name     | Data Type           | Description                                                          |
| -------------- | ------------------- | -------------------------------------------------------------------- |
| `TLS_SNI`      | `string`            | Subject Name Indentifier (SNI) from the TLS handshake                |
| `TLS_JA3`      | `string`            | JA3 fingerprint of the TLS Client Hello                              |
| `TLS_JA4`      | `string`            | JA4 fingerprint of the TLS Client Hello                              |
| `TLS_ALPN`     | `string`            | Application-Layer Protocol Negotiation (ALPN) from the TLS handshake |
| `TLS_VERSION`  | `uint16_t`          | TLS version used in the connection                                   |
| `TLS_EXT_TYPE` | `array of uint16_t` | Types of TLS extensions in the Client Hello                          |
| `TLS_EXT_LEN`  | `array of uint16_t` | Lengths of TLS extensions in the Client Hello                        |
| `TLS_EXT`      | `array of bytes`    | Payload of TLS extensions in the Client Hello                        |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - tls
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p tls ...`
