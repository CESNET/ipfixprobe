# MQTT Plugin

The **MQTT Plugin** extends flow records with MQTT (Message Queuing Telemetry Transport) message information.

## Features

- Extracts and exports MQTT fields if flow contains MQTT information.
- Only MQTT v3.1.1 and v5.0 are supported.
- Flow is finished when *disconect* message is received.

## Parameters

| Long name | Short name | Type   | Default | Description                                                 |
|-----------|------------|--------|---------|-------------------------------------------------------------|
| `tc`     | `topiccount`       | `int`   | 10 | Maximal count of topics from *publish* messages to save |

## Output Fields

	MQTT_TYPE_CUMULATIVE = 0,
	MQTT_VERSION,
	MQTT_CONNECTION_FLAGS,
	MQTT_KEEP_ALIVE,
	MQTT_CONNECTION_RETURN_CODE,
	MQTT_PUBLISH_FLAGS,
	MQTT_TOPICS,


| Field Name      | Data Type | Description                                                 |
|-----------------|-----------|----------------------------------------|
| `MQQT_TYPE_CUMULATIVE`| `uint16_t`  | Bitfield of messages that were detected during the communication.
DISCONNECT \| PINGRESP(1b) \| PINGREQ(1b) \| UNSUBACK(1b) \| UNSUBSCRIBE(1b) /|
	SUBACK(1b) | SUBSCRIBE(1b) | PUBCOMP(1b) | PUBREL(1b) | PUBREC(1b) | PUBACK(1b) | PUBLISH(1b) |
	CONNACK(1b) | CONNECT(1b) | session present(1b) | 
| `MQTT_VERSION`| `uint8_t`  |  |
| `MQTT_CONNECTION_FLAGS`| `uint8_t`  |  |
| `MQTT_KEEP_ALIVE`| `uint8_t`  |  |
| `MQTT_VERSION`| `uint8_t`  |  |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - dnssd
```

### CLI Usage

You can also enable the plugin directly from the command line:

```ipfixprobe -p dnssd ...```
```ipfixprobe -p "dnssd;txt" ...```
```ipfixprobe -p "dnssd;txt=<path_to_file>" ...```
