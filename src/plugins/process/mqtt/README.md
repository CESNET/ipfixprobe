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

| Field Name      | Data Type | Description                                                 |
|-----------------|-----------|----------------------------------------|
| `MQQT_TYPE_CUMULATIVE`| `uint16_t`  | Bitfield of messages that were detected during the communication. Each value takes 1 bit. 
DISCONNECT \| PINGRESP \| PINGREQ \| UNSUBACK \| UNSUBSCRIBE \|
	SUBACK \| SUBSCRIBE \| PUBCOMP \| PUBREL \| PUBREC \| PUBACK \| PUBLISH \|
	CONNACK \| CONNECT \| session present flag from *connection* message\|
| `MQTT_VERSION`| `uint8_t`  | Identifies the MQTT version being used. |
| `MQTT_CONNECTION_FLAGS`| `uint8_t`  | Flags of *connection* message. |
| `MQTT_KEEP_ALIVE`| `uint16_t`  | MQTT connection keep alive |
| `MQTT_CONNECTION_RETURN_CODE`| `uint8_t`  | Return code value from *connack* message. |
| `MQTT_PUBLISH_FLAGS`| `uint8_t`  | Cumulative of *publish* message flags. |
| `MQTT_TOPICS`| `string`  | Concatenation of **topiccount** topics from *publish* messages. |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - mqtt 
```

### CLI Usage

You can also enable the plugin directly from the command line:

```ipfixprobe -p mqtt ...```
```ipfixprobe -p "mqtt;tc=<topic_count>" ...```
