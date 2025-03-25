---
title: QUIC
description: List of fields exported together with basic flow fields on interface by quic plugin. -with-quic-ch-full-tls-ext enables extraction of all TLS extensions in the Client Hello.
fields:
  -
    name: "QUIC_SNI"
    type: "string"
    ipfix: "8057/890"
    value: " 	Decrypted server name"
  -
    name: "QUIC_USER_AGENT"
    type: "string"
    ipfix: "8057/891"
    value: " 	Decrypted user agent"
  -
    name: "QUIC_VERSION"
    type: "uint32"
    ipfix: "8057/892"
    value: " 	QUIC version from first server long header packets"
  -
    name: "QUIC_CLIENT_VERSION"
    type: "uint32"
    ipfix: "8057/893"
    value: " 	QUIC version from first client long header packet"
  -
    name: "QUIC_TOKEN_LENGTH"
    type: "uint64"
    ipfix: "8057/894"
    value: " 	Token length from Initial and Retry packets"
  -
    name: "QUIC_OCCID"
    type: "bytes"
    ipfix: "8057/895"
    value: " 	Source Connection ID from first client packet"
  -
    name: "QUIC_OSCID"
    type: "bytes"
    ipfix: "8057/896"
    value: " 	Destination Connection ID from first client packet"
  -
    name: "QUIC_SCID"
    type: "bytes"
    ipfix: "8057/897"
    value: " 	Source Connection ID from first server packet"
  -
    name: "QUIC_RETRY_SCID"
    type: "bytes"
    ipfix: "8057/898"
    value: " 	Source Connection ID from Retry packet"
  -
    name: "QUIC_MULTIPLEXED"
    type: "uint8"
    ipfix: "8057/899"
    value: " 	> 0 if multiplexed (at least two different QUIC_OSCIDs or SNIs)"
  -
    name: "QUIC_ZERO_RTT"
    type: "uint8"
    ipfix: "8057/889"
    value: " 	Number of 0-RTT packets in flow."
  -
    name: "QUIC_SERVER_PORT"
    type: "uint16"
    ipfix: "8057/887"
    value: " 	TODO Server Port determined by packet type and TLS message"
  -
    name: "QUIC_PACKETS"
    type: "uint8*"
    ipfix: "0/291"
    value: " 	QUIC long header packet type (v1 encoded), version negotiation, QUIC bit"
  -
    name: "QUIC_CH_PARSED"
    type: "uint8"
    ipfix: "8057/886"
    value: " 	>0 if TLS Client Hello parsed without errors"
  -
    name: "QUIC_TLS_EXT_TYPE"
    type: "uint16*"
    ipfix: "0/291"
    value: " 	TLS extensions in the TLS Client Hello"
  -
    name: "QUIC_TLS_EXT_LEN"
    type: "uint16*"
    ipfix: "0/291"
    value: " 	Length of each TLS extension"
  -
    name: "QUIC_TLS_EXT"
    type: "string"
    ipfix: "8057/883"
    value: " 	Payload of all/application_layer_protocol_negotiation and quic_transport params TLS extension"
---
