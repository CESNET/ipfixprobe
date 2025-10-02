# DNS Plugin

The **DNS Plugin** is a module for the IPFIXprobe exporter, designed to analyze DNS traffic.

## Features

- Extends basic flow export data. 
- Extracts and exports additional fields from network flows.


## Output Fields

| Field Name      | Data Type | Description                                                 |
|-----------------|-----------|-------------------------------------------------------------|
| IP_TTL          | uint8_t   | IP time-to-live in source-to-destination direction          |
| IP_TTL_REV      | uint8_t   | IP time-to-live in destination-to-source direction          |
| IP_FLG          | uint8_t   | IP flags in source-to-destination direction                 |
| IP_FLG_REV      | uint8_t   | IP flags in destination-to-source direction                 |
| TCP_WIN         | uint16_t  | TCP window size in source-to-destination direction          |
| TCP_WIN_REV     | uint16_t  | TCP window size in destination-to-source direction          |
| TCP_OPT         | uint64_t   | TCP options in source-to-destination direction              |
| TCP_OPT_REV     | uint64_t   | TCP options in destination-to-source direction              |
| TCP_MSS         | uint32_t  | TCP maximum segment size in source-to-destination direction |
| TCP_MSS_REV     | uint32_t  | TCP maximum segment size in destination-to-source direction |
| TCP_SYN_SIZE    | uint16_t  | TCP syn packet size (only one in bidirectional flow)        |

## Usage

Once enabled, the plugin will automatically process flows and add the export fields to each record.

1. ``` make install ```.
2. ``` ipfixprobe -p "basicplus" ... " ```
3. Extracted values are exported to the output interface.

## Support

For issues or feature requests, please open an issue in the [IPFIXprobe repository](https://github.com/CESNET/ipfixprobe).
