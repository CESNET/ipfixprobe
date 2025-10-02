# BurstStats Plugin

The **BurstStats Plugin** is a module for the IPFIXprobe exporter, designed to analyze packet burst statistics.

## Features

- Consider packet to be a part of burst if it arrives within short time interval after previous packet.
- Extracts and exports burst statistics from network flows. 

## Output Fields

| Field Name      | Data Type | Description                                                 |
|-----------------|-----------|-------------------------------------------------------------|
| SBI_BRST_PACKETS| uint32_t  | Array of packets in each burst in source-to-destination direction                  |
| SBI_BRST_BYTES  | uint32_t  | Array of bytes in each burst in source-to-destination direction                    |
| SBI_BRST_TIME_START | Timestamp | Array of burst start times in source-to-destination direction                   |
| SBI_BRST_TIME_STOP  | Timestamp | Array of burst end times in source-to-destination direction                     |
| DBI_BRST_PACKETS| uint32_t  | Array of packets in each burst in destination-to-source direction                  |
| DBI_BRST_BYTES  | uint32_t  | Array of bytes in each burst in destination-to-source direction                    |
| DBI_BRST_TIME_START | Timestamp | Array of burst start times in destination-to-source direction                   |
| DBI_BRST_TIME_STOP  | Timestamp | Array of burst end times in destination-to-source direction                     |

## Usage

Once enabled, the plugin will automatically process flows and add the export fields to each record.

1. ``` make install ```.
2. ``` ipfixprobe -p "bstats" ... " ```
3. Extracted values are exported to the output interface.

## Support

For issues or feature requests, please open an issue in the [IPFIXprobe repository](https://github.com/CESNET/ipfixprobe).
