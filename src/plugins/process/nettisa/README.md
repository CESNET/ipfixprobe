# NetTimeSeries Plugin

This plugin analyzes network data as time series, enabling more comprehensive and insightful analysis.

## Features

- Calculates and exports statistical properties of the flow based on packet lengths.

## Output Fields

| Field Name               | Data Type  | Description                                                                    |
| ------------------------ | ---------- | ------------------------------------------------------------------------------ |
| `NTS_MEAN`               | `float`    | Mean packet length over the flow duration.                                     |
| `NTS_MIN`                | `uint16_t` | Minimum packet length over the flow duration.                                  |
| `NTS_MAX`                | `uint16_t` | Maximum packet length over the flow duration.                                  |
| `NTS_STDEV`              | `float`    | Standard deviation of packet lengths over the flow duration.                   |
| `NTS_KURTOSIS`           | `float`    | Kurtosis of packet lengths over the flow duration.                             |
| `NTS_ROOT_MEAN_SQUARE`   | `float`    | Root mean square of packet lengths over the flow duration.                     |
| `NTS_AVERAGE_DISPERSION` | `float`    | Average dispersion of packet lengths over the flow duration.                   |
| `NTS_MEAN_SCALED_TIME`   | `float`    | Mean of packet lengths scaled by time over the flow duration.                  |
| `NTS_MEAN_DIFFTIMES`     | `float`    | Mean of time differences between packets over the flow duration.               |
| `NTS_MIN_DIFFTIMES`      | `float`    | Minimum of time differences between packets over the flow duration.            |
| `NTS_MAX_DIFFTIMES`      | `float`    | Maximum of time differences between packets over the flow duration.            |
| `NTS_TIME_DISTRIBUTION`  | `float`    | Sum of deviations from mean interpacket arrival times.                         |
| `NTS_SWITCHING_RATIO`    | `float`    | Ratio of packets when payload length changed in comparison to previous packet. |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - nettisa
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p nettisa ...`
