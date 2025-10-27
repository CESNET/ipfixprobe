# OSQuery Plugin

Plugin for querying operating system about the flows.

## Features

- Uses osqueryi to query the operating system and exports relevant information.

## Output Fields

| Field Name                 | Data Type  | Description                               |
| -------------------------- | ---------- | ----------------------------------------- |
| `OSQUERY_PROGRAM_NAME`     | `string`   | Name of the program generating the flow.  |
| `OSQUERY_USERNAME`         | `string`   | Username of the user running the program. |
| `OSQUERY_OS_NAME`          | `string`   | Operating system name.                    |
| `OSQUERY_OS_MAJOR`         | `uint16_t` | Operating system major version.           |
| `OSQUERY_OS_MINOR`         | `uint16_t` | Operating system minor version.           |
| `OSQUERY_OS_BUILD`         | `string`   | Operating system build.                   |
| `OSQUERY_OS_PLATFORM`      | `string`   | Operating system platform.                |
| `OSQUERY_OS_PLATFORM_LIKE` | `string`   | Windows/Linux/Darwin.                     |
| `OSQUERY_OS_ARCH`          | `string`   | Operating system architecture.            |
| `OSQUERY_KERNEL_VERSION`   | `string`   | Operating system kernel version.          |
| `OSQUERY_SYSTEM_HOSTNAME`  | `string`   | System hostname.                          |

## Usage

### YAML Configuration

Add the plugin to your ipfixprobe YAML configuration:

```yaml
process_plugins:
  - osquery
```

### CLI Usage

You can also enable the plugin directly from the command line:

`ipfixprobe -p osquery ...`
