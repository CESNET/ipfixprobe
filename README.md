<div align="center">
<picture>
  <source srcset="https://raw.githubusercontent.com/CESNET/ipfixprobe/refs/heads/master/docs/images/logo/logo_horizontal_white.svg" width="450" media="(prefers-color-scheme: dark)">
  <img src="https://raw.githubusercontent.com/CESNET/ipfixprobe/refs/heads/master/docs/images/logo/logo_horizontal_color.svg" width="450">
</picture>
</div>
</br>

The ipfixprobe is a high-performance, modular flow exporter that processes packets into bidirectional flows and exports them via a selected output plugin.
It supports a wide range of application-layer protocol parsers, including TLS, QUIC, HTTP, DNS, and many others. These protocol-specific extensions can be enabled via process plugins in the configuration.

Need more details? Check out our [documentation](https://ipfixprobe.cesnet.cz) for a full list of supported protocols and usage examples.

[![](https://img.shields.io/badge/license-BSD-blue.svg)](https://github.com/CESNET/ipfixprobe/blob/master/LICENSE)
[![](https://img.shields.io/badge/docs-ipfixprobe-blue.svg)](https://ipfixprobe.cesnet.cz)
![Coverity Scan](https://img.shields.io/coverity/scan/22112)
![GitHub top language](https://img.shields.io/github/languages/top/CESNET/ipfixprobe)

## ✨ Key Features

- Modular input–parser–output architecture
- High-speed processing (DPDK, multi-threaded, NUMA-aware)
- Built-in protocol parsers: TLS, QUIC, HTTP, DNS, …
- Bidirectional flow (biflow) support
- Real-time telemetry and statistics

## 📦 Installation

If you are running a RHEL system or one of its derivatives (e.g. Oracle Linux, Rocky Linux, CentOS Stream), the easiest way to install
ipfixprobe is from our [copr repository](https://copr.fedorainfracloud.org/coprs/g/CESNET/ipfixprobe/).

```bash
$ dnf install dnf-plugins-core # Extra step necessary on some systems
$ dnf copr enable @CESNET/ipfixprobe
$ dnf install ipfixprobe
```

This installs the main `ipfixprobe` binary along with core functionality.

#### 🗃️ Available Packages

The Copr repository provides modular RPM packages, so you can install only what you need.
The following packages are available and can be installed individually as needed:

| Package Name                                | Description                                                                 |
|---------------------------------------------|-----------------------------------------------------------------------------|
| `ipfixprobe`                                | Core binary with common process/output plugins. |
| `ipfixprobe-msec`                           | Core binary with common process/output plugins. Uses millisecond timestamps (compatible with Flowmon collector) |
| `ipfixprobe-input-pcap`                     | Input plugin for PCAP files and live capture                               |
| `ipfixprobe-input-dpdk`                     | High-speed input plugin using DPDK                                         |
| `ipfixprobe-input-nfb`                      | Input plugin for CESNET NFB/NDP cards                                      |
| `ipfixprobe-process-experimental`           | Extra (possibly unstable) process plugins                                  |

For other systems, follow the build instructions below.

## 🛠️ Build

You can build ipfixprobe from source using standard CMake.
This lets you customize the build by enabling optional plugins and features as needed.

**Note:** Some plugins may require additional dependencies beyond the basic requirements.

### RHEL/CentOS:

#### 🧰 Requirements

```bash
$ dnf install epel-release git make cmake gcc-c++ rpm-build
$ dnf install libunwind-devel lz4-devel openssl-devel fuse3-devel

# for RHEL 8/9
$ dnf install gcc-toolset-14-libatomic-devel

# for RHEL 10+
$ dnf install libatomic
```

### Debian/Ubuntu:

#### 🧰 Requirements

```bash
$ apt install git make cmake g++ pkg-config rpm
$ apt install libunwind-dev liblz4-dev libssl-dev libfuse3-dev libatomic1
```

#### 🧱 Build steps

```bash
git clone https://github.com/CESNET/ipfixprobe.git
cd ipfixprobe
mkdir build && cd build
cmake ..
make -j$(nproc)
# make install
```

#### ⚙️ Optional build flags
You can enable or disable optional plugins and features via CMake flags:

| Flag                               | Default | Description                                                      |
| ---------------------------------- | ------- | ---------------------------------------------------------------- |
| `-DENABLE_MILLISECONDS_TIMESTAMP=ON` | OFF     | Use millisecond precision timestamps (for Flowmon compatibility) |
| `-DENABLE_INPUT_PCAP=ON`             | OFF     | Enable PCAP input plugin (live & file) (requires `libpcap`)    |
| `-DENABLE_INPUT_DPDK=ON`             | OFF     | Enable high-speed DPDK input plugin    (requires `dpdk-devel`) |
| `-DENABLE_INPUT_NFB=ON`              | OFF     | Enable input plugin for CESNET NFB/NDP cards (requires `netcope-common`) |
| `-DENABLE_PROCESS_EXPERIMENTAL=ON`   | OFF     | Enable experimental process plugins                            |
| `-DENABLE_NEMEA=ON`                  | OFF     | Enable support for NEMEA modules (requires `nemea-framework-devel` ) |

Run the command to view all available build options:

```bash
cmake -LAH
```

#### Example
To build with DPDK and PCAP input support, and install to /usr:

```cmake
cmake .. \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DENABLE_INPUT_PCAP=ON \
  -DENABLE_INPUT_DPDK=ON
```


## 🧩 Available Plugins

### Input Plugins
List of input plugins with estimated performance and configuration complexity.

| Plugin        | Max Throughput | Usage Complexity | Description                               |
|---------------|----------------|------------------|-------------------------------------------|
| [`pcap_live`](./src/plugins/input/pcap/README.md#pcap-live-input-plugin) | ~1 Gbps   | Easy    | captures packets from a live network interface |
| [`pcap_file`](./src/plugins/input/pcap/README.md#pcap-file-input-plugin) | ~1 Gbps   | Easy    | reads packets from an offline PCAP file       |
| [`raw`](./src/plugins/input/raw/README.md)                               | ~1 Gbps   | Easy    | captures packets using a raw socket           |
| [`ndp`](./src/plugins/input/nfb/README.md)                               | 400 Gbps  | Medium  | uses CESNET NFB/NDP hardware for packet input |
| [`dpdk`](./src/plugins/input/dpdk/README.md#dpdk-input-plugin)           | 400 Gbps  | Complex | receives packets via high-performance DPDK    |
| [`dpdk-ring`](./src/plugins/input/dpdk/README.md)                        | 400 Gbps  | Complex | receives packets from a shared DPDK memory ring |

---

### Process Plugins

These plugins extract protocol-specific or behavioral information from packets and enrich flow records with metadata.

| Plugin        | Description                                                  |
|---------------|--------------------------------------------------------------|
| [`basic`](./src/plugins/process/basic/README.md)           | extracts basic L3/L4 flow fields (IPs, ports, protocol)      |
| [`icmp`](./src/plugins/process/icmp/README.md)             | extracts ICMP type/code and related metadata                 |
| [`http`](./src/plugins/process/http/README.md)             | extracts HTTP methods, hosts, URIs, status codes             |
| [`tls`](./src/plugins/process/tls/README.md)               | extracts TLS handshake info (SNI, version, JA3, etc.)        |
| [`ovpn`](./src/plugins/process/ovpn/README.md)             | extracts metadata from OpenVPN tunnels                       |
| [`wg`](./src/plugins/process/wg/README.md)                 | parses WireGuard handshake and endpoint metadata             |
| [`quic`](./src/plugins/process/quic/README.md)             | parses QUIC protocol including SNI, versions, ALPN           |
| [`basicplus`](./src/plugins/process/basicplus/README.md)   | adds common L3/L4 flow fields (e.g., ports, IPs, TCP flags)  |
| [`bstats`](./src/plugins/process/bstats/README.md)         | basic flow statistics (packet/byte counters, duration, ...)  |
| [`dns`](./src/plugins/process/dns/README.md)               | extracts DNS queries, responses, and domains                 |
| [`dnssd`](./src/plugins/process/dnssd/README.md)           | parses DNS Service Discovery (mDNS) traffic                  |
| [`flowHash`](./src/plugins/process/flowHash/README.md)     | extracts a flow hash                                         |
| [`idpContent`](./src/plugins/process/idpContent/README.md) | parses IDP content in flows                                  |
| [`mpls`](./src/plugins/process/mpls/README.md)             | extracts MPLS labels and encapsulation metadata              |
| [`mqtt`](./src/plugins/process/mqtt/README.md)             | parses MQTT protocol traffic (IoT messaging)                 |
| [`netbios`](./src/plugins/process/netbios/README.md)       | extracts NetBIOS session and name service info               |
| [`nettisa`](./src/plugins/process/nettisa/README.md)       | parses NETTISA related metadata (experimental)               |
| [`ntp`](./src/plugins/process/ntp/README.md)               | extracts NTP timestamps and server info                      |
| [`osquery`](./src/plugins/process/osquery/README.md)       | parses osquery-generated data streams                        |
| [`passiveDns`](./src/plugins/process/passiveDns/README.md) | generates passive DNS entries from observed DNS traffic      |
| [`phists`](./src/plugins/process/phists/README.md)         | parses phishing-related signatures (heuristic)               |
| [`pstats`](./src/plugins/process/pstats/README.md)         | advanced packet statistics (e.g., inter-packet gaps)         |
| [`rtsp`](./src/plugins/process/rtsp/README.md)             | extracts RTSP stream metadata                                |
| [`sip`](./src/plugins/process/sip/README.md)               | parses SIP call setup, headers, and codecs                   |
| [`smtp`](./src/plugins/process/smtp/README.md)             | extracts SMTP envelope data (from, to, subject, etc.)        |
| [`ssaDetector`](./src/plugins/process/ssaDetector/README.md) | performs simple anomaly detection based on traffic patterns |
| [`ssdp`](./src/plugins/process/ssdp/README.md)             | parses SSDP (UPnP discovery) protocol                        |
| [`vlan`](./src/plugins/process/vlan/README.md)             | extracts VLAN IDs and QinQ encapsulation                     |

---
### Output Plugins

These plugins export flow records to various formats and external systems.

| Plugin        | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| [`ipfix`](./src/plugins/output/ipfix/README.md)     | exports flow records in IPFIX format to a remote collector (UDP/TCP) |
| [`text`](./src/plugins/output/text/README.md)       | writes flow records in human-readable text to a file or stdout |
| [`unirec`](./src/plugins/output/unirec/README.md)   | exports flow records using the UniRec format for NEMEA/TRAP ecosystem |

---

## 📘 Usage

The `ipfixprobe` processing pipeline can be launched directly or via the `ipfixprobed` wrapper — a lightweight runtime designed to simplify plugin configuration using YAML files.
This method is preferred for production deployments due to its clarity and flexibility.

### ✅ Recommended (YAML-based configuration)

```bash
/usr/bin/ipfixprobed <CONFIG_NAME> [LIBRARY_PATH]
```

- `<CONFIG_NAME>` – Name of the YAML configuration file (without the .conf extension).
The full path must be `/etc/ipfixprobe/<CONFIG_NAME>.conf`.

- `[LIBRARY_PATH]` – (Optional) Path to the ipfixprobe plugin library directory.
If not provided, the default `/usr/lib64/ipfixprobe` is used.

#### Example:
```bash
/usr/bin/ipfixprobed example
```

This will run `ipfixprobe` using the YAML configuration from `/etc/ipfixprobe/example.conf`.

👉 See the full YAML configuration reference here: https://github.com/CESNET/ipfixprobe/blob/master/init/link0.conf.example

### ⚠️ Legacy usage (CLI parameters)

You may also run the processing pipeline using the `ipfixprobe` binary directly, with CLI parameters.
This method is not recommended for production use, as it lacks flexibility and clarity.

```bash
/usr/bin/ipfixprobe [OPTIONS]
```

#### Available options:

- `-i ARGS`       Activate input plugin  (`-h input` for help)
- `-s ARGS`       Activate storage plugin (`-h storage` for help)
- `-o ARGS`       Activate output plugin (`-h output` for help)
- `-p ARGS`       Activate processing plugin (`-h process` for help)
- `-q SIZE`       Size of queue between input and storage plugins
- `-b SIZE`       Size of input queue packet block
- `-Q SIZE`       Size of queue between storage and output plugins
- `-B SIZE`       Size of packet buffer
- `-f NUM`        Export max flows per second
- `-c SIZE`       Quit after number of packets are processed on each interface
- `-P FILE`       Create a PID file
- `-t PATH`       Mount point of AppFs telemetry directory
- `-d`            Run as a standalone process
- `-h [PLUGIN]`   Print help text. Supported help for input, storage, output and process plugins
- `-V`            Show version and exit

## 📖 Examples
Below are practical examples showcasing common plugin configurations using both CLI and YAML formats.

#### **🔹 Basic Interface Capture**
Capture network traffic from the `wlp2s0` interface using a raw socket. Flow records are printed in plain-text format to the console.

🧪 Command-line usage:
```bash
/usr/bin/ipfixprobe -i 'raw;ifc=wlp2s0' -o 'text'
```

📄 Equivalent YAML configuration:
```yaml
input_plugin:
  raw:
    interface: 'wlp2s0'

output_plugin:
  text: {}
```

----

#### **🔹 PCAP File → IPFIX Collector**
Process packets from a `.pcap` file and export flows via IPFIX over UDP

🧪 Command-line usage:
```bash
/usr/bin/ipfixprobe -i 'pcap;file=/data/capture.pcap' -o 'ipfix;udp;host=collector.example.com;port=4739'
```

📄 Equivalent YAML configuration:
```yaml
input_plugin:
  pcap_file:
    file: '/data/capture.pcap'
output_plugin:
  ipfix:
    collector:
      host: collector.example.com
      port: 4739
    protocol:
      udp: {}
```

----

#### **🔹Live Capture with Cache Configuration and Telemetry**
Capture from `eth0` interface using libpcap, split biflows into uniflows and use active/inactive timeouts, print flows to console.
Telemetry data are exposed via the appFs library in `/var/run/ipfixprobe` directory.

🧪 Command-line usage:
```bash
/usr/bin/ipfixprobe -i 'pcap;ifc=eth0' -s 'cache;split;active=300;inactive=60' -o 'text' -t /var/run/ipfixprobe
```

📄 Equivalent YAML configuration:
```yaml
input_plugin:
  pcap_live:
    interface: 'eth0'

storage:
  cache: {}
  timeouts:
    active: 300
    inactive: 60
  split_biflow: true

output_plugin:
  text: {}

telemetry:
  appfs:
    enabled: true
    mount_point: /var/run/ipfixprobe
```

----

#### 🔹 High-speed DPDK Capture with HTTP, TLS, and QUIC Processing
Capture packets using DPDK from port 0 with 2 queues bound to a specific PCI device (`0000:17:00.0`), enable HTTP, TLS, and QUIC process plugins, and export flows via IPFIX to a local collector at 127.0.0.1.

🧪 Command-line usage:
```bash
/usr/bin/ipfixprobe -i "dpdk;p=0;q=2;e=-a 0000:17:00.0" -i dpdk -p http -p tls -p quic -o "ipfix;h=127.0.0.1"
```

📄 Equivalent YAML configuration:
```yaml
input_plugin:
  dpdk:
    allowed_nics: "0000:17:00.0"
    rx_queues: 2

process_plugins:
  - http
  - tls
  - quic

output_plugin:
  ipfix:
    collector:
      host: '127.0.0.1'
      port: 4739
    protocol:
      udp: {}
```

## 📊 Telemetry

## 🧪 Testing & Validation

## 🧰 FAQ
