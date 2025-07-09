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
|--------------------------------------------|-----------------------------------------------------------------------------|
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

TODO

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



## 🔧 Parameters
### Module specific parameters
- `-i ARGS`       Activate input plugin  (-h input for help)
- `-s ARGS`       Activate storage plugin (-h storage for help)
- `-o ARGS`       Activate output plugin (-h output for help)
- `-p ARGS`       Activate processing plugin (-h process for help)
- `-q SIZE`       Size of queue between input and storage plugins
- `-b SIZE`       Size of input queue packet block
- `-Q SIZE`       Size of queue between storage and output plugins
- `-B SIZE`       Size of packet buffer
- `-f NUM`        Export max flows per second
- `-c SIZE`       Quit after number of packets are processed on each interface
- `-P FILE`       Create pid file
- `-t PATH`       Mount point of AppFs telemetry directory
- `-d`            Run as a standalone process
- `-h [PLUGIN]`   Print help text. Supported help for input, storage, output and process plugins
- `-V`            Show version and exit

### ❓ Help
Printing general help is done using the `-h` parameter. To print help for specific plugins, `-h` with parameter is used.
This parameter accepts `input`, `storage`, `process`, `output` or name of a plugin (or path to a .so file with plugin).

## 📖 Example
Here are the examples of various plugins usage:
```bash
# Capture from wlp2s0 interface using raw sockets, print flows to console
./ipfixprobe -i 'raw;ifc=wlp2s0' -o 'text'

# Capture from wlp2s0 interface and scale packet processing using 2 instances of plugins, send flow to ifpfix collector using UDP
./ipfixprobe -i 'raw;ifc=wlp2s0;f' -i 'raw;ifc=wlp2s0;f' -o 'ipfix;u;host=collector.example.com;port=4739'

# Capture from a COMBO card using ndp plugin, sends ipfix data to 127.0.0.1:4739 using TCP by default
./ipfixprobe -i 'ndp;dev=/dev/nfb0:0' -i 'ndp;dev=/dev/nfb0:1' -i 'ndp;dev=/dev/nfb0:2'

# Capture from eth0 interface using pcap plugin, split biflows into flows and prints them to console without mac addresses, telemetry data are exposed via the appFs library in /var/run/ipfixprobe directory
./ipfixprobe -i 'pcap;ifc=eth0' -s 'cache;split' -o 'text;m' -t /var/run/ipfixprobe

# Read packets from pcap file, enable 4 processing plugins, sends L7 HTTP extended biflows to unirec interface named `http` and data from 3 other plugins to the `stats` interface
./ipfixprobe -i 'pcap;file=pcaps/http.pcap' -p http -p pstats -p idpcontent -p phists -o 'unirec;i=u:http:timeout=WAIT,u:stats:timeout=WAIT;p=http,(pstats,phists,idpcontent)'

# Read packets using DPDK input interface and 1 DPDK queue, enable plugins for basic statistics, http and tls, output to IPFIX on a local machine
# DPDK EAL parameters are passed in `e, eal` parameters
# DPDK plugin configuration has to be specified in the first input interface.
# The following `dpdk` interfaces are given without parameters; their configuration is inherited from the first one.
# Example for the queue of 3 DPDK input plugins (q=3):
`./ipfixprobe -i "dpdk;p=0;q=3;e=-c 0x1 -a  <[domain:]bus:devid.func>" -i dpdk -i dpdk -p http "-p" bstats -p tls -o "ipfix;h=127.0.0.1"`

# Same example for the multiport read from ports 0 and 1, note comma separated ports:
`./ipfixprobe -i "dpdk;p=0,1;q=3;e=-c 0x1 -a  <[domain:]bus:devid.func>" -i dpdk -i dpdk -p http "-p" bstats -p tls -o "ipfix;h=127.0.0.1"`


# Read packets using DPDK input interface as secondary process with shared memory (DPDK rings) - in this case, 4 DPDK rings are used
`./ipfixprobe -i 'dpdk-ring;r=rx_ipfixprobe_0;e= --proc-type=secondary' -i 'dpdk-ring;r=rx_ipfixprobe_1' -i 'dpdk-ring;r=rx_ipfixprobe_2' -i 'dpdk-ring;r=rx_ipfixprobe_3' -o 'text'`
```

## Build

### 📦 Requirements

- `libatomic`
- [telemetry](https://github.com/CESNET/telemetry) (**required**) Installable from the [COPR repository](https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA-stable/package/telemetry/) or buildable from source
- Linux kernel version **≥ 3.19**
- [libpcap](http://www.tcpdump.org/) — required for PCAP input plugin (`-DENABLE_INPUT_PCAP`)
- `netcope-common` — required for NDP input plugin with [COMBO cards](https://www.liberouter.org/technologies/cards/) (`-DENABLE_INPUT_NFB`)
- `libunwind-devel`
- [NEMEA](http://github.com/CESNET/Nemea-Framework) — required for UniRec output plugin (`-DENABLE_NEMEA`, `-DENABLE_OUTPUT_UNIREC`)
- [DPDK](http://core.dpdk.org/download/) — required for DPDK input plugin (`-DENABLE_INPUT_DPDK`)

> For most conventional monitoring use-cases (not requiring high-speed packet libraries like DPDK or NDP), you can install required dependencies using the following commands:

#### 🐧 RHEL9-based distributions

```bash
sudo yum-config-manager --add-repo https://yum.oracle.com/repo/OracleLinux/OL9/codeready/builder/x86_64/
sudo dnf copr enable @CESNET/NEMEA-stable
sudo dnf install -y git wget curl net-tools gcc gcc-c++ \
    libtool lz4-devel rpm-build fuse3-devel make cmake rpm \
    libatomic libunwind-devel openssl-devel pkgconf-pkg-config \
    telemetry gcc-toolset-14-libatomic-devel
```

---

### ⚙️ Project build with CMake

This project uses the standard CMake build system. Example setup:

```bash
git clone --recurse-submodules https://github.com/CESNET/ipfixprobe
cd ipfixprobe
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
```

#### 🔧 Notable CMake Build Options

Run the command to view all available build options:

```bash
cmake -LAH
```

The most notable options are:

| Option                          | Description                                                              |
|--------------------------------|--------------------------------------------------------------------------|
| `ENABLE_MILISECONDS_TIMESTAMPS`| Enable millisecond timestamp precision                                   |
| `ENABLE_NEMEA`                 | Enable support for NEMEA modules                                         |
| `ENABLE_RPMBUILD`              | Enable building of RPM packages (enabled by default)                     |
| `ENABLE_TESTS`                 | Enable building of unit and integration tests                            |
| `ENABLE_INPUT_PCAP`            | Build PCAP input plugin (requires `libpcap`)                             |
| `ENABLE_INPUT_NFB`             | Build NFB input plugin (requires `netcope-common`)                       |
| `ENABLE_INPUT_DPDK`            | Build DPDK input plugin (requires `dpdk`)                                |


---

#### 🛠️ Build from Source

Once the CMake project is configured, build the project using:

```bash
make -j
```

The resulting binary will be located at:

```bash
ipfixprobe/build/src/core/ipfixprobe
```

To install the binary system-wide:

```bash
make install
```

---

#### 📦 Build RPM Packages

RPM packages are created automatically based on the enabled CMake options.

If the project is configured with `ENABLE_RPMBUILD` (enabled by default), you can build RPM packages using:

```bash
make -j rpm
```

The resulting RPM files will be located in:

```
ipfixprobe/build/pkg/rpm/rpmbuild/
```

## 📈 Telemetry

`ipfixprobe` exports statistics and other diagnostic information through a telemetry interface based on appFs library, which leverages the fuse3 library (filesystem in userspace) to allow telemetry data to be accessed and manipulated
through standard filesystem operations.

```
/var/run/ipfixprobe/
├── output
│   └── ipxRing
│       └── stats
└── pipeline
    └── queues
        ├── 0
        │   ├── cache-stats
        │   ├── fragmentation-cache-stats
        │   ├── input-stats
        │   └── parser-stats
        ├── 1
        ...
```

From telemetry stats you can read:

**Output Directory:**

In the output directory, you can monitor the capacity and current usage of the ipxRing. This helps determine whether the output plugin can export flows quickly enough or if there are bottlenecks caused by insufficient ring capacity.

***Example: ipxRing/stats***
```
count: 204
size:  16536
usage: 1.23 (%)
```

**Pipeline Directory:**

The pipeline directory provides statistics for all worker queues. Each queue is identified by its ID (e.g., 0, 1) and includes the following files:
- cache-stats: Provides detailed metrics about flow cache usage and exported flow statistics.

    ***Example:***

    ```
    FlowCacheUsage:                 3.81 (%)
    FlowEndReason:ActiveTimeout:    34666654
    FlowEndReason:Collision:        4272143
    FlowEndReason:EndOfFlow:        486129363
    FlowEndReason:Forced:           58905
    FlowEndReason:InactiveTimeout:  2169352600
    FlowRecordStats:11-20packets:   178735501
    FlowRecordStats:1packet:        1824500140
    FlowRecordStats:2-5packets:     376268956
    FlowRecordStats:21-50packets:   87971544
    FlowRecordStats:51-plusPackets: 55424342
    FlowRecordStats:6-10packets:    171579322
    FlowsInCache:                   39986
    TotalExportedFlows:             2694479805
    ```

- fragmentation-cache-stats: Provides metrics related to packet fragmentation.

    ***Example:***

    ```
    firstFragments:    163634416
    fragmentedPackets: 395736897
    fragmentedTraffic: 0.13 (%)
    notFoundFragments: 85585913
    totalPackets:      314829930486
    ```

- input-stats: Provides metrics on the data received by by the queue.

    ***Example:***
    ```
    received_bytes:   388582006601530
    received_packets: 314788702409
    ```


- parser-stats: Provides detailed information about the types of packets processed by the parser.

    ***Example:***
    ```
    ipv4_packets:    193213761481
    ipv6_packets:    121566104060
    mpls_packets:    0
    pppoe_packets:   0
    seen_packets:    314791928764
    tcp_packets:     301552123188
    trill_packets:   0
    udp_packets:     12783568334
    unknown_packets: 11601117
    vlan_packets:    31477986554
    ```


## 📥 Input / Output of the flow exporter

The availability of input and output types depends on the installed packages or enabled build options (see section of README Project Setup with CMake).
By default, installing the `ipfixprobe` package enables standard raw socket output.

To enable additional input capabilities, install the corresponding input plugin packages:

- `ipfixprobe-input-dpdk` – enables DPDK input support
- `ipfixprobe-input-nfb` – enables NFB input support
- `ipfixprobe-input-pcap` – enables libpcap input support

For more information, visit the [input plugin documentation](https://ipfixprobe.cesnet.cz/en/plugins) or run `ipfixprobe -h input` for more information and complete list of input plugins and their parameters.


### 📤 Output

Similarly as in input, the output availability also depends on the installed packages.
By default, installed the `ipfixprobe` package enables standard `ipfix` and `text` output.

To add [NEMEA system](https://nemea.liberouter.org) output capability, you should install `ipfixprobe-nemea` instead of ipfixprobe

See `ipfixprobe -h output` for more information and complete list of output plugins and their parameters.

#### LZ4 compression:
ipfix plugin supports LZ4 compression algorithm over tcp. See plugin's help for more information.


## ⚠️ Possible issues
### Flows are not send to output interface when reading small pcap file (NEMEA output)

Turn off message buffering using `buffer=off` option and set `timeout=WAIT` on output interfaces.

```
./ipfixprobe -i 'pcap;file=traffic.pcap' -o 'unirec;i=u:out:timeout=WAIT:buffer=off'
```
