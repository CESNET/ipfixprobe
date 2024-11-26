<p align="center">
    <img src="https://raw.githubusercontent.com/CESNET/ipfixprobe/refs/heads/master/docs/images/ipfixprobe-horizontal.svg" width="450">
</p>

[![](https://img.shields.io/badge/license-BSD-blue.svg)](https://github.com/CESNET/ipfixprobe/blob/master/LICENSE)
![Coverity Scan](https://img.shields.io/coverity/scan/22112)
![GitHub top language](https://img.shields.io/github/languages/top/CESNET/ipfixprobe)

ipfixprobe is a high-performance flow exporter. It creates bidirectional flows from packet input and exports them to output interface. The ipfixprobe support vide variety of flow extenstion for application layer protocol information. The flow extension can be turned on with process plugins. We support TLS, QUIC, HTTP, DNS and many more. Just check our [documentation](https://cesnet.github.io/ipfixprobe/).

## Installation
The RPM packages for RHEL based distributions can be downloaded from our  [copr repository](https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/package/ipfixprobe/). Or just simply run:

```
dnf install -y dnf-plugins-core && dnf copr -y enable @CESNET/NEMEA
dnf install ipfixprobe
```

## Parameters
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

### Help
Printing general help is done using the `-h` parameter. To print help for specific plugins, `-h` with parameter is used.
This parameter accepts `input`, `storage`, `process`, `output` or name of a plugin (or path to a .so file with plugin).

## Example
Here are the examples of various plugins usage:
```
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

### Requirements
- libatomic
- kernel version at least 3.19 when using raw sockets input plugin enabled by default (disable with `--without-raw` parameter for `./configure`)
- [libpcap](http://www.tcpdump.org/) when compiling with pcap plugin (`--with-pcap` parameter)
- netcope-common [COMBO cards](https://www.liberouter.org/technologies/cards/) when compiling with ndp plugin (`--with-ndp` parameter)
- libunwind-devel when compiling with stack unwind on crash feature (`--with-unwind` parameter)
- [nemea](http://github.com/CESNET/Nemea-Framework) when compiling with unirec output plugin (`--with-nemea` parameter)
- cloned submodule with googletest framework to enabled optional tests (`--with-gtest` parameter)

To compile DPDK interfaces, make sure you have DPDK libraries (and development files) installed and set the `PKG_CONFIG_PATH` environment variable if necessary. You can obtain the latest DPDK at http://core.dpdk.org/download/ Use `--with-dpdk` parameter of the `configure` script to enable it.

### Source codes

This project uses a standard process of:

```
git clone --recurse-submodules https://github.com/CESNET/ipfixprobe
cd ipfixprobe
autoreconf -i
./configure
make
sudo make install
```

Check `./configure --help` for more details and settings.

### RPM packages

RPM package can be created in the following versions using `--with` parameter of `rpmbuild`:
- `--with pcap` enables RPM with pcap input plugin
- `--with ndp` enables RPM with netcope-common, i.e., ndp input plugin
- `--with nemea` enables RPM with unirec output plugin
- `--without raw` disables RPM with default raw socket input plugin
- `--with unwind` enables RPM with stack unwinding feature

These parameters affect required dependencies of the RPM and build process.

The default configuration of the RPM can be created using simply: `make rpm`

Alternative versions (described in the following section) can be created by:
- NEMEA version of RPM: `make rpm-nemea`
- NDP version of RPM: `make rpm-ndp`

We use [COPR infrastructure](https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/) to build and serve RPM packages for EPEL9.
It is not possible to pass arguments to rpmbuild, so there is an option in configure to enforce NEMEA dependency:

`./configure --enable-coprrpm && make srpm`

The output source RPM can be uploaded to copr.

To install ipfixprobe with NEMEA dependency from binary RPM packages, it is possible to follow instructions on:
[https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/](https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/)

## Telemetry

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


## Input / Output of the flow exporter

The availability of the input and output interfaces depends on the ipfixprobe build settings. By default, we provide RPM package with pcap and raw inputs. The default provided outpus are ipfix and text.

When the project is configured with `./configure --with-nemea`, the flow
exporter supports NEMEA output via TRAP IFC besides the default IPFIX output.
For more information about NEMEA, visit
[https://nemea.liberouter.org](https://nemea.liberouter.org).

The flow exporter supports compilation with libpcap (`./configure --with-pcap`), which allows for receiving packets
from PCAP file or network interface card.

When the project is configured with `./configure --with-ndp`, it is prepared for high-speed packet transfer
from special HW acceleration FPGA cards.  For more information about the cards,
visit [COMBO cards](https://www.liberouter.org/technologies/cards/) or contact
us.

### Output

There are several currently available output plugins, such as:

- `ipfix` standard IPFIX [RFC 5101](https://tools.ietf.org/html/rfc5101)
- `unirec` data source for the [NEMEA system](https://nemea.liberouter.org), the output is in the UniRec format sent via a configurable interface using [https://nemea.liberouter.org/trap-ifcspec/](https://nemea.liberouter.org/trap-ifcspec/)
- `text` output in human readable text format on standard output file descriptor (stdout)

The output flow records are composed of information provided by the enabled plugins (using `-p` parameter, see [Flow Data Extension - Processing Plugins](./README.md#flow-data-extension---processing-plugins)).

See `ipfixprobe -h output` for more information and complete list of output plugins and their parameters.

LZ4 compression:
ipfix plugin supports LZ4 compression algorithm over tcp. See plugin's help for more information.


## Possible issues
### Flows are not send to output interface when reading small pcap file (NEMEA output)

Turn off message buffering using `buffer=off` option and set `timeout=WAIT` on output interfaces.

```
./ipfixprobe -i 'pcap;file=traffic.pcap' -o 'unirec;i=u:out:timeout=WAIT:buffer=off'
```

