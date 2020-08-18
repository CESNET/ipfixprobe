# flow_meter module - README

## Description
This NEMEA module creates biflows from input PCAP file / network interface and exports them to output interface.

## Requirements
- To compile this module you will need [libpcap](http://www.tcpdump.org/) development library installed.
- Root priviliges are needed when capturing from network interface.

## Interfaces
### Inputs
- PCAP file
- Network interface

### Outputs
- UniRec containing `<COLLECTOR_FLOW>` + fields added by active plugins
- IPFIX [RFC 5101](https://tools.ietf.org/html/rfc5101)

## Parameters
### Module specific parameters
- `-p STRING`        Activate specified parsing plugins. Output interface for each plugin correspond the order which you specify items in -i and -p param. For example: '-i u:a,u:b,u:c -p http,basic,dns\' http traffic will be send to interface u:a, basic flow to u:b etc. If you don't specify -p parameter, flow meter will require one output interface for basic flow by default. Format: plugin_name[,...] Supported plugins: http,rtsp,https,dns,sip,ntp,smtp,basic,arp,passivedns,pstats,ssdp,dnssd,ovpn
  - Some plugins have features activated with additional parameters. Format: plugin_name[:plugin_param=value[:...]][,...] If plugin does not support parameters, any parameters given will be ignored. Supported plugin parameters are listed bellow with output data.
- `-c NUMBER`        Quit after `NUMBER` of packets are captured.
- `-I STRING`        Capture from given network interface. Parameter require interface name (eth0 for example). For nfb interface you can channel after interface delimited by : (/dev/nfb0:1) default is 0.
- `-r STRING`        Pcap file to read. `-` to read from stdin.
- `-n`               Don't send NULL record when flow_meter exits.
- `-l NUMBER`        Snapshot length when reading packets. Set value between `120`-`65535`.
- `-t NUM:NUM`       Active and inactive timeout in seconds. Format: DOUBLE:DOUBLE. Value default means use default value 300.0:30.0.
- `-s STRING`        Size of flow cache. Parameter is used as an exponent to the power of two. Valid numbers are in range 4-30. default is 17 (131072 records).
- `-S NUMBER`        Print flow cache statistics. `NUMBER` specifies interval between prints.
- `-P`               Print pcap statistics every 5 seconds. The statistics do not behave the same way on all platforms.
- `-L NUMBER`        Link bit field value.
- `-D NUMBER`        Direction bit field value.
- `-F STRING`        String containing filter expression to filter traffic. See man pcap-filter.
- `-O`               Send ODID field instead of LINK_BIT_FIELD.
- `-x STRING`        Export to IPFIX collector. Format: HOST:PORT or [HOST]:PORT.
- `-u`               Use UDP when exporting to IPFIX collector.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Stores packets from input PCAP file / network interface in flow cache to create flows. After whole PCAP file is processed, flows from flow cache are exported to output interface.
When capturing from network interface, flows are continuously send to output interfaces until N (or unlimited number of packets if the -c option is not specified) packets are captured and exported.

## Extension
`flow_meter` can be extended by new plugins for exporting various new information from flow.
There are already some existing plugins that export e.g. `DNS`, `HTTP`, `SIP`, `NTP`, `PassiveDNS`.

## Adding new plugin
To create new plugin use [create_plugin.sh](create_plugin.sh) script. This interactive script will generate .cpp and .h
file template and will also print `TODO` guide what needs to be done.

## Exporting packets
It is possible to export single packet with additional information using plugins (`ARP`).

## Possible issues
### Flows are not send to output interface when reading small pcap file
Turn off message buffering using `buffer=off` option on output interfaces.

```
./flow_meter -i u:abc:buffer=off -r traffic.pcap
```

## Output data
### Basic
Basic unirec fields exported on interface with basic (pseudo) plugin. These fields are also exported on interfaces where HTTP, DNS, SIP and NTP plugins are active.

| UniRec field           | Type             | Description                                         |
|:----------------------:|:----------------:|:---------------------------------------------------:|
| DST_MAC                | macaddr          | destination MAC address                             |
| SRC_MAC                | macaddr          | source MAC address                                  |
| DST_IP                 | ipaddr           | destination IP address                              |
| SRC_IP                 | ipaddr           | source IP address                                   |
| BYTES                  | uint64           | number of bytes in data flow (src to dst)           |
| BYTES_REV              | uint64           | number of bytes in data flow (dst to src)           |
| LINK_BIT_FIELD or ODID | uint64 or uint32 | exporter identification                             |
| TIME_FIRST             | time             | first time stamp                                    |
| TIME_LAST              | time             | last time stamp                                     |
| PACKETS                | uint32           | number of packets in data flow (src to dst)         |
| PACKETS_REV            | uint32           | number of packets in data flow (dst to src)         |
| DST_PORT               | uint16           | transport layer destination port                    |
| SRC_PORT               | uint16           | transport layer source port                         |
| DIR_BIT_FIELD          | uint8            | bit field for determining outgoing/incoming traffic |
| PROTOCOL               | uint8            | transport protocol                                  |
| TCP_FLAGS              | uint8            | TCP protocol flags (src to dst)                     |
| TCP_FLAGS_REV          | uint8            | TCP protocol flags (dst to src)                     |

### HTTP
List of unirec fields exported together with basic flow fields on interface by HTTP plugin.

| UniRec field                 | Type   | Description                 |
|:----------------------------:|:------:|:---------------------------:|
| HTTP_REQUEST_METHOD          | string | HTTP request method         |
| HTTP_REQUEST_HOST            | string | HTTP request host           |
| HTTP_REQUEST_URL             | string | HTTP request url            |
| HTTP_REQUEST_AGENT           | string | HTTP request user agent     |
| HTTP_REQUEST_REFERER         | string | HTTP request referer        |
| HTTP_RESPONSE_STATUS_CODE    | uint16 | HTTP response code          |
| HTTP_RESPONSE_CONTENT_TYPE   | string | HTTP response content type  |

### RTSP
List of unirec fields exported together with basic flow fields on interface by RTSP plugin.

| UniRec field                 | Type   | Description                 |
|:----------------------------:|:------:|:---------------------------:|
| RTSP_REQUEST_METHOD          | string | RTSP request method name    |
| RTSP_REQUEST_AGENT           | string | RTSP request user agent     |
| RTSP_REQUEST_URI             | string | RTSP request URI            |
| RTSP_RESPONSE_STATUS_CODE    | uint16 | RTSP response status code   |
| RTSP_RESPONSE_SERVER         | string | RTSP response server field  |
| RTSP_RESPONSE_CONTENT_TYPE   | string | RTSP response content type  |

### HTTPS
List of unirec fields exported together with basic flow fields on interface by HTTPS plugin.

| UniRec field        | Type   | Description                  |
|:-------------------:|:------:|:----------------------------:|
| HTTPS_SNI           | string | HTTPS server name indication |

### DNS
List of unirec fields exported together with basic flow fields on interface by DNS plugin.

| UniRec field | Type   | Description                     |
|:------------:|:------:|:-------------------------------:|
| DNS_ID       | uint16 | transaction ID                  |
| DNS_ANSWERS  | uint16 | number of DNS answer records    |
| DNS_RCODE    | uint8  | response code field             |
| DNS_NAME     | string | question domain name            |
| DNS_QTYPE    | uint16 | question type field             |
| DNS_CLASS    | uint16 | class field of DNS question     |
| DNS_RR_TTL   | uint32 | resource record TTL field       |
| DNS_RLENGTH  | uint16 | length of DNS_RDATA             |
| DNS_RDATA    | bytes  | resource record specific data   |
| DNS_PSIZE    | uint16 | requestor's payload size        |
| DNS_DO       | uint8  | DNSSEC OK bit                   |

#### DNS_RDATA format

DNS_RDATA formatting is implemented for some base DNS RR Types in human-readable output.
Same as [here](https://www.liberouter.org/technologies/exporter/dns-plugin/):

| Record | Format |
|:------:|:------:|
| A      | <IPv4 in dotted decimal representation\> |
| AAAA   | <IPv6 represented as groups separated by semicolons\> |
| NS     | <parsed hostname\> |
| CNAME  | <parsed hostname\> |
| PTR    | <parsed hostname\> |
| DNAME  | <parsed hostname\> |
| SOA    | <mname\> <rname\> <serial\> <refresh\> <retry\> <expire\> <min ttl\> |
| SRV    | <service\> <protocol\> <name\> <target\> <priority\> <weight\> <port\> |
| MX     | <priority\> <mx hostname\> |
| TXT    | <txt string\> |
| MINFO  | <rmailbx\> <emailbx\> |
| HINFO  | <txt string\> |
| ISDN   | <txt string\> |
| DS     | <keytag\> <algorithm\> <digest\> <publickey\>\* |
| RRSIG  | <type_covered\> <algorithm\> <labels\> <original_ttl\> <signature_exp\> <signature_inc\> <keytag\> <signer_signature\>\* |
| DNSKEY | <flags\> <protocol\> <algorithm\> <publickey\>\* |
| other  | <not impl\>\* |

 \* binary data are skipped and not printed

### PassiveDNS
List of unirec fields exported together with basic flow fields on interface by PassiveDNS plugin.

| UniRec field | Type   | Description                             |
|:------------:|:------:|:---------------------------------------:|
| DNS_ID       | uint16 | transaction ID                          |
| DNS_ATYPE    | uint8  | response record type                    |
| DNS_NAME     | string | question domain name                    |
| DNS_RR_TTL   | uint32 | resource record TTL field               |
| DNS_IP       | ipaddr | IP address from PTR, A or AAAA record   |

### SIP
List of unirec fields exported together with basic flow fields on interface by SIP plugin.

| UniRec field      | Type   | Description                     |
|:-----------------:|:------:|:-------------------------------:|
| SIP_MSG_TYPE      | uint16 | SIP message code                |
| SIP_STATUS_CODE   | uint16 | status of the SIP request       |
| SIP_CSEQ          | string | CSeq field of SIP packet        |
| SIP_CALLING_PARTY | string | calling party (from) URI        |
| SIP_CALLED_PARTY  | string | called party (to) URI           |
| SIP_CALL_ID       | string | call ID                         |
| SIP_USER_AGENT    | string | user agent field of SIP packet  |
| SIP_REQUEST_URI   | string | SIP request URI                 |
| SIP_VIA           | string | via field of SIP packet         |

### NTP
List of unirec fields exported together with basic flow fields on interface by NTP plugin.

| UniRec field   | Type   | Description               |
|:--------------:|:------:|:-------------------------:|
| NTP_LEAP       | uint8  | NTP leap field            |
| NTP_VERSION    | uint8  | NTP message version       |
| NTP_MODE       | uint8  | NTP mode field            |
| NTP_STRATUM    | uint8  | NTP stratum field         |
| NTP_POLL       | uint8  | NTP poll interval         |
| NTP_PRECISION  | uint8  | NTP precision field       |
| NTP_DELAY      | uint32 | NTP root delay            |
| NTP_DISPERSION | uint32 | NTP root dispersion       |
| NTP_REF_ID     | string | NTP reference ID          |
| NTP_REF        | string | NTP reference timestamp   |
| NTP_ORIG       | string | NTP origin timestamp      |
| NTP_RECV       | string | NTP receive timestamp     |
| NTP_SENT       | string | NTP transmit timestamp    |

### SMTP
List of unirec fields exported on interface by SMTP plugin

| UniRec field              | Type   | Description                         |
|:-------------------------:|:------:|:-----------------------------------:|
| SMTP_2XX_STAT_CODE_COUNT  | uint32 | number of 2XX status codes          |
| SMTP_3XX_STAT_CODE_COUNT  | uint32 | number of 3XX status codes          |
| SMTP_4XX_STAT_CODE_COUNT  | uint32 | number of 4XX status codes          |
| SMTP_5XX_STAT_CODE_COUNT  | uint32 | number of 5XX status codes          |
| SMTP_COMMAND_FLAGS        | uint32 | bit array of commands present       |
| SMTP_MAIL_CMD_COUNT       | uint32 | number of MAIL commands             |
| SMTP_RCPT_CMD_COUNT       | uint32 | number of RCPT commands             |
| SMTP_STAT_CODE_FLAGS      | uint32 | bit array of status codes present   |
| SMTP_DOMAIN               | string | domain name of the SMTP client      |
| SMTP_FIRST_SENDER         | string | first sender in MAIL command        |
| SMTP_FIRST_RECIPIENT      | string | first recipient in RCPT command     |

#### SMTP\_COMMAND\_FLAGS
The following table shows bit values of `SMTP\_COMMAND\_FLAGS` for each SMTP command present in communication.

| Command  | Value  |
|:--------:|:------:|
| EHLO     | 0x0001 |
| HELO     | 0x0002 |
| MAIL     | 0x0004 |
| RCPT     | 0x0008 |
| DATA     | 0x0010 |
| RSET     | 0x0020 |
| VRFY     | 0x0040 |
| EXPN     | 0x0080 |
| HELP     | 0x0100 |
| NOOP     | 0x0200 |
| QUIT     | 0x0400 |
| UNKNOWN  | 0x8000 |

#### SMTP\_STAT\_CODE\_FLAGS
The following table shows bit values of `SMTP\_STAT_CODE\_FLAGS` for each present in communication.

| Status code | Value      |
|:-----------:|:----------:|
| 211         | 0x00000001 |
| 214         | 0x00000002 |
| 220         | 0x00000004 |
| 221         | 0x00000008 |
| 250         | 0x00000010 |
| 251         | 0x00000020 |
| 252         | 0x00000040 |
| 354         | 0x00000080 |
| 421         | 0x00000100 |
| 450         | 0x00000200 |
| 451         | 0x00000400 |
| 452         | 0x00000800 |
| 455         | 0x00001000 |
| 500         | 0x00002000 |
| 501         | 0x00004000 |
| 502         | 0x00008000 |
| 503         | 0x00010000 |
| 504         | 0x00020000 |
| 550         | 0x00040000 |
| 551         | 0x00080000 |
| 552         | 0x00100000 |
| 553         | 0x00200000 |
| 554         | 0x00400000 |
| 555         | 0x00800000 |
| *           | 0x40000000 |
| UNKNOWN     | 0x80000000 |

* Bit is set if answer contains SPAM keyword.

### PSTATS
List of unirec fields exported on interface by PSTATS plugin.  The plugin is compiled to gather statistics for the first `PSTATS_MAXELEMCOUNT` (30 by default) packets in the biflow record.
Note: the following fields are UniRec arrays.

| UniRec field               | Type     | Description                            |
|:--------------------------:|:--------:|:--------------------------------------:|
| PPI_PKT_LENGTHS            | uint16\* | sizes of the first packets             |
| PPI_PKT_TIMES              | time\*   | timestamps of the first packets        |
| PPI_PKT_DIRECTIONS         | int8\*   | directions of the first packets        |
| PPI_PKT_FLAGS              | uint8\*  | TCP flags for each packet              |

### ARP
List of unirec fields exported on interface by ARP plugin.

| UniRec field    | Type     | Description                        |
|:---------------:|:--------:|:----------------------------------:|
| SRC_MAC         | macaddr  | source MAC address                 |
| DST_MAC         | macaddr  | destinaton MAC address             |
| ETHERTYPE       | uint16   | protocol encapsulated in L2 frame  |
| TIME            | time     | time packet was received           |
| ARP_HA_FORMAT   | uint16   | hardware address format            |
| ARP_PA_FORMAT   | uint16   | protocol address format            |
| ARP_OPCODE      | uint16   | type of ARP message                |
| ARP_SRC_HA      | bytes    | source hardware address            |
| ARP_SRC_PA      | bytes    | source protocol address            |
| ARP_DST_HA      | bytes    | destination hardware address       |
| ARP_DST_PA      | bytes    | destination protocol address       |


### SSDP
List of unirec fields exported together with basic flow fields on interface by SSDP plugin.

| UniRec field       | Type   | Description                     |
|:------------------:|:------:|:-------------------------------:|
| SSDP_LOCATION_PORT | uint16 | service port                    |
| SSDP_NT            | string | list of advertised service urns |
| SSDP_SERVER        | string | server info                     |
| SSDP_ST            | string | list of queried service urns    |
| SSDP_USER_AGENT    | string | list of user agents             |

All lists are semicolon separated.

### DNS-SD
List of unirec fields exported together with basic flow fields on interface by DNS-SD plugin.

| UniRec field    | Type   | Description                     |
|:---------------:|:------:|:-------------------------------:|
| DNSSD_QUERIES   | string | list of queries for services    |
| DNSSD_RESPONSES | string | list of advertised services     |

Format of DNSSD_QUERIES: [service_instance_name;][...]

Format of DNSSD_RESPONSES: [service_instance_name;service_port;service_target;hinfo;txt;][...]

#### Plugin parameters:
- txt - Activates processing of txt records.
    - Allows to pass a filepath to .csv file with whitelist filter of txt records.
   - File line format: service.domain,txt_key1,txt_key2,...
   - If no filepath is provided, all txt records will be aggregated.

### OVPN (OpenVPN)

List of UniRec fields exported together with basic flow fields on interface by OVPN plugin.

| UniRec field       | Type   | Description                     |
|:------------------:|:------:|:-------------------------------:|
| OVPN_CONF_LEVEL    | uint8  | level of confidence that the flow record is an OpenVPN tunnel |

## Simplified function diagram
Diagram below shows how `flow_meter` works.

1. `Packet` is read from pcap file or network interface
2. `Packet` is processed by PcapReader and is about to put to flow cache
3. Flow cache create or update flow and call `pre_create`, `post_create`, `pre_update`, `post_update` and `pre_export` functions for each active plugin at appropriate time
4. `Flow` is put into exporter when considered as expired, flow cache is full or is forced to by a plugin
5. Exporter fills `unirec record`, which is then send it to output libtrap interface

```
       +--------------------------------+
       | pcap file or network interface |
       +-----+--------------------------+
             |
          1. |
             |                                  +-----+
    +--------v---------+                              |
    |                  |             +-----------+    |
    |    PcapReader    |      +------>  Plugin1  |    |
    |                  |      |      +-----------+    |
    +--------+---------+      |                       |
             |                |      +-----------+    |
          2. |                +------>  Plugin2  |    |
             |                |      +-----------+    |
    +--------v---------+      |                       |
    |                  |  3.  |      +-----------+    +----+ active plugins
    |   NHTFlowCache   +------------->  Plugin3  |    |
    |                  |      |      +-----------+    |
    +--------+---------+      |                       |
             |                |            .          |
          4. |                |            .          |
             |                |            .          |
    +--------v---------+      |                       |
    |                  |      |      +-----------+    |
    |  UnirecExporter  |      +------>  PluginN  |    |
    |                  |             +-----------+    |
    +--------+---------+                              |
             |                                  +-----+
          5. |
             |
       +-----v--------------------------+
       |    libtrap output interface    |
       +--------------------------------+
```
