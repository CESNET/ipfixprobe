# ipfixprobe
IPFIX capable flow exporter with L7 flow extension support.

## Dependencies

- libpcap devel: [download link](http://www.tcpdump.org/)

## Installation
```
./bootstrap.sh
./configure
make
make install
```

## Module options
- `h` `help`      Print this message
- `v` `verbose`   Set verbose mode
- `i` `interface` Read packets from network interface
- `c` `count`     End after number of packets are processed
- `r` `pcap`      Read packets from pcap file
- `f` `filter`    String containing filter expression to filter packets. See `man pcap-filter`
- `s` `size`      Cache size exponent n. Accept values 1-31 (cache size=2^n), default is 17
- `l` `line`      Cache line size. Must be power of two
- `o` `odid`      Set observation domain ID
- `x` `ipfix`     Specify IPFIX exporter address and port. Format: `IPv4:PORT` and `[IPv6]:PORT`
- `u` `udp`       Use UDP instead of default TCP protocol for collector connection
- `p` `plugins`   Activate parsing plugins. Specify list of names separated by comma
