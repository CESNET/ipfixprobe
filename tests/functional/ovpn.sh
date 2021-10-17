#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test ovpn "$pcap_dir/ovpn.pcap"
