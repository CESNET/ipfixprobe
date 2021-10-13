#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test ovpn "$pcap_dir/ovpn.pcap"
