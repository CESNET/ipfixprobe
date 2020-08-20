#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test ovpn "$pcap_dir/ovpn-sample.pcap"
