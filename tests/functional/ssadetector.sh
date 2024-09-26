#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test ssadetector "$pcap_dir/ovpn.pcap"
