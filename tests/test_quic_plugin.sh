#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test quic "$pcap_dir/quic_initial-sample.pcap"
