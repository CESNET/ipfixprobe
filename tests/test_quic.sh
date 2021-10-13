#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test quic "$pcap_dir/quic_initial-sample.pcap"
