#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test quic "$pcap_dir/quic_initial-sample.pcap"
