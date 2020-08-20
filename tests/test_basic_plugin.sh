#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test basic "$pcap_dir/mixed-sample.pcap"

