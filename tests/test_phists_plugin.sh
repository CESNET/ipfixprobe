#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test phists "$pcap_dir/mixed-sample.pcap"

