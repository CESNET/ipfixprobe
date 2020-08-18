#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test ntp "$pcap_dir/ntp-sample.pcap"

