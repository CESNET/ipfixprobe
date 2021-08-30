#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test ntp "$pcap_dir/ntp.pcap"

