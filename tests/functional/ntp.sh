#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test ntp "$pcap_dir/ntp.pcap"

