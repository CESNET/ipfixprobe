#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test pstats "$pcap_dir/mixed.pcap"

