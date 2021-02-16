#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test bstats "$pcap_dir/bstats-sample.pcap"

