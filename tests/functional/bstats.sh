#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test bstats "$pcap_dir/bstats.pcap"

