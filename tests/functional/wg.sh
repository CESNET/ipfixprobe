#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test wg "$pcap_dir/wg.pcap"
