#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test netbios "$pcap_dir/netbios-sample.pcap"

