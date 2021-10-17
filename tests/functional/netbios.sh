#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test netbios "$pcap_dir/netbios.pcap"

