#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test ssdp "$pcap_dir/ssdp.pcap"

