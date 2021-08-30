#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test ssdp "$pcap_dir/ssdp.pcap"

