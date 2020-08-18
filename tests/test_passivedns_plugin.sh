#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test passivedns "$pcap_dir/dns-sample.pcap"

