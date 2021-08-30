#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test passivedns "$pcap_dir/dns.pcap"

