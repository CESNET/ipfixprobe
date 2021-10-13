#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test dns "$pcap_dir/dns.pcap"

