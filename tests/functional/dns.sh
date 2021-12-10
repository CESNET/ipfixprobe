#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test dns "$pcap_dir/dns.pcap"

