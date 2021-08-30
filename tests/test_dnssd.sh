#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test dnssd "$pcap_dir/dnssd.pcap"

