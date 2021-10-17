#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test dnssd "$pcap_dir/dnssd.pcap"

