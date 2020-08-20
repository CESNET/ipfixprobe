#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test dnssd "$pcap_dir/dnssd-sample.pcap"

