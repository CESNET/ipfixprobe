#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test basicplus "$pcap_dir/http-sample.pcap"

