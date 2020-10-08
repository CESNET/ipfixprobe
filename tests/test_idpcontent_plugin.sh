#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test idpcontent "$pcap_dir/idpcontent-sample.pcap"
