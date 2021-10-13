#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test idpcontent "$pcap_dir/idpcontent.pcap"
