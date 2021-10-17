#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test idpcontent "$pcap_dir/idpcontent.pcap"
