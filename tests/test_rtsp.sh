#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test rtsp "$pcap_dir/rtsp.pcap"

