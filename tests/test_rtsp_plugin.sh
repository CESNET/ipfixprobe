#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test rtsp "$pcap_dir/rtsp-sample.pcap"

