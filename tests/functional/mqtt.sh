#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test mqtt "$pcap_dir/mqtt.pcap"

