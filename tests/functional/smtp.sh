#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test smtp "$pcap_dir/smtp.pcap"

