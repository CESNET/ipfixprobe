#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test.sh

run_plugin_test smtp "$pcap_dir/smtp.pcap"

