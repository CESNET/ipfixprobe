#!/bin/sh

test -z "$srcdir" && export srcdir=.

. $srcdir/test_plugin.sh

run_plugin_test smtp "$pcap_dir/smtp-sample.pcap"

