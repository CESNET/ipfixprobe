#!/bin/bash

test -z "$srcdir" && export srcdir=.

. $srcdir/common.sh

run_plugin_test vlan "$pcap_dir/vlan.pcap"
