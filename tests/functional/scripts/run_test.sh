#!/bin/bash

test_dir=$1
build_dir=$2
plugin_name=$3
pcap_filename=$4

ipfixprobe_bin=$build_dir/src/core/ipfixprobe
libdir=$build_dir/src/plugins

if [ -x /usr/bin/nemea/logger ]; then
   logger_bin=/usr/bin/nemea/logger
fi

if ! [ -f "$logger_bin" ]; then
    echo "/usr/bin/nemea/logger not found!"
    return 1
fi


run_test() {
	"$ipfixprobe_bin" -i "pcap;file=$test_dir/inputs/$pcap_filename" \
	                  -L "${build_dir}/src/plugins" \
                      -o "unirec;ifc=f:${build_dir}/tests/functional/results/${plugin_name}.trapcap:buffer=off:timeout=WAIT;id=0" \
                      -p "$plugin_name" >/dev/null
	"$logger_bin"     -i f:"${build_dir}/tests/functional/results/${plugin_name}.trapcap" -t | sort > "${build_dir}/tests/functional/results/${plugin_name}"
	rm "${build_dir}/tests/functional/results/${plugin_name}.trapcap"

	if sort "${test_dir}/outputs/${plugin_name}" | diff -u "${build_dir}/tests/functional/results/${plugin_name}" -s - ; then
		echo "$1 plugin test OK"
		return 0
	fi

	echo "$plugin_name plugin test FAILED"
	return 1
}

run_test
