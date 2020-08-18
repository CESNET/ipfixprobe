#!/bin/bash

export LC_ALL=C
export LANG=C

test -z "$srcdir" && export srcdir=.

flow_meter_bin=../flow_meter
logger_bin=../../logger/logger

pcap_dir=$srcdir/../traffic-samples
ref_dir=$srcdir/test_reference
output_dir=./test_output
file_out="$$.data"

# Usage: run_plugin_test <plugin> <data file>
run_plugin_test() {
   if ! [ -f "$flow_meter_bin" ]; then
      echo "flow_meter not compiled"
      return 77
   fi

   if ! [ -f "$logger_bin" ]; then
      echo "logger not compiled"
      return 77
   fi

   if ! [ -d "$output_dir" ]; then
      mkdir "$output_dir"
   fi

   "$flow_meter_bin" -i f:"$output_dir/$file_out":buffer=off:timeout=WAIT -p "$1" -L 0 -r "$2" >/dev/null
   "$logger_bin"     -i f:"$output_dir/$file_out" -t | sort > "$output_dir/$1"
   rm "$output_dir/$file_out"

   if sort "$ref_dir/$1" | diff -u "$output_dir/$1" -s - ; then
      echo "$1 plugin test OK"
   else
      echo "$1 plugin test FAILED"
      return 1
   fi
}

