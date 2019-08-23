all:
	p4c-p4e p4/exporter.p4  -v --Wdisable=uninitialized_use --Wdisable=uninitialized_out_param
	re2c -P -i exporter/regex.c.re -o exporter/regex.c
	(cd exporter && ./bootstrap.sh && ./configure && make)
