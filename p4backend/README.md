# P4 exporter

## Dependencies

For this backend:

- inja template engine for C++ v1.0.0: [Github repo](https://github.com/pantor/inja) 
- JSON for C++ v3.5.0: [Github repo](https://github.com/nlohmann/json) 
- C++17

For P4 compiler:
See `p4c/README.md`.

For generated exporter C source:

- Lexer generator re2c: [Github repo](https://github.com/skvadrik/re2c) 
- libpcap: [Github repo](https://github.com/the-tcpdump-group/libpcap) 

## Compilation

### Compiler with backend
Download P4 compiler source codes.

```
git clone --recursive https://github.com/p4lang/p4c.git
cd p4c
git checkout a7aa7d0d3ab8c8502bf15b9823a3b0012e7ad313
```

Put this backend folder into p4c/extensions folder or create symlink to it.
```
mkdir -p extensions
cd extensions

ln -s PATH/TO/P4EXPORTER p4e
```

Compile.
```
mkdir -p ../build
cd ../build
cmake -DCMAKE_BUILD_TYPE=DEBUG -DENABLE_GC=OFF -DENABLE_PROTOBUF_STATIC=OFF -DENABLE_DOCS=OFF -DENABLE_BMV2=OFF ..
make
```

### P4 exporter
Compile P4 program into exporter source codes. Then use re2c to source code files and compile exporter.

```
p4c/build/extensions/p4e/p4c-p4e p4/exporter.p4  -v --Wdisable=uninitialized_use --Wdisable=uninitialized_out_param
re2c -P -i exporter/regex.c.re -o exporter/regex.c
cd exporter
./bootstrap.sh
./configure
make
```

### Vagrant
Easiest way to install is to use vagrant virtual machine.
```
vagrant up
```

Wait until installation is done.

```
vagrant ssh
```

