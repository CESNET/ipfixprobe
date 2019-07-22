# -*- mode: ruby -*
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "debian/stretch64"

  # config.vm.network "forwarded_port", guest: 80, host: 8080
  # config.vm.network "private_network", ip: "192.168.33.10"
  # config.vm.network "public_network"

  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.synced_folder ".", "/p4exporter", type: "rsync"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:

   config.vm.provider "virtualbox" do |vb|
      # Display the VirtualBox GUI when booting the machine
      # vb.gui = true
      # Customize the amount of memory on the VM:
      vb.memory = 4096
      vb.cpus = 4
   end

   config.vm.provider "libvirt" do |vb|
      vb.memory = 4096
      vb.cpus = 4
   end

  # Install basic dependencies
  config.vm.provision "shell", inline: <<-SHELL
     apt-get update
     apt-get install -y gcc g++ automake autoconf make libtool wget vim git tree
  SHELL

  config.vm.provision "shell", inline: <<-SHELL
     apt-get install -y libpthread-stubs0-dev libgmp-dev libpcap-dev libevent-dev flex bison unzip git libboost-thread-dev libboost-filesystem-dev libboost-system-dev libboost-program-options-dev libboost-test-dev libboost-dev curl libboost-graph-dev libboost-iostreams-dev

     (
        wget --no-verbose https://github.com/Kitware/CMake/releases/download/v3.14.2/cmake-3.14.2.tar.gz &&
        tar -xzf cmake-3.14.2.tar.gz &&
        cd cmake-3.14.2 &&
        ./bootstrap &&
        ./configure &&
        make -j 4 &&
        make install &&
        ldconfig
     )

     (
        wget --no-verbose https://github.com/skvadrik/re2c/releases/download/1.1.1/re2c-1.1.1.tar.gz &&
        tar -xvzf re2c-1.1.1.tar.gz &&
        cd re2c-1.1.1/ &&
        ./configure &&
        make -j 4 &&
        make -j 4 install &&
        ldconfig
     )

     (
        wget --no-verbose https://github.com/ivmai/bdwgc/archive/v8.0.4.zip
        unzip -q v8.0.4 &&
        cd bdwgc-8.0.4 &&
        ./autogen.sh &&
        ./configure &&
        make -j 4 &&
        make -j 4 install &&
        ldconfig
     )

     (
        wget --no-verbose https://github.com/nlohmann/json/archive/v3.6.1.zip &&
        unzip -q v3.6.1.zip &&
        cd json-3.6.1/ &&
        mkdir -p build &&
        cd build &&
        cmake -DJSON_BuildTests=OFF  .. &&
        make -j 4 &&
        make -j 4 install &&
        ldconfig
     )

     (
        wget --no-verbose https://github.com/pantor/inja/archive/v2.1.0.zip &&
        unzip -q v2.1.0.zip &&
        cd inja-2.1.0/ &&
        mkdir -p build &&
        cd build &&
        cmake -j 4 .. &&
        make -j 4 &&
        make -j 4 install &&
        ldconfig
     )

     (
        git clone https://github.com/protocolbuffers/protobuf.git &&
        cd protobuf &&
        git checkout v3.2.0 &&
        git submodule update --init --recursive &&
        ./autogen.sh &&
        ./configure &&
        make -j 4 &&
        make -j 4 install &&
        ldconfig
     )

     (
        git clone --recursive https://github.com/p4lang/p4c.git &&
        cd p4c &&
        git checkout a7aa7d0d3ab8c8502bf15b9823a3b0012e7ad313 &&
        mkdir extensions &&
        cd extensions &&
        ln -s /p4exporter p4exporter
        cd .. &&
        mkdir -p build &&
        cd build &&
        cmake -DCMAKE_BUILD_TYPE=DEBUG -DENABLE_GC=OFF -DENABLE_PROTOBUF_STATIC=OFF -DENABLE_DOCS=OFF -DENABLE_BMV2=OFF .. &&
        make -j 4 &&
        make -j 4 install &&
        ldconfig
     )

     (
        cd /p4exporter &&
        p4c-p4e p4/exporter.p4  -v --Wdisable=uninitialized_use --Wdisable=uninitialized_out_param &&
        re2c -P -i exporter/regex.c.re -o exporter/regex.c &&
        cd exporter &&
        make
     )
  SHELL


end
