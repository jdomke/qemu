# Cloning the repo
```
# git checkout -b bbgraph 1cf9bc6
git clone --branch bbgraph --recurse-submodules git@github.com:jdomke/qemu.git
git submodule update --init --recursive
```

# Build json-c
```
rm -rf json-c/build
mkdir json-c/build
cd json-c/build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(pwd)/../../json-c-inst -DBUILD_SHARED_LIBS=OFF
make
make USE_VALGRIND=0 test
make install
cd -
rm -rf json-c/build
```

# Build qemu with plugins
```
export PKG_CONFIG_PATH="$(pwd)/json-c-inst/lib64/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
rm -rf build
mkdir build
cd build
../configure --extra-cflags="$(pkg-config --cflags json-c,bzip2)" --extra-ldflags="$(pkg-config --libs json-c,bzip2)" --target-list=aarch64-linux-user --enable-plugins --disable-docs 2>&1 |tee -a build.log
make -j$(nproc) all  2>&1 |tee -a build.log
cd -
```

# Build guest application (e.g. stream)
```
bash -c "source ~/llvm-v19.1.4/init.sh; clang -o stream ./misc/stream.c -fopenmp -DSTREAM_ARRAY_SIZE=1024 -DTUNED"
```

# Exec bbv plugin to test functionality
```
./build/qemu-aarch64 -E OMP_NUM_THREADS=12 -E LD_DEBUG=files \
    -plugin 'build/contrib/plugins/libbbv.so,outfile=per_thread_bbinfo' \
    -d plugin ./stream
```

# Newly developed bbgraph plugin (based on bbv and cflow features)
```
./build/qemu-aarch64 -E OMP_NUM_THREADS=12 -E LD_DEBUG=files \
    -plugin 'build/contrib/plugins/libbbgraph.so,outfile=per_thread_bbgraph' \
    -d plugin ./stream
```

# old readme
[here](README_org.rst)
