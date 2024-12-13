# Cloning the repo
```
# git checkout -b bbgraph 1cf9bc6
git clone --branch bbgraph --recurse-submodules git@github.com:jdomke/qemu.git
```

# Build qemu with plugins
```
mkdir build
cd build
../configure --target-list=aarch64-linux-user --enable-plugins --disable-docs 2>&1 |tee -a build.log
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
