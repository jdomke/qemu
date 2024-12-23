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

# Build destructor (run after app's main) to dump /proc/self/maps
```
bash -c "source ~/llvm-v19.1.4/init.sh; rm -f misc/libdpm.*; clang misc/dump_proc_maps.c -c -o dpm.o; ar rcs misc/libdpm.a dpm.o; rm -f dpm.o; clang misc/dump_proc_maps.c -c -fPIC -o dpm.o; clang dpm.o -shared -o misc/libdpm.so; rm -f dpm.o"
```


# Build guest applications (e.g. stream)
```
bash -c "source ~/llvm-v19.1.4/init.sh; clang -o sum ./misc/sum.c -O0 -static -L./misc -Wl,-rpath=\$(pwd)/misc -Wl,--whole-archive -ldpm -Wl,--no-whole-archive"
bash -c "source ~/llvm-v19.1.4/init.sh; clang -o stream ./misc/stream.c -fopenmp -DSTREAM_ARRAY_SIZE=1024 -DTUNED -L./misc -Wl,-rpath=\$(pwd)/misc -Wl,--whole-archive -ldpm -Wl,--no-whole-archive"
```

# Build testing/validation set
```
mkdir -p misc/polybench; URL="https://downloads.sourceforge.net/project/polybench/polybench-c-4.2.1-beta.tar.gz"; DEP=$(basename $URL); if [ ! -f misc/${DEP} ]; then wget ${URL} -O misc/${DEP}; fi; tar xzf misc/${DEP} -C misc/polybench --strip-components 1
bash -c "source ~/llvm-v19.1.4/init.sh; cd misc/polybench; for BName in \$(find datamining linear-algebra medley stencils -name '*.c' | /bin/grep -v '\.orig\.'); do clang -O3 -ffast-math -flto=full -I\$(dirname \${BName}) -I./utilities ./utilities/polybench.c \${BName} -DMINI_DATASET -DPOLYBENCH_TIME -o \${BName}.exe -L\$(pwd)/../../misc -Wl,-rpath=\$(pwd)/../../misc -Wl,--whole-archive -ldpm -Wl,--no-whole-archive -static; done; cd -"
```

# Exec bbv plugin to test functionality
```
./build/qemu-aarch64 -E OMP_NUM_THREADS=12 -E LD_DEBUG=files \
    -plugin 'build/contrib/plugins/libbbv.so,outfile=per_thread_bbinfo' \
    -d plugin ./stream
```

# Newly developed Dynamic Control-Flow Graph plugin (based on bbv and cflow features)
```
./build/qemu-aarch64 -E OMP_NUM_THREADS=12 \
    -plugin 'build/contrib/plugins/libdcfg.so,outfile=stream.dcfg' \
    -d plugin ./stream
```

# Install dependencies for block parser
```
python3 -m pip install --user -r misc/requirements.txt
```

# Exec block analyzer to get cycles from MCA estimates
```
python3 ./misc/parse_basic_blocks.py --sde_json ./stream.dcfg.json.bz2 --cpu_arch a64fx
#Note: use -s and -l options to avoid parsing the oject files every time
```

# Test DCFG with polybench
```
for BName in $(find misc/polybench -name '*.c.exe'); do ./build/qemu-aarch64 \
	-plugin "build/contrib/plugins/libdcfg.so,outfile=$(basename ${BName}).dcfg" \
    -d plugin ${BName} 2>&1; done
for BName in $(find misc/polybench -name '*.c.exe'); do python3 \
    ./misc/parse_basic_blocks.py \
    --sde_json "$(basename ${BName}).dcfg.json.bz2" \
    --cpu_arch a64fx 2>&1 | tee "$(basename ${BName}).dcfg.json.bz2.log"; done
```


# old readme
[here](README_org.rst)
