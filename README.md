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
../configure --extra-cflags="$(pkg-config --cflags json-c,bzip2)" --extra-ldflags="$(pkg-config --libs json-c,bzip2)" --target-list=aarch64-linux-user,riscv64-linux-user --enable-plugins --disable-docs 2>&1 |tee -a build.log
make -j$(nproc) all  2>&1 |tee -a build.log
cd -
```

# Get LLVM/GCC tooling in place for cross compiling
```
LLVMV=19.1.7
URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVMV}/LLVM-${LLVMV}-Linux-X64.tar.xz"; F="$(basename "${URL}")"
if [ ! -f "${F}" ] && [[ "${URL}" = "http"* ]]; then if ! wget --quiet "${URL}" -O "${F}"; then echo "ERR: download failed for ${URL}"; exit 1; fi; fi
[ ! -d llvm ] && mkdir llvm && tar xf "${F}" -C llvm --strip-components 1
###
GNUV="14.2.rel1"; __GNU_PREFIX__="aarch64-none-linux-gnu"; GCCARMVERSION="arm-gnu-toolchain-${GNUV}-x86_64-${__GNU_PREFIX__}"
URL="https://developer.arm.com/-/media/Files/downloads/gnu/${GNUV}/binrel/${GCCARMVERSION}.tar.xz"; F="$(basename "${URL}")"
if [ ! -f "${F}" ] && [[ "${URL}" = "http"* ]]; then if ! wget --quiet "${URL}" -O "${F}"; then echo "ERR: download failed for ${URL}"; exit 1; fi; fi
[ ! -d gnu ] && mkdir gnu && tar xf "${F}" -C gnu --strip-components 1
###
export PATH="$(pwd)/llvm/bin:$(pwd)/gnu/bin:${PATH}"
SYSROOT="$(pwd)/gnu/${__GNU_PREFIX__}/libc"
CROSSFLAGS=("--target=aarch64-unknown-linux-gnu" "-march=armv8.2-a" "-mcpu=neoverse-n1" "--sysroot=${SYSROOT}" "--gcc-toolchain=$(pwd)/gnu" "-Wl,-rpath=${SYSROOT}/lib64:${SYSROOT}/usr/lib64:$(pwd)/llvm/lib" "-Wl,-dynamic-linker=${SYSROOT}/lib/ld-linux-aarch64.so.1")
###
URL="https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-${LLVMV}.tar.gz"; F="$(basename "${URL}")"
if [ ! -f "${F}" ] && [[ "${URL}" = "http"* ]]; then if ! wget --quiet "${URL}" -O "${F}"; then echo "ERR: download failed for ${URL}"; exit 1; fi; fi
[ ! -d llvmomp ] && mkdir llvmomp && tar xzf "${F}" -C llvmomp --strip-components 1
cd llvmomp/openmp
rm -rf build; mkdir build; cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_ASM_FLAGS="${CROSSFLAGS}" -DCMAKE_C_FLAGS="${CROSSFLAGS}" -DCMAKE_CXX_FLAGS="${CROSSFLAGS}" \
  -DLIBOMP_ARCH=aarch64 -DLIBOMP_OMPD_SUPPORT:BOOL=OFF \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../../../llvm/ \
  -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_VERBOSE_BUILD:BOOL=ON ..
make -j install
cd ../../../
```

# Build destructor (run after app's main) to dump /proc/self/maps
```
rm -f misc/libdpm.*
clang ${CROSSFLAGS[@]} misc/dump_proc_maps.c -c -o dpm.o
ar rcs misc/libdpm.a dpm.o
rm -f dpm.o
clang ${CROSSFLAGS[@]} misc/dump_proc_maps.c -c -fPIC -o dpm.o
clang ${CROSSFLAGS[@]} dpm.o -shared -o misc/libdpm.so
rm -f dpm.o
DPMFLAGS=("-L$(pwd)/misc" "-Wl,-rpath=$(pwd)/misc" "-Wl,--whole-archive" "-ldpm" "-Wl,--no-whole-archive")
```

# Build guest applications (e.g. stream)
```
clang ${CROSSFLAGS[@]} -o sum ./misc/sum.c -O0 -static ${DPMFLAGS[@]}
clang ${CROSSFLAGS[@]} -o stream ./misc/stream.c -fopenmp -DSTREAM_ARRAY_SIZE=1024 -DTUNED ${DPMFLAGS[@]}
```

# Build testing/validation set
```
URL="https://downloads.sourceforge.net/project/polybench/polybench-c-4.2.1-beta.tar.gz"; F=$(basename $URL)
if [ ! -f "${F}" ] && [[ "${URL}" = "http"* ]]; then if ! wget --quiet "${URL}" -O "${F}"; then echo "ERR: download failed for ${URL}"; exit 1; fi; fi
[ ! -d polybench ] && mkdir polybench && tar xzf "${F}" -C polybench --strip-components 1
###
cd polybench
for BName in $(find datamining linear-algebra medley stencils -name '*.c' | /bin/grep -v '\.orig\.'); do
    clang ${CROSSFLAGS[@]} ${DPMFLAGS[@]} -O3 -ffast-math \
        -I$(dirname ${BName}) -I./utilities ./utilities/polybench.c ${BName} \
        -DMINI_DATASET -DPOLYBENCH_TIME -o ${BName}.exe -static
done
cd -
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
for BName in $(find polybench -name '*.c.exe'); do ./build/qemu-aarch64 \
	-plugin "build/contrib/plugins/libdcfg.so,outfile=$(basename ${BName}).dcfg" \
    -d plugin ${BName} 2>&1; done
for BName in $(find polybench -name '*.c.exe'); do python3 \
    ./misc/parse_basic_blocks.py \
    --sde_json "$(basename ${BName}).dcfg.json.bz2" \
    --cpu_arch a64fx 2>&1 | tee "$(basename ${BName}).dcfg.json.bz2.log"; done
if lscpu | grep 'sve' >/dev/null 2>&1; then
    for BName in $(find polybench -name '*.c.exe'); do
        LOG="$(basename ${BName}).dcfg.json.bz2.log"
        START="$(date +%s.%N)"
        echo "Kernel runtime: $(${BName})" 2>&1 | tee -a "${LOG}"
        ENDED="$(date +%s.%N)"
        echo "Total running time: $(echo "${ENDED} - ${START}" | bc -l)" | tee -a "${LOG}"
    done
else echo "ERR: please exec this part on A64FX to get real perf numbers"; fi
```

# RISC-V example for Ventana Veyron V1 CPU
```
__GNU_PREFIX__="riscv64-unknown-linux-gnu"
URL="https://github.com/riscv-collab/riscv-gnu-toolchain/releases/download/2025.01.20/riscv64-glibc-ubuntu-24.04-gcc-nightly-2025.01.20-nightly.tar.xz"; F="$(basename "${URL}")"
if [ ! -f "${F}" ] && [[ "${URL}" = "http"* ]]; then if ! wget --quiet "${URL}" -O "${F}"; then echo "ERR: download failed for ${URL}"; exit 1; fi; fi
[ ! -d riscv ] && mkdir riscv && tar xf "${F}" -C riscv --strip-components 1
###
export PATH="$(pwd)/llvm/bin:$(pwd)/riscv/bin:${PATH}"
SYSROOT="$(pwd)/riscv/sysroot"
CROSSFLAGS=("--target=${__GNU_PREFIX__}" "-mcpu=xiangshan-nanhu" "--sysroot=${SYSROOT}" "--gcc-toolchain=$(pwd)/riscv" "-Wl,-rpath=${SYSROOT}/lib:${SYSROOT}/usr/lib:$(pwd)/llvm/lib" "-Wl,-dynamic-linker=${SYSROOT}/lib/ld-linux-riscv64-lp64d.so.1")
###
rm -f misc/libdpm.*
clang ${CROSSFLAGS[@]} misc/dump_proc_maps.c -c -o dpm.o
ar rcs misc/libdpm.a dpm.o
rm -f dpm.o
clang ${CROSSFLAGS[@]} misc/dump_proc_maps.c -c -fPIC -o dpm.o
clang ${CROSSFLAGS[@]} dpm.o -shared -o misc/libdpm.so
rm -f dpm.o
DPMFLAGS=("-L$(pwd)/misc" "-Wl,-rpath=$(pwd)/misc" "-Wl,--whole-archive" "-ldpm" "-Wl,--no-whole-archive")
### (drop '-static' since it leads to odd behavior with bnez and strange offsets)
clang ${CROSSFLAGS[@]} -o sum ./misc/sum.c -O0 ${DPMFLAGS[@]}
###
./build/qemu-riscv64 -E OMP_NUM_THREADS=1 -plugin 'build/contrib/plugins/libdcfg.so,outfile=sum.dcfg' -d plugin ./sum
###
python3 ./misc/parse_basic_blocks.py --sde_json ./sum.dcfg.json.bz2 --cpu_arch xiangshan_nanhu
```


# TODO LIST
- fix misc/parse\_basic\_blocks.py to handle threads (see line 1694)
- check simple kernels and visualize (--vis) the BB graph
- validate/verify with poly(MINI) for aarch64
- scale down inception to kernels/functions instead of full apps


# old readme
[here](README_org.rst)
