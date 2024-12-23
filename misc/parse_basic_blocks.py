#!/usr/bin/env python3

# usage:
# <script> -j ./dcfg-out.dcfg.json.bz2 -b ./dcfg-out.bb.txt.bz2
#  ( create files: ./dcfg-out.dcfg.json.bz2 and ./dcfg-out.bb.txt.bz2 via
#      `sde64 -dcfg 1 -dcfg:write_bb 1 ...` )

from os import path, getpid, remove, environ
from sys import exit
from platform import uname
from bz2 import open as bz2open
from json import dumps as jsondumps     # TODO: take this out
from json import loads as jsonloads
from re import compile, findall, search, sub, DOTALL, IGNORECASE
from collections import defaultdict
from subprocess import run, PIPE
from networkx import DiGraph, has_path, find_cycle, dfs_edges, \
    NetworkXNoCycle, kamada_kawai_layout
from copy import deepcopy
from io import StringIO
from osaca import osaca
from functools import reduce

# info put together from different sources:
#   github.com/archspec/archspec-json/blob/master/cpu/microarchitectures.json
#   github.com/torvalds/linux/blob/master/arch/x86/events/intel/core.c
KNOWN_ARCHS = {
    # Intel
    'x86': None, 'i686': None, 'pentium2': None, 'pentium3': None,
    'pentium4': None, 'prescott': None, 'x86_64': None, 'nocona': None,
    'core2': None, 'nehalem': None, 'westmere': None, 'sandybridge': None,
    'ivybridge': None, 'haswell': None, 'broadwell': None, 'skylake': None,
    'mic_knl': None, 'skylake_avx512': None, 'cannonlake': None,
    'cascadelake': None, 'icelake': None, 'sapphirerapids': None,
    # AMD
    'k10': None, 'bulldozer': None, 'piledriver': None, 'steamroller': None,
    'excavator': None, 'zen': None, 'zen2': None, 'zen3': None, 'zen4': None,
    # IBM
    'ppc64': None, 'power7': None, 'power8': None, 'power9': None,
    'ppc64le': None, 'power8le': None, 'power9le': None, 'power10le': None,
    # ARM
    'aarch64': None, 'thunderx2': None, 'a64fx': None, 'graviton': None,
    'graviton2': None, 'neoverse_n1': None, 'neoverse_n2': None,
    'm1': None, 'm2': None, 'arm': None,
    # other
    'ppc': None, 'ppcle': None, 'sparc': None, 'sparc64': None, 'riscv64': None
}

def _get_OBJDUMP_ASSEMBLY(sde_files=None):
    assert(isinstance(sde_files, dict))

    objdp_asm = {}

    elf_part = compile(r'^\s*LOAD\s+\w+\s+(\w+)\s+\w+\s+\w+\s+\w+\s+R[\sWE]{2}\s+\w+$')
    nm_part = compile(r'^(\w+)\s+(\w+)\s+[A-Za-z]\s+(.*)$')
    # offset, fn name
    fn_hdr = compile(r'^(\w+)\s+<(.+)>:$')
    # offset, instruction (+comment)
    fn_asm_part = compile(r'^\s+(\w+):\s+([\.\(]?\w{1,}.*)$')
    fn_asm_hexpc_part = compile(r'^(.*\s)(0x)(\w{6,})(.*)$')
    fn_asm_igno = compile(r'^(.*)\s+(<.*>)$')
    __trash__ = compile(
        r'^$|^.*:\s+file format elf.*$|^Disassembly.*$|^\s+#.*|^Sections.*|^Idx .*|^\s*\w+\s+.*\w+\s+\w+.*|^Program .*|^Dynamic .*|^\s+SONAME .*|^\s+NEEDED .*|^\s+[A-Z_\d]+\s+\w+|^Version .*|^.* GLIBC_.*|^\d+\s+\w+\s+\w+\s+.*')

    for fid in sde_files:
        FILE_NAME = sde_files[fid]
        objdp_asm[fid] = {'File': FILE_NAME, 'FileID': fid, 'FNs': {}, 'LO': 0}

        # ignore kernel lib
        #if FILE_NAME == '[vdso]' or not path.exists(FILE_NAME):
        if (FILE_NAME.startswith('[') and FILE_NAME.endswith(']')) \
                or not path.exists(FILE_NAME):
            print('WRN 01: skipping missing file %s' % FILE_NAME)
            continue

        # XXX: executable ELF64 binaries linked by ld have canonical
        #      base address offset of 0x400000, but SDE subtracts this
        # XXX: much bigger mess nowadays and esp for non-X86 binaries
        #      so we switch to looking for first TEXT in Sections table
        # XXX: ... the mess:
        #      static binary w/ ld/bfd/gold -> load address offset is 0x400000
        #      static binary with lld -> load address offset is 0x200000
        #      dynamic binary with ld/bfd/gold -> load address offset is 0x0
        #      dynamic binary with lld -> load address offset is 0x0
        #      libs -> looks like all offsets are 0x0 (fingers crossed)

        # get the stupid load address first -> hit on first find of 'LOAD'
        #print('_get_OBJDUMP_ASSEMBLY', FILE_NAME)
        p = run(['llvm-readelf', '--program-headers', FILE_NAME], stdout=PIPE)
        load_os  = None
        for line in p.stdout.decode().splitlines():
            #print('_get_OBJDUMP_ASSEMBLY', line)
            if elf_part.match(line):
                load_os = int(elf_part.match(line).group(1).strip(), 16)
                break
        assert(load_os is not None)
        if load_os == int('0x400000', 16) or load_os == int('0x200000', 16):
            objdp_asm[fid]['LO'] = load_os
        elif load_os > 0:
            exit('ERR: never seen before base address offset')

        #XXX: objdump may not show all the symbols (eg libc.so.6 only has a
        #     bit .text blob :-( so we first check nm and extract the asm from
        #     start to stop address and then do 2nd pass to find what's missing
        #TODO: ...this takes now much longer to parse the asm dumps, SHIT!

        p = run(['llvm-nm',
                 '--defined-only',
                 '--demangle',
                 '--print-size',
                 '--numeric-sort',
                 FILE_NAME], stdout=PIPE)

        for line in p.stdout.decode().splitlines():
            if nm_part.match(line):
                nm = nm_part.match(line)

                fn_os, fn_size, fn_name = int(nm.group(1).strip(), 16), \
                    int(nm.group(2).strip(), 16), nm.group(3).strip()
                if fn_size < 1 or fn_os < load_os: continue

                curr_fn_os = fn_os - load_os
                os_str = '0x' + format(curr_fn_os, 'x')

                objdp_asm[fid]['FNs'][curr_fn_os] = {
                    'Offset': os_str,
                    'Func': fn_name,
                    'ASM': _get_single_block_from_OBJDUMP(FILE_NAME, curr_fn_os, fn_size, load_os)}

        # get objdump for each file (main binary and all shared libs)
        p = run(['llvm-objdump',
                 '--disassembler-color=off',
                 '--disassemble',
                 '--disassemble-zeroes',
                 '--no-show-raw-insn',
                 '--demangle',
                 FILE_NAME], stdout=PIPE, stderr=PIPE)

        curr_fn_os, skip = None, False
        for line in p.stdout.decode().splitlines():
            if fn_hdr.match(line):

                fn = fn_hdr.match(line)
                #fn_os, fn_name, fn_real_os = \
                #    fn.group(1).strip(), fn.group(2).strip(), \
                #    fn.group(3).strip()
                fn_os, fn_name = fn.group(1).strip(), fn.group(2).strip()

                curr_fn_os = int(fn_os, 16) - load_os
                os_str = '0x' + format(curr_fn_os, 'x')

                if curr_fn_os in objdp_asm[fid]['FNs']:
                    skip = True
                    continue
                else:
                    skip = False

                objdp_asm[fid]['FNs'][curr_fn_os] = {'Offset': os_str,
                                                     'Func': fn_name,
                                                     'ASM': []}
            elif fn_asm_part.match(line):
                if skip: continue

                assert(curr_fn_os is not None)

                fn = fn_asm_part.match(line)
                fn_asm_os, fn_asm_in = fn.group(1).strip(), fn.group(2).strip()
                # FIXME: strip comments at end as well??? => yes, llvm confused
                if fn_asm_igno.match(fn_asm_in):
                    fn_asm_in = fn_asm_igno.match(fn_asm_in).group(1)

                fn_asm_os = '0x' + format(int(fn_asm_os, 16) - load_os, 'x')

                objdp_asm[fid]['FNs'][curr_fn_os]['ASM'].append([fn_asm_os,
                                                                 fn_asm_in])
            elif __trash__.match(line):
                continue
            else:
                exit('ERR: unknown line (%s) in objdump (%s)' %
                     (line, FILE_NAME))

        for line in p.stderr.decode().splitlines():
            if 'warning: section' in line: continue
            print(line)

        # adjust pc offsets if load_os > 0
        if load_os > 0:
            for curr_fn_os in objdp_asm[fid]['FNs']:
                for i in range(len(objdp_asm[fid]['FNs'][curr_fn_os]['ASM'])):
                    fn_asm_os, fn_asm_in = objdp_asm[fid]['FNs'][curr_fn_os]['ASM'][i]
                    hexpc = fn_asm_hexpc_part.match(fn_asm_in)
                    if hexpc and int(hexpc.group(3), 16) > load_os:
                        fn_asm_in = hexpc.group(1) + hex(int(hexpc.group(3), 16)-load_os) + hexpc.group(4)
                        objdp_asm[fid]['FNs'][curr_fn_os]['ASM'][i] = [fn_asm_os, fn_asm_in]

    return objdp_asm


def _get_single_block_from_OBJDUMP(sde_file=None, from_addr=None,
                                   num_byte=None, load_os=0):
    assert(isinstance(sde_file, str) and isinstance(load_os, int)
           and isinstance(from_addr, int) and isinstance(num_byte, int))
    assert(sde_file != '[vdso]')

    asm = []
    start_addr = load_os + from_addr

    if not path.exists(sde_file):
        print('WRN 10: %s missing on "this" node, or was deleted' % sde_file)
        return [['0x' + format(x, 'x'), 'nop']
                for x in range(start_addr, start_addr + num_byte)]

    fn_asm_part = compile(r'^\s+(\w+):\s+([\.\(]?\w{1,}.*)$')
    fn_asm_igno = compile(r'^(.*)\s+(<.*>)$')

    # open interval [.,.), so --stop-address=0x... is excluded from output
    p = run(['llvm-objdump',
             '--disassembler-color=off',
             '--disassemble',
             '--disassemble-zeroes',
             '--no-show-raw-insn',
             '--demangle',
             '--start-address=0x' + format(start_addr, 'x'),
             '--stop-address=0x' + format(start_addr + num_byte, 'x'),
             sde_file], stdout=PIPE, stderr=PIPE)

    for line in p.stdout.decode().splitlines():
        if fn_asm_part.match(line):
            fn = fn_asm_part.match(line)
            fn_asm_os, fn_asm_in = fn.group(1).strip(), fn.group(2).strip()
            # FIXME: strip comments at end as well??? => yes, llvm confused
            if fn_asm_igno.match(fn_asm_in):
                fn_asm_in = fn_asm_igno.match(fn_asm_in).group(1)

            fn_asm_os = '0x' + format(int(fn_asm_os, 16) - load_os, 'x')
            asm.append([fn_asm_os, fn_asm_in])

    for line in p.stderr.decode().splitlines():
        if 'no section overlaps the range' in line: continue
        print(line)

    return asm


def _read_backup_OBJDUMP_ASSEMBLY(backup=None):
    assert(isinstance(backup, str))

    from pickle import load

    return load(open(backup, 'rb'))


def _store_backup_OBJDUMP_ASSEMBLY(objdp_asm=None, backup=None):
    assert(isinstance(objdp_asm, dict) and isinstance(backup, str))

    from pickle import dump

    return dump(objdp_asm, open(backup, 'wb'))


def _parse_FILE_NAMES(sde_bb_json=None, arch=None):
    assert(isinstance(sde_bb_json, dict) and isinstance(arch, str))

    ARCHS = deepcopy(KNOWN_ARCHS)
    ARCHS['broadwell'] = ['x86_64', 'vdso.so']
    ARCHS['cannonlake'] = ['x86_64', 'vdso.so']
    ARCHS['cascadelake'] = ['x86_64', 'vdso.so']
    ARCHS['core2'] = ['x86_64', 'vdso.so']
    ARCHS['haswell'] = ['x86_64', 'vdso.so']
    ARCHS['icelake'] = ['x86_64', 'vdso.so']
    ARCHS['ivybridge'] = ['x86_64', 'vdso.so']
    ARCHS['mic_knl'] = ['x86_64', 'vdso.so']
    ARCHS['nehalem'] = ['x86_64', 'vdso.so']
    ARCHS['sandybridge'] = ['x86_64', 'vdso.so']
    ARCHS['skylake'] = ['x86_64', 'vdso.so']
    ARCHS['skylake_avx512'] = ['x86_64', 'vdso.so']
    ARCHS['westmere'] = ['x86_64', 'vdso.so']
    ARCHS['x86_64'] = ['x86_64', 'vdso.so']
    ARCHS['aarch64'] = ['aarch64', 'vdso-be.so']
    ARCHS['thunderx2'] = ['aarch64', 'vdso-be.so']
    ARCHS['a64fx'] = ['aarch64', 'vdso-be.so'] # be==big-endian
    ARCHS['power7'] = ['ppc64', 'vdso-64.so']
    ARCHS['power8'] = ['ppc64', 'vdso-64.so']
    ARCHS['power9'] = ['ppc64', 'vdso-64.so'] # random guess
    assert(ARCHS[arch])

    # "FILE_NAMES" :
    #   [ [ "FILE_NAME_ID", "FILE_NAME" ],
    #     [ 2, "\/usr\/joe\/src\/misc\/hello-world" ],
    #     [ 5, "\/lib64\/libgcc_s.so" ], ...
    #   ]
    vdso = path.join(path.dirname(__file__), '..', 'linux-user', ARCHS[arch][0], ARCHS[arch][1])
    for i in range(len(sde_bb_json['FILE_NAMES'])):
        fid, FILE_NAME = sde_bb_json['FILE_NAMES'][i]
        if FILE_NAME == '[vdso]': sde_bb_json['FILE_NAMES'][i] = [fid, vdso]
    return dict(sde_bb_json['FILE_NAMES'][1:])


def _parse_SPECIAL_NODES(sde_bb_json=None):
    assert(isinstance(sde_bb_json, dict))

    # "SPECIAL_NODES" :
    #   [ [ "NODE_ID", "NODE_NAME" ],
    #     [ 1, "START" ],
    #     [ 2, "END" ],
    #     [ 3, "UNKNOWN" ]
    #   ]
    return dict(sde_bb_json['SPECIAL_NODES'][1:])


def _parse_EDGE_TYPES(sde_bb_json=None):
    assert(isinstance(sde_bb_json, dict))

    # "EDGE_TYPES" :
    #   [ [ "EDGE_TYPE_ID", "EDGE_TYPE" ],
    #     [ 1, "ENTRY" ],
    #     [ 2, "EXIT" ], ...
    #   }
    return dict(sde_bb_json['EDGE_TYPES'][1:])


def _parse_PROCESSES(sde_bb_json=None, sde_files=None, objdp_asm=None):
    assert(isinstance(sde_bb_json, dict) and isinstance(sde_files, dict)
           and isinstance(objdp_asm, dict))

    sde_procs = {}

    # "PROCESSES" :
    #   [ [ "PROCESS_ID", "PROCESS_DATA" ],
    #     [ 22814, dict{...} ],
    #     [ 958, dict{...} ], ...
    #   ]
    for PROCESS_ID, PROCESS_DATA in sde_bb_json['PROCESSES'][1:]:
        assert(PROCESS_ID not in sde_procs)

        # "PROCESS_DATA" :
        #   { "INSTR_COUNT" : 2134576,
        #     "INSTR_COUNT_PER_THREAD" : [ 1997750, 51676, 19794,18381, ...],
        #     "IMAGES" : [...],
        #     "EDGES" : [...]
        #   }
        # ==> "IMAGES" :    // basically just: binaries and shared objects
        #       [ [ "IMAGE_ID", "LOAD_ADDR", "SIZE", "IMAGE_DATA" ],
        #         [ 1, "0x400000", 2102216, {...} ],
        #         [ 2, "0x2aaaaaaab000", 1166728, {...} ]
        #       ]
        sde_procs[PROCESS_ID] = {'FileIDs': {}, 'Edges': {}}
        for _, LOAD_ADDR, _, IMAGE_DATA in PROCESS_DATA['IMAGES'][1:]:
            fid = IMAGE_DATA['FILE_NAME_ID']
            #if sde_files[fid] == '[vdso]':
            #    _add_fake_vdso_info_to_asm(IMAGE_DATA, objdp_asm[fid]['FNs'])
            if sde_files[fid] == '[vvar]' or sde_files[fid] == '[vsyscall]':
                _add_fake_vstuff_info_to_asm(IMAGE_DATA, objdp_asm[fid]['FNs'])

            _, symbols, _, bb, rout = _parse_IMAGE_DATA(IMAGE_DATA, sde_files,
                                                        objdp_asm[fid]['FNs'])

            laddr = '0x' + format(int(LOAD_ADDR, 16), 'x')
            sde_procs[PROCESS_ID]['FileIDs'][fid] = {'FileID': fid,
                                                     'Offset': laddr,
                                                     'FNs': symbols,
                                                     'Blocks': bb,
                                                     'Routines': rout}

            #if fid==54612029: print('_parse_PROCESSES', fid,sde_procs[PROCESS_ID]['FileIDs'][fid]['Blocks'])
        _parse_EDGES(PROCESS_DATA['EDGES'], sde_procs[PROCESS_ID]['Edges'])

    # XXX: shouldn't have more than 1 process in here
    assert(1 == len(sde_procs))

    return sde_procs


def _parse_IMAGE_DATA(sde_image_data=None, sde_files=None, objdp_asm=None):
    assert(isinstance(sde_image_data, dict) and isinstance(sde_files, dict)
           and isinstance(objdp_asm, dict))

    # "IMAGE_DATA" :
    #   { "FILE_NAME_ID" : 4,
    #     "SYMBOLS" : [...],        // eq. functions (names and offsets)
    #     "SOURCE_DATA" : [...],    // XXX: SOURCE_DATA seems optional
    #     "BASIC_BLOCKS" : [...],
    #     "ROUTINES" : [...]        // FIXME: not sure, but its not full func
    #   }
    symbols, src_data, bb, routines = {}, {}, {}, {}

    if 'FILE_NAME_ID' in sde_image_data:
        FILE_NAME_ID = sde_image_data['FILE_NAME_ID']
    else:
        exit('ERR: no FILE_NAME_ID found in IMAGE_DATA')

    if 'SYMBOLS' in sde_image_data:
        _parse_SYMBOLS(sde_image_data, sde_files, objdp_asm, symbols)
    if 'SOURCE_DATA' in sde_image_data:
        _parse_SOURCE_DATA(sde_image_data, src_data)
    if 'BASIC_BLOCKS' in sde_image_data:
        _parse_BASIC_BLOCKS(sde_image_data, sde_files, objdp_asm, bb)
    if 'ROUTINES' in sde_image_data:
        _parse_ROUTINES(FILE_NAME_ID, symbols, bb, routines)

    return (FILE_NAME_ID, symbols, src_data, bb, routines)


def _parse_SYMBOLS(sde_image_data=None, sde_files=None, objdp_asm=None, symbols=None):
    assert(isinstance(sde_image_data, dict) and isinstance(sde_files, dict)
           and isinstance(objdp_asm, dict) and isinstance(symbols, dict))

    # "SYMBOLS" :   // XXX: no more SDE -> check objdump:
    #   0000000000404d30 0000000000002050 T main
    #   0000000000ffa3a0 0000000000000890 d main_arena
    #   0000000001066f58 0000000000000020 B main_kmpc_tree_reduct_lock_0
    #   0000000000b47a80 0000000000000547 t make_request
    #   0000000000adbe70 00000000000000f2 W mallinfo
    #   0000000000ad9ce0 00000000000000d6 T malloc

    FILE_NAME = sde_files[sde_image_data['FILE_NAME_ID']]
    if (FILE_NAME.startswith('[') and FILE_NAME.endswith(']')):
        return

    elf_part = compile(r'^\s*LOAD\s+\w+\s+(\w+)\s+\w+\s+\w+\s+\w+\s+R[\sWE]{2}\s+\w+$')
    # get the stupid load address first -> hit on first find of 'LOAD'
    p = run(['llvm-readelf', '--program-headers', FILE_NAME], stdout=PIPE)
    load_os = None
    for line in p.stdout.decode().splitlines():
        if elf_part.match(line):
            load_os = int(elf_part.match(line).group(1).strip(), 16)
            break
    assert(load_os is not None)

    sym_part = compile(r'^(\w+)\s+(\w+)\s+(\w)\s+(.*)$')
    # now we can check the symbol table
    p = run(['llvm-nm',
             '--defined-only',
             '--demangle',
             '--print-size',
             '--numeric-sort',
             FILE_NAME], stdout=PIPE)

    for line in p.stdout.decode().splitlines():
        if sym_part.match(line):
            s = sym_part.match(line)
            OFFSET, SIZE, _, NAME = int(s.group(1).strip(), 16) - load_os, \
                int(s.group(2).strip(), 16), s.group(3).strip(), \
                s.group(4).strip()
            if OFFSET < 0: continue
            symbols[OFFSET] = {'Func': NAME, 'Size': SIZE,
                               'Offset': '0x' + format(OFFSET, 'x')}

    plt_hdr = compile(r'^(\w+)\s+<(.+)>:$')
    asm_part = compile(r'^\s+(\w+):\s+([\.\(]?\w{1,}.*)$')
    # need ducking .plt section too...
    p = run(['llvm-objdump',
             '--disassembler-color=off',
             '--disassemble',
             '--disassemble-zeroes',
             '--no-show-raw-insn',
             '--demangle',
             '--section=.plt', '--section=.rela.dyn', '--section=.rela.plt',
             FILE_NAME], stdout=PIPE, stderr=PIPE)

    OFFSET = None
    for line in p.stdout.decode().splitlines():
        if plt_hdr.match(line):
            plt = plt_hdr.match(line)
            OFFSET, NAME = int(plt.group(1).strip(), 16) - load_os, plt.group(2).strip()
            symbols[OFFSET] = {'Func': NAME, 'Size': 0,
                               'Offset': '0x' + format(OFFSET, 'x')}
        elif asm_part.match(line):
            assert(OFFSET and OFFSET in symbols)
            asm = asm_part.match(line)
            asm_os = int(asm.group(1).strip(), 16) - load_os
            symbols[OFFSET]['Size'] = asm_os - OFFSET
    #for s in symbols: print('_parse_SYMBOLS', symbols[s])

    for line in p.stderr.decode().splitlines():
        if 'warning: section' in line: continue
        print(line)


def _add_fake_vstuff_info_to_asm(sde_image_data=None, objdp_asm=None):
    assert(isinstance(sde_image_data, dict) and isinstance(objdp_asm, dict))


def _add_fake_vdso_info_to_asm(sde_image_data=None, objdp_asm=None):
    assert(isinstance(sde_image_data, dict) and isinstance(objdp_asm, dict))

    # can't find assembly of [vdso], and hence assume all is 'nop' instruction
    for NAME, ADDR_OFFSET, SIZE in sde_image_data['SYMBOLS'][1:]:
        curr_fn_os = int(ADDR_OFFSET, 16)
        os_str = '0x' + format(curr_fn_os, 'x')
        objdp_asm[curr_fn_os] = {'Offset': os_str,
                                 'Func': NAME,
                                 'ASM': [['0x' + format(x, 'x'), 'nop']
                                         for x in range(curr_fn_os,
                                                        curr_fn_os + SIZE)]}


def _parse_SOURCE_DATA(sde_image_data=None, src_data=None):
    assert(isinstance(sde_image_data, dict) and isinstance(src_data, dict))

    # "SOURCE_DATA" :
    #   [ [ "FILE_NAME_ID", "LINE_NUM", "ADDR_OFFSET", "SIZE", "NUM_INSTRS" ],
    #     [ 8, 25, "0x7a8", 4, 1 ],
    #     [ 8, 26, "0x7ac", 5, 1 ], ...
    #   ] -> FIXME: do we need this? maybe if we insert start/stop SDE cmd?
    return


def _parse_BASIC_BLOCKS(sde_image_data=None, sde_files=None, objdp_asm=None,
                        bb=None):
    assert(isinstance(sde_image_data, dict) and isinstance(sde_files, dict)
           and isinstance(objdp_asm, dict) and isinstance(bb, dict))

    # "BASIC_BLOCKS" :
    #   [ [ "NODE_ID", "ADDR_OFFSET", "SIZE", "NUM_INSTRS",
    #       "LAST_INSTR_OFFSET", "COUNT" ],
    #     [ 4, "0x7a8", 9, 2, 4, 1 ],
    #     [ 5, "0x7b1", 5, 1, 0, 9 ], ...
    #   ]
    # NODE_ID : is unique across the entire process
    # COUNT : total nr of times this block was executed across all threads
    #print('_parse_BASIC_BLOCKS', sde_image_data)
    #print('_parse_BASIC_BLOCKS', sde_files)
    #for x in objdp_asm: print('_parse_BASIC_BLOCKS', x, objdp_asm[x])
    #for x in bb: print('_parse_BASIC_BLOCKS', bb[x])
    for NODE_ID, ADDR_OFFSET, SIZE, NUM_INSTRS, _, COUNT in sde_image_data[
            'BASIC_BLOCKS'][1:]:
        if COUNT <= 0: continue
        #print('_parse_BASIC_BLOCKS', 'jj nnid',NODE_ID)
        fn_offset = _get_fn_os_for_block(objdp_asm, int(ADDR_OFFSET, 16))
        fn_name = objdp_asm[fn_offset]['Func']
        bb[NODE_ID] = {
            'Offset': '0x' + format(int(ADDR_OFFSET, 16), 'x'), 'Bytes': SIZE,
            'Func': fn_name, 'FuncOffset': fn_offset,
            'NumInst': NUM_INSTRS, 'ExecCnt': COUNT}
        if bb[NODE_ID]['Func'] is None:
            print('WRN 02: Cannot find block w/ offset %s in %s' %
                  (ADDR_OFFSET, sde_files[sde_image_data['FILE_NAME_ID']]))
            # can happen sometimes, SDE's SYMBOLS list seems incomplete, so
            # we should record the offset just in case we get ID/name later


def _get_fn_os_for_block(objdp_asm=None, bb_offset=None):
    assert(isinstance(objdp_asm, dict) and isinstance(bb_offset, int))

    for fn_offset in sorted(objdp_asm.keys(), reverse=False):
        if bb_offset >= fn_offset and \
                len(objdp_asm[fn_offset]['ASM']) > 0 and \
                bb_offset <= int(objdp_asm[fn_offset]['ASM'][-1][0], 16):
            return fn_offset  # objdp_asm[fn_offset]['Func']
    else:
        exit('ERR: symbol (0x%s) not found basic block' %
             format(bb_offset, 'x'))
        # return None


def _parse_ROUTINES(file_id=None, symbols=None, bb=None, routines=None):
    assert(isinstance(file_id, int) and isinstance(symbols, dict)
           and isinstance(bb, dict) and isinstance(routines, dict))

    # "ROUTINES" :  // XXX: no more SDE -> reverse engineer from symbols
    #  ...
    # ENTRY_NODE_ID : first block of a function
    # NODES : list of all blocks belonging to same function (and their
    #         immediate dominators)

    rev_map = {}
    #if file_id==54601002: print('_parse_ROUTINES', symbols)
    #if file_id==54601002: print('_parse_ROUTINES', bb)
    #if file_id==54601002: print('_parse_ROUTINES', routines)
    # first find all 'first blocks'
    for bid, bb_data in bb.items():
        for sy_os, sy_data in symbols.items():
            if int(sy_data['Offset'], 16) == bb_data['FuncOffset']:
                #if file_id==54601002: print('_parse_ROUTINES', 'jj1 setting', bid, bb_data, sy_os, sy_data)
                routines[bid] = [bid]
                rev_map[int(sy_data['Offset'], 16)] = bid
    #if 139906446259479 in bb: print('_parse_ROUTINES', 'jj mofo is there too', bb[139906446259479])
    # and then assign the rest
    for bid, bb_data in bb.items():
        for sy_os, sy_data in symbols.items():
            #if file_id==54601002: print('_parse_ROUTINES', 'jj2', bid, bb_data, sy_os, sy_data)
            if int(bb_data['Offset'], 16) > int(sy_data['Offset'], 16) and \
                    int(bb_data['Offset'], 16) < int(sy_data['Offset'], 16) + sy_data['Size']:
                routines[rev_map[int(sy_data['Offset'], 16)]].append(bid)
    # sort the result
    for r_data in routines.values():
        r_data.sort(reverse=False)


def _parse_EDGES(sde_edge_data=None, edges=None):
    assert(isinstance(sde_edge_data, list) and isinstance(edges, dict))

    # "EDGES" :     // XXX: self-edges are possible
    #   [ ["EDGE_ID", "SOURCE_NODE_ID", "TARGET_NODE_ID", "EDGE_TYPE_ID",
    #      "COUNT_PER_THREAD" ],
    #     [ 4810, 1683, 3002, 16, [ 0, 0, 1, 1, 1, 0 ] ],
    #     [ 3460, 1597, 1598, 18, [ 1, 0, 0, 0, 0, 0 ] ], ...
    #   ]
    for dataset in sde_edge_data[1:]:
        EDGE_ID, SRC_BLOCK_ID, TARGET_BLOCK_ID, EDGE_TYPE_ID = dataset[0:4]
        COUNT_PER_THREAD = dataset[4]

        if SRC_BLOCK_ID not in edges:
            edges[SRC_BLOCK_ID] = {}
        else:
            assert(TARGET_BLOCK_ID not in edges[SRC_BLOCK_ID])

        edges[SRC_BLOCK_ID][TARGET_BLOCK_ID] = {
            'EdgeTypeID': EDGE_TYPE_ID,
            'ThreadExecCnts': COUNT_PER_THREAD}


def parse_SDE_JSON(args=None, sde_data=None, arch=None):
    assert(isinstance(args, dict) and isinstance(sde_data, dict)
           and isinstance(arch, str))

    from json import load as jsonload

    # JSON information follows the DCFG specification from:
    # from software.intel.com/sites/default/files/managed/32/2d/DCFG-format.pdf
    sde_bb_json = jsonload(bz2open(path.realpath(args.get('__sde_json_f__')),
                                   'rt'))
    assert(sde_bb_json is not None and
           6 == len(sde_bb_json.keys()) and
           'MAJOR_VERSION' in sde_bb_json and
           'MINOR_VERSION' in sde_bb_json and
           'FILE_NAMES' in sde_bb_json and
           'EDGE_TYPES' in sde_bb_json and
           'SPECIAL_NODES' in sde_bb_json and
           'PROCESSES' in sde_bb_json)

    sde_data['Files'] = _parse_FILE_NAMES(sde_bb_json, arch)
    #print('parse_SDE_JSON', 'jj _parse_FILE_NAMES done', flush=True)
    # first need to get the assembly, from either real files or previous runs
    if args.get('__load_objdump__') is None:
        sde_data['ObjDumpAsm'] = _get_OBJDUMP_ASSEMBLY(sde_data['Files'])
    else:
        sde_data['ObjDumpAsm'] = _read_backup_OBJDUMP_ASSEMBLY(
            path.realpath(args.get('__load_objdump__')))
    if args.get('__store_objdump__') is not None:
        _store_backup_OBJDUMP_ASSEMBLY(
            sde_data['ObjDumpAsm'],
            path.realpath(args.get('__store_objdump__')))
        exit("INFO: intermediate store of objdump data complete;\n"
             "      rerun with --load_objd %s to complete the workflow"
             % args.get('__store_objdump__'))
    #print('parse_SDE_JSON', 'jj _get_OBJDUMP_ASSEMBLY done', flush=True)

    # and then continue with the rest
    sde_data['SpecialBlockIDs'] = _parse_SPECIAL_NODES(sde_bb_json)
    #print('parse_SDE_JSON', 'jj _parse_SPECIAL_NODES done', flush=True)
    sde_data['EdgeTypes'] = _parse_EDGE_TYPES(sde_bb_json)
    #print('parse_SDE_JSON', 'jj _parse_EDGE_TYPES done', flush=True)
    sde_data['Processes'] = _parse_PROCESSES(sde_bb_json, sde_data['Files'],
                                             sde_data['ObjDumpAsm'])
    #print('parse_SDE_JSON', 'jj _parse_PROCESSES done', flush=True)


def _get_helping_mappers(sde_data=None):
    assert(isinstance(sde_data, dict))

    # 'sde_data' :
    #   { 'Files': {},              // executable and libs belonging to it
    #     'SpecialBlockIDs': {},    // block IDs without real instr
    #     'EdgeTypes': {},          // types of control flow edges
    #     'Processes': {},          // data for each process ID
    #     'ObjDumpAsm': {},         // assembly of files collected from objdump
    #   }

    # create quick lookup tables:
    #       file ID -to- file name
    fid2fn, fn2fid = sde_data['Files'], {}
    for file_id, file_name in fid2fn.items():
        fn2fid[file_name] = file_id
    #       special block ID -to- special block name
    sbid2sbn, sbn2sbid = sde_data['SpecialBlockIDs'], {}
    for spec_blk_id, spec_blk_name in sbid2sbn.items():
        sbn2sbid[spec_blk_name] = spec_blk_id
    #       edge type ID -to- edge type name
    etid2etn, etn2etid = sde_data['EdgeTypes'], {}
    for et_id, et_name in etid2etn.items():
        etn2etid[et_name] = et_id

    # 'sde_data'/'Processes' :
    #   { 'FileIDs': {ID: { 'FileID': ID,
    #                       'Offset': 0xYZ,
    #                       'FNs': {},
    #                       'Blocks': {},
    #                       'Routines': {} } },
    #     'Edges': {SRC: {DST: {'EdgeTypeID': ID,
    #                           'ThreadExecCnts': list} } }
    #   }

    #       basic block ID -to- process ID
    #       basic block ID -to- file ID
    #       offset/file -to- basic block ID
    bbid2pid, bbid2fid, offs2bbid = {}, {}, {}
    for pid, pid_data in sde_data['Processes'].items():
        for fid in pid_data['FileIDs']:
            offs2bbid[fid] = {}
            #print('_get_helping_mappers', 'kk', pid_data['FileIDs'][fid]['Blocks'])
            for bid in pid_data['FileIDs'][fid]['Blocks']:
                assert(bid not in bbid2pid)
                bbid2pid[bid] = pid
                assert(bid not in bbid2fid)
                bbid2fid[bid] = fid
                offset = pid_data['FileIDs'][fid]['Blocks'][bid]['Offset']
                #print('_get_helping_mappers', fid, bid, offset)
                assert(offset not in offs2bbid[fid])
                offs2bbid[fid][offset] = bid
    #       basic block ID -to- "routine" primary basic block
    bbid2rpbb = {}
    for pid, pid_data in sde_data['Processes'].items():
        for fid in pid_data['FileIDs']:
            for bid in pid_data['FileIDs'][fid]['Blocks']:
                #if fid==54601002: print('_get_helping_mappers', pid_data['FileIDs'][fid]['Routines'])
                for rpbbid in pid_data['FileIDs'][fid]['Routines']:
                    if bid in pid_data['FileIDs'][fid]['Routines'][rpbbid]:
                        assert(bid not in bbid2rpbb)
                        bbid2rpbb[bid] = rpbbid
                        break
                else:
                    print('WRN 03: BB ID (%s) missing from "routines" of %s' %
                          (bid, fid2fn[fid]))
    #       "routine" primary basic block -to- function primary basic block
    rpbb2fpbb, fpbb2rpbb = {}, defaultdict(list)
    for pid, pid_data in sde_data['Processes'].items():
        for fid in pid_data['FileIDs']:
            for rpbbid in pid_data['FileIDs'][fid]['Routines']:
                rpbbid_os = \
                    pid_data['FileIDs'][fid]['Blocks'][rpbbid]['Offset']
                found = False
                for fn_os in sde_data['ObjDumpAsm'][fid]['FNs']:
                    fn_asm = sde_data['ObjDumpAsm'][fid]['FNs'][fn_os]
                    for offset, _ in fn_asm['ASM']:
                        if offset == rpbbid_os:
                            # XXX: SDE doesn't have some blocks, like .plt.got
                            if fn_asm['Offset'] in offs2bbid[fid]:
                                rpbb2fpbb[rpbbid] = \
                                    offs2bbid[fid][fn_asm['Offset']]
                            else:
                                rpbb2fpbb[rpbbid] = offs2bbid[fid][offset]
                                print('WRN 04:', pid, fid, rpbbid, offset)
                            found = True
                            break
                    if found:
                        break
                else:
                    print('WRN 05: BB ID (%s) missing from objdump of %s' %
                          (rpbbid, fid2fn[fid]))
    for rpbb, fpbb in rpbb2fpbb.items():
        fpbb2rpbb[fpbb].append(rpbb)
    #       function/file -to- func primary block  // XXX: fn names not unique
    func2fpbb, fpbb2func = {}, {}
    for pid, pid_data in sde_data['Processes'].items():
        for fid in pid_data['FileIDs']:
            func2fpbb[fid] = defaultdict(list)
            for rpbbid in pid_data['FileIDs'][fid]['Routines']:
                fpbb = rpbb2fpbb[rpbbid]
                # diff. routine BB IDs can point to same function primary BB ID
                if fpbb not in fpbb2func:
                    fpbb2func[fpbb] = \
                        pid_data['FileIDs'][fid]['Blocks'][fpbb]['Func']
                # stupid WRN 04 situation can lead to instance where two (or
                # more) rpbbIDs belong to same function but the function itself
                # has no primary block in our list (eg. __cpu_indicator_init)
                func2fpbb[fid][fpbb2func[fpbb]].append(fpbb)

    return (fid2fn, fn2fid, sbid2sbn, sbn2sbid, etid2etn, etn2etid, bbid2pid,
            bbid2fid, offs2bbid, bbid2rpbb, rpbb2fpbb, fpbb2rpbb, func2fpbb,
            fpbb2func)


def convert_sde_data_to_something_usable(sde_data=None):
    assert(isinstance(sde_data, dict))

    data = {}

    # ___Naming Scheme___
    # fid2fn/fn2fid        :  file names & file IDs
    # sbid2sbn/sbn2sbid    :  special block ID & special block name
    # etid2etn/etn2etid    :  edge type ID & edge type name
    # bbid2pid             :  basic block ID & process ID
    # bbid2fid             :  basic block ID & file ID
    # offs2bbid            :  offsets & basic blocks
    # bbid2rpbb            :  basic block ID & "routine" primary basic block
    # rpbb2fpbb/fpbb2rpbb  :  "routine" p. basic block & func. p. basic block
    # func2fpbb/fpbb2func  :  function name/file & func. p. basic block

    fid2fn, fn2fid, sbid2sbn, sbn2sbid, etid2etn, etn2etid, bbid2pid, \
        bbid2fid, offs2bbid, bbid2rpbb, rpbb2fpbb, fpbb2rpbb, func2fpbb, \
        fpbb2func = _get_helping_mappers(sde_data)
    mapper = {'fid2fn': fid2fn, 'fn2fid': fn2fid,
              'sbid2sbn': sbid2sbn, 'sbn2sbid': sbn2sbid,
              'etid2etn': etid2etn, 'etn2etid': etn2etid,
              'bbid2pid': bbid2pid, 'bbid2fid': bbid2fid,
              'offs2bbid': offs2bbid,
              'bbid2rpbb': bbid2rpbb,
              'rpbb2fpbb': rpbb2fpbb, 'fpbb2rpbb': fpbb2rpbb,
              'func2fpbb': func2fpbb, 'fpbb2func': fpbb2func}

    maybe_sinks = set()
    for pid, pid_data in sde_data['Processes'].items():
        for source_bb in pid_data['Edges']:

            # if no edge in and no edge out, then ignore this block
            in_edges, out_edges = {}, {}
            for block, edges in pid_data['Edges'].items():
                # XXX: self-edges (source_bb == block ID) are possible!!!!!!!
                if source_bb == block and not source_bb not in edges:
                    continue
                elif source_bb in edges and \
                        sum(edges[source_bb]['ThreadExecCnts']) > 0:
                    in_edges[block] = deepcopy(edges[source_bb])
            for target_bb, edge_data in pid_data['Edges'][source_bb].items():
                if sum(edge_data['ThreadExecCnts']) > 0:
                    out_edges[target_bb] = deepcopy(edge_data)

            if len(in_edges) == 0 and len(out_edges) == 0:
                continue

            # get some metadata for block, but careful with special snowflakes
            if source_bb in sbid2sbn:
                func, file_name = sbid2sbn[source_bb], 'N/A'
            else:
                func = fpbb2func[rpbb2fpbb[bbid2rpbb[source_bb]]]
                file_name = fid2fn[bbid2fid[source_bb]]

            # get AT&T assembly for the block
            if source_bb in sbid2sbn:
                asm = [['0xffffffffffffffff', 'nop']]
            else:
                fid = bbid2fid[source_bb]
                blk_data = pid_data['FileIDs'][fid]['Blocks'][source_bb]
                objdp_asm = \
                    sde_data['ObjDumpAsm'][fid]['FNs'][blk_data['FuncOffset']]
                # sometimes blocks start in middle of other instructions, e.g.
                #    XDIS 4835ff: BINARY    BASE       00C3    add %al, %bl
                # and the PC jumps to 483600 and executes the C3 (meaning a
                # "ret" instruction...) -> these blocks won't be found in
                # native objdump data, so we have to get it manually ;-(
                try:
                    idx = [offset
                           for offset, _
                           in objdp_asm['ASM']].index(blk_data['Offset'])
                    asm = objdp_asm['ASM'][idx:idx + blk_data['NumInst']]
                except BaseException:
                    print('WRN 06: odd block; could not find [bb=%s] %s in %s'
                          % (source_bb, blk_data['Offset'], file_name)
                          + ' (perform fuzzy _get_single_block_from_OBJDUMP)')
                    asm = _get_single_block_from_OBJDUMP(
                        file_name, int(blk_data['Offset'], 16),
                        blk_data['Bytes'], sde_data['ObjDumpAsm'][fid]['LO'])
                    pass
                if len(asm) != blk_data['NumInst']:
                    print('WRN 07: strange block ID %s in fn %s (%s) with a'
                          % (source_bb, func, file_name)
                          + ' mismatch in len(asm) and instructions (%s vs %s)'
                          % (len(asm), blk_data['NumInst']) + '; please check')

            data[source_bb] = {'ID': source_bb,
                               'File': file_name,
                               'Func': func,
                               'ASM': asm,
                               'NumASM': len(asm),
                               'in_edges': in_edges,
                               'out_edges': out_edges}
            maybe_sinks.update(out_edges.keys())

            #if len(in_edges)>0 and len(out_edges)>0:
            #    print('jens:', source_bb)
            #    print('IN:', in_edges)
            #    for b in in_edges:
            #        if b in data: print(data[b])
            #    print('SELF:', data[source_bb])
            #    print('out:', out_edges)
            #    for b in out_edges:
            #        if b in data: print(data[b])


    for sink_bb in maybe_sinks:
        # only process remaining real sinks
        if sink_bb not in data:
            in_edges = {}
            for block, edges in pid_data['Edges'].items():
                if sink_bb in edges and \
                        sum(edges[sink_bb]['ThreadExecCnts']) > 0:
                    in_edges[block] = deepcopy(edges[sink_bb])

            # get some metadata for block, but careful with special snowflakes
            if sink_bb in sbid2sbn:
                func, file_name = sbid2sbn[sink_bb], 'N/A'
            else:
                func = fpbb2func[rpbb2fpbb[bbid2rpbb[sink_bb]]]
                file_name = fid2fn[bbid2fid[sink_bb]]

            # get AT&T assembly for the block
            if sink_bb in sbid2sbn:
                asm = [['0xffffffffffffffff', 'nop']]
            else:
                fid = bbid2fid[sink_bb]
                blk_data = pid_data['FileIDs'][fid]['Blocks'][sink_bb]
                objdp_asm = \
                    sde_data['ObjDumpAsm'][fid]['FNs'][blk_data['FuncOffset']]
                # sometimes blocks start in middle ... (see complaint above)
                try:
                    idx = [offset
                           for offset, _
                           in objdp_asm['ASM']].index(blk_data['Offset'])
                    asm = objdp_asm['ASM'][idx:idx + blk_data['NumInst']]
                except BaseException:
                    print('WRN 08: odd block; could not find [bb=%s] %s in %s'
                          % (sink_bb, blk_data['Offset'], file_name)
                          + ' (perform fuzzy _get_single_block_from_OBJDUMP)')
                    asm = _get_single_block_from_OBJDUMP(
                        file_name, int(blk_data['Offset'], 16),
                        blk_data['Bytes'], sde_data['ObjDumpAsm'][fid]['LO'])
                    pass
                if len(asm) != blk_data['NumInst']:
                    print('WRN 09: strange block ID %s in fn %s (%s) with a'
                          % (sink_bb, func, file_name)
                          + ' mismatch in len(asm) and instructions (%s vs %s)'
                          % (len(asm), blk_data['NumInst']) + '; please check')

            data[sink_bb] = {'ID': sink_bb,
                             'File': file_name,
                             'Func': func,
                             'ASM': asm,
                             'NumASM': len(asm),
                             'in_edges': in_edges,
                             'out_edges': {}}

    return (data, mapper)


def simulate_cycles_with_IACA(keep=False, arch=None, blkdata=None,
                              branches=None):
    assert(isinstance(keep, bool) and isinstance(arch, str)
           and isinstance(blkdata, dict) and isinstance(branches, list))

    ARCHS = deepcopy(KNOWN_ARCHS)
    ARCHS['broadwell'] = 'BDW'
    ARCHS['haswell'] = 'HSW'
    ARCHS['skylake'] = 'SKL'
    ARCHS['skylake_avx512'] = 'SKX'
    assert(ARCHS[arch])

    for bbid, sink_bbid, _ in branches:
        edge_data = blkdata[bbid]['out_edges'][sink_bbid]

        selfloop, twoblockloop = (bbid == sink_bbid), \
            (bbid != sink_bbid and bbid in blkdata[sink_bbid]['out_edges'])

        # Intel's IACA needs binary, so dump code to ramdisk and compile it
        iaca_in_fn = '/dev/shm/iaca_%s_%s_%s.c' % (getpid(), bbid, sink_bbid)

        num_instr_in_input = 0
        with open(iaca_in_fn, 'w') as iaca_in_file:
            iaca_in_file.write('#include<iacaMarks.h>\n' +
                               'void foo(){\n' +
                               '    IACA_START;\n' +
                               '     __asm__(\n');

            if not selfloop:
                iaca_in_file.write('\n'.join(['"%s\\n\\t"'
                                              % sub(r'rep[nz]{,2}\s+nop\s+.*',  # Error: invalid instruction `nop' after `repz'
                                                    r'nop',
                                                    instr.split('#')[0].strip(),
                                                    count=0, flags=IGNORECASE)
                                              for _, instr
                                              in blkdata[bbid]['ASM']])
                                   + '\n')
                num_instr_in_input += len(blkdata[bbid]['ASM'])

            iaca_in_file.write('\n'.join(['"%s\\n\\t"'
                                          % sub(r'rep[nz]{,2}\s+nop\s+.*',      # Error: invalid instruction `nop' after `repz'
                                                r'nop',
                                                instr.split('#')[0].strip(),
                                                count=0, flags=IGNORECASE)
                                          for _, instr
                                          in blkdata[sink_bbid]['ASM']])
                               + '\n')
            num_instr_in_input += len(blkdata[sink_bbid]['ASM'])

            iaca_in_file.write('             );\n' +
                               '    IACA_END;\n' +
                               '}\n')

        # compile first, must? use -O0 since its assembly and shouldn't
        # be removed switch to gcc cause intel fails to inject its own
        # assembly, FUCKING HELL...
        # (sometimes linker fucks up, but IACA also takes in *.o  *facepalm*)
        p = run(['gcc', '-c', '-O0',
                 '-I%s' % (environ['IACAINCL']
                           if 'IACAINCL' in environ else '.'),
                 '-o', '%s.o' % iaca_in_fn,
                 iaca_in_fn], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.stdout.decode(), p.stderr.decode()
        if 0 != p.returncode:
            with open(iaca_in_fn, 'r') as iaca_in_file:
                print('ERR in gcc compile:\nstdout: ', stdout,
                      '\nstderr: ', stderr, '  for input (%s):\n```\n%s\n```\n'
                      % (iaca_in_fn, iaca_in_file.read()))
            continue

        # check block throughput with Intel's analysis tool
        p = run(['iaca',
                 '-arch', ARCHS[arch],
                 '-trace-cycle-count', '%s' % max(1024, 3 * num_instr_in_input),
                 '-trace', '%s.t' % iaca_in_fn,
                 '%s.o' % iaca_in_fn], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.stdout.decode(), p.stderr.decode()
        if 0 != p.returncode:
            with open(iaca_in_fn, 'r') as iaca_in_file:
                print('ERR in iaca:\nstdout: ', stdout, '\nstderr: ', stderr,
                      '  for input (%s):\n```\n%s\n```\n'
                      % (iaca_in_fn, iaca_in_file.read()))
            continue

        if selfloop or twoblockloop:
            cycles = search(r'Block\s+Throughput:' +
                            r'\s+([-+]?\d*\.\d+|\d+)\s+Cycles',
                            stdout, IGNORECASE)
            cycles = float(cycles.group(1))
        else:
            tl_pipe = compile(r'^\s*(\d+)\|\s*(\d+)\|\s+TYPE_.*\s+' +
                              r':([\s|]*[\sAscdweRp\-_]+)(?:[\s|]+)?$')
            prev_inst_nr, timeline_data = -1, []
            with open('%s.t' % iaca_in_fn, 'r') as iaca_tl_file:
                for line in iaca_tl_file:
                    tl = tl_pipe.match(line)
                    if not tl:
                        continue

                    iter_nr, inst_nr, timeline = \
                        int(tl.group(1)), int(tl.group(2)), tl.group(3).rstrip()
                    if timeline.find('R') < 0:
                        print('WRN 14: retirement indicator missing from' +
                              ' inst %s of basic block chain (%s->%s)'
                              % (inst_nr, bbid, sink_bbid))
                    # sometimes we have gaps if iaca processes unsupported inst
                    # we just replicate the last known valid instruction
                    for nr in range(prev_inst_nr + 1, inst_nr):
                        timeline_data.append(
                            [nr, timeline_data[prev_inst_nr][1]
                                    if prev_inst_nr >= 0 else 'R'])
                    # and now store the real one, but check if we already had
                    # (in which case we overwrite if new retire is later)
                    if len(timeline_data) and timeline_data[-1][0] == inst_nr:
                        if timeline_data[-1][1].find('R') < timeline.find('R'):
                            timeline_data[-1] = [inst_nr, timeline]
                    else:
                        timeline_data.append([inst_nr, timeline])
                    prev_inst_nr = inst_nr
                    if iter_nr > 0:
                        break

                else:
                    print('WRN 15: basic block chain (%s->%s)'
                          % (bbid, sink_bbid) +
                          ' was longer than expected; try increasing' +
                          ' trace-cycle-count for iaca')
                    continue

            cycles = \
                timeline_data[-1][1].find('R') \
                - timeline_data[blkdata[bbid]['NumASM'] - 1][1].find('R')

        # clean up the temp file under /dev/shm
        if not keep:
            if path.isfile(iaca_in_fn):
                remove(iaca_in_fn)
            if path.isfile('%s.t' % iaca_in_fn):
                remove('%s.t' % iaca_in_fn)
            if path.isfile('%s.o' % iaca_in_fn):
                remove('%s.o' % iaca_in_fn)

        notes = search(r'Analysis\s+Notes:\n(.*)',
                       stdout, flags=DOTALL|IGNORECASE)
        if notes:
            notes = notes.group(1)

            notes = sub(r'Backend allocation was stalled due to unavailable' +
                        r' allocation resources.\n',
                        r'', notes, count=0, flags=IGNORECASE)
            unsupp = search(r'There was an unsupported instruction(s), it' +
                            r' was not accounted in Analysis.',
                            notes, flags=IGNORECASE)
            if unsupp and 0 >= cycles:
                continue

            if len(notes):
                print(notes)

        if cycles < 0:
            print('WRN 16: basic block chain (%s->%s)'
                  % (bbid, sink_bbid) +
                  ' resulted in negative cycles; this makes no sense')
            continue
        if twoblockloop:
            cycles /= 2
        # rare cases with two blocks ending at same cycle, but they're legit
        if cycles == 0:
            cycles = pow(10, -10)

        if cycles:
            edge_data['CyclesPerIter'][1] = cycles


def simulate_cycles_with_uiCA(keep=False, arch=None, blkdata=None,
                              branches=None):
    assert(isinstance(keep, bool) and isinstance(arch, str)
           and isinstance(blkdata, dict) and isinstance(branches, list))

    ARCHS = deepcopy(KNOWN_ARCHS)
    ARCHS['sandybridge'] = 'SNB'
    ARCHS['ivybridge'] = 'IVB'
    ARCHS['haswell'] = 'HSW'
    ARCHS['broadwell'] = 'BDW'
    ARCHS['skylake'] = 'SKL'
    ARCHS['skylake_avx512'] = 'SKX'
    ARCHS['cascadelake'] = 'CSX'
    ARCHS['icelake'] = 'ICL'
    ARCHS['kabylake'] = 'KBL'
    ARCHS['coffeelake'] = 'CFL'
    ARCHS['tigerlake'] = 'TGL'
    ARCHS['rocketlake'] = 'RKL'
    assert(ARCHS[arch])

    for bbid, sink_bbid, _ in branches:
        edge_data = blkdata[bbid]['out_edges'][sink_bbid]

        selfloop, twoblockloop = (bbid == sink_bbid), \
            (bbid != sink_bbid and bbid in blkdata[sink_bbid]['out_edges'])

        # use Intel's IACA binary, which was already created/compiled
        uica_in_fn = '/dev/shm/iaca_%s_%s_%s.c' % (getpid(), bbid, sink_bbid)

        num_instr_in_input = len(blkdata[sink_bbid]['ASM'])
        if not selfloop:
            num_instr_in_input += len(blkdata[bbid]['ASM'])

        # check block throughput with uiCA analysis tool
        p = run(['python3',
                 '%s/uiCA.py' % environ['UICADIR'],
                 '-arch', ARCHS[arch],
                 '-iacaMarkers',
                 '-trace', '%s.html' % uica_in_fn,
                 '%s.o' % uica_in_fn], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.stdout.decode(), p.stderr.decode()
        if 0 != p.returncode:
            with open(uica_in_fn, 'r') as uica_in_file:
                print('ERR in uica:\nstdout: ', stdout, '\nstderr: ', stderr,
                      '  for input (%s):\n```\n%s\n```\n'
                      % (uica_in_fn, uica_in_file.read()))
            continue

        if selfloop or twoblockloop:
            cycles = search(r'^Throughput:\s+([-+]?\d*\.\d+|\d+)',
                            stdout, IGNORECASE)
            cycles = float(cycles.group(1))
        else:
            with open('%s.html' % uica_in_fn) as uica_tl_file:
                for line in uica_tl_file:
                    tl_data = search(r'\s*var tableData =\s+(.*)', line)
                    if not tl_data:
                        continue
                    else:
                        break

                # ASM sequence are printed multiple times
                prev_inst_nr, inst_nr, timeline_data = -1, 0, []
                for inst_group in jsonloads(tl_data.group(1)):
                    for inst in inst_group:
                        if len([1 for uop in inst['uops']
                                if 'R' in uop['events'].values()]) < 1:
                            print('WRN 17: retirement indicator missing from' +
                                  ' inst %s of basic block chain (%s->%s)'
                                  % (inst_nr, bbid, sink_bbid))
                            continue

                        # not sure, but lets see if have to fill gaps here, too
                        for nr in range(prev_inst_nr + 1, inst_nr):
                            timeline_data.append(
                                [nr, timeline_data[prev_inst_nr][1]
                                        if prev_inst_nr >= 0 else 0])

                        # and now store the real one, but check if we already
                        # had one uop (in which case we overwrite if new retire
                        # is later)
                        prev_set = False
                        for uop in inst['uops']:
                            for ret_cycle, pipeline_op in uop['events'].items():
                                if 'R' != pipeline_op:
                                    continue
                                ret_cycle = int(ret_cycle)
                                if len(timeline_data) and prev_set:
                                    if timeline_data[-1][1] < ret_cycle:
                                        timeline_data[-1][1] = ret_cycle
                                else:
                                    timeline_data.append([inst_nr, ret_cycle])
                                    prev_set = True

                        prev_inst_nr = inst_nr
                        inst_nr += 1
                    # stop after first full group
                    break

            cycles = timeline_data[-1][1] - \
                timeline_data[blkdata[bbid]['NumASM'] - 1][1]

        # clean up the temp file under /dev/shm
        if not keep:
            if path.isfile(uica_in_fn):
                remove(uica_in_fn)
            if path.isfile('%s.t' % uica_in_fn):
                remove('%s.t' % uica_in_fn)
            if path.isfile('%s.o' % uica_in_fn):
                remove('%s.o' % uica_in_fn)
            if path.isfile('%s.html' % uica_in_fn):
                remove('%s.html' % uica_in_fn)

        if cycles < 0:
            print('WRN 17: basic block chain (%s->%s)'
                  % (bbid, sink_bbid) +
                  ' resulted in negative cycles; this makes no sense')
            continue
        if twoblockloop:
            cycles /= 2
        # rare cases with two blocks ending at same cycle, but they're legit
        if cycles == 0:
            cycles = pow(10, -10)

        if cycles:
            edge_data['CyclesPerIter'][2] = cycles


def simulate_cycles_with_OSACA(keep=False, arch=None, blkdata=None,
                               branches=None):
    assert(isinstance(keep, bool) and isinstance(arch, str)
           and isinstance(blkdata, dict) and isinstance(branches, list))

    ARCHS = deepcopy(KNOWN_ARCHS)
    ARCHS['sandybridge'] = 'SNB'
    ARCHS['ivybridge'] = 'IVB'
    ARCHS['haswell'] = 'HSW'
    ARCHS['broadwell'] = 'BDW'
    ARCHS['skylake_avx512'] = 'SKX'
    ARCHS['cascadelake'] = 'CSX'
    ARCHS['icelake'] = 'ICL'
    ARCHS['zen'] = 'ZEN1'
    ARCHS['zen2'] = 'ZEN2'
    ARCHS['thunderx2'] = 'TX2'
    ARCHS['aarch64'] = 'N1'
    ARCHS['a64fx'] = 'A64FX'
    assert(ARCHS[arch])

    oparser = osaca.create_parser()
    oargs = oparser.parse_args(['--arch', ARCHS[arch],
                                '--ignore-unknown', '--verbose',
                                '--lcd-timeout', '60',
                                path.realpath(__file__)])
    osaca.check_arguments(oargs, oparser)
    osaca_res_line = compile(r'^[\d\s\.]+$')
    bak_machine_model_pickle, bak_machine_isa_pickle = None, None

    for bbid, sink_bbid, _ in branches:
        edge_data = blkdata[bbid]['out_edges'][sink_bbid]

        selfloop, twoblockloop = (bbid == sink_bbid), \
            (bbid != sink_bbid and bbid in blkdata[sink_bbid]['out_edges'])

        # sadly OSACA has no timeline, so result will be a lower bound and
        # slightly overestimating the performance for blocks which are not
        # self-/twoloop
        if not selfloop and not twoblockloop:
            print('WRN 13: osaca estimating cycles of non-trivial blk chain' +
                  ' %s->%s' % (bbid, sink_bbid))
            #return None

        osaca_in_fn = '/dev/shm/osaca_%s_%s_%s.s' % (getpid(), bbid, sink_bbid)

        with open(osaca_in_fn, 'w') as osaca_in_file:
            osaca_in_file.write('# OSACA-BEGIN\n');

            if not selfloop:
                osaca_in_file.write('\n'.join([sub(r'jmpq\s+\*%ds:', r'jmpq *', # osaca parser currently fails for 'jmpq *%ds:0x...'
                                                   instr,
                                                   count=0, flags=IGNORECASE)
                                               for _, instr
                                               in blkdata[bbid]['ASM']])
                                    + '\n')
            osaca_in_file.write('\n'.join([sub(r'jmpq\s+\*%ds:', r'jmpq *',
                                               instr, count=0, flags=IGNORECASE)
                                           for _, instr
                                           in blkdata[sink_bbid]['ASM']])
                                + '\n')

            osaca_in_file.write('# OSACA-END\n')

        # overwrite stdout with special output stream
        osaca_out = StringIO()
        try:
            with open(osaca_in_fn, 'r') as osaca_in_file:
                oargs.file = osaca_in_file
                bak_machine_model_pickle, bak_machine_isa_pickle = \
                    osaca.run(oargs, output_file=osaca_out,
                              mmodel=bak_machine_model_pickle,
                              misa=bak_machine_isa_pickle)
        except:
            with open(osaca_in_fn, 'r') as osaca_in_file:
                print('ERR in osaca:\n%s\n' % osaca_out.getvalue(),
                      '  for asm input (%s):\n```\n%s\n```\n'
                      % (osaca_in_fn, osaca_in_file.read()))
            continue

        # clean up the temp file under /dev/shm
        if not keep:
            if path.isfile(osaca_in_fn):
                remove(osaca_in_fn)

        # results listed without special prefix, but should only contain numbers
        cycles = None
        for line in osaca_out.getvalue().split('\n'):
            if osaca_res_line.match(line):
                cycles = [float(nr)
                          for nr in findall(r'[-+]?\d*\.\d+|\d+', line)]

        if len(cycles) < 3:
            continue

        throughput, crit_path, loop_carried_dep = \
            max(cycles[0:-2]), cycles[-2], cycles[-1]

        # osaca devs: block runtime is estimated by =max(TP, LCD)
        cycles = float(max(throughput, loop_carried_dep))
        if twoblockloop:
            cycles /= 2
        # rare cases with two blocks ending at same cycle, but they're legit
        if cycles == 0:
            cycles = pow(10, -10)

        # not sure which estimate is more accurate -> take the mean
        if cycles:
            edge_data['CyclesPerIter'][3] = cycles


def _fix_stupid_llvmasm_and_mca_quirks(asm=None, num_asm=None):
    assert(isinstance(asm, list) and isinstance(num_asm, int))

    asm_out = []
    # XXX handle exceptions:
    for asm_os, asm_in in asm:
        # XXX: x86/broadwell
        # llvm hates: `bnd jmpq *%r11`, check llvm-objdump to replace
        asm_in = sub(r'^bnd\s+jmpq', r'repne\njmpq', asm_in,
                     count=0, flags=IGNORECASE)
        # llvm hates: `fs addr32 nop`, check llvm-objdump to replace
        asm_in = sub(r'^fs\s+addr32\s+nop', r'nop', asm_in,
                     count=0, flags=IGNORECASE)
        # llvm hates: `ds jmpq ...`, check llvm-objdump to replace
        asm_in = sub(r'^ds\s+jmpq\s+\*', r'jmpq *', asm_in,
                     count=0, flags=IGNORECASE)
        # llvm hates: `jg,pt ...`, check llvm-objdump to replace
        asm_in = sub(r'^jg,pt\s+', r'jg ', asm_in,
                     count=0, flags=IGNORECASE)
        # llvm hates: `fldenv ...`, which sends llvm-mca into a
        # lifelock, so instead of load we store and hope it's similar
        asm_in = sub(r'fldenv\s+', r'frstor ', asm_in,
                     count=0, flags=IGNORECASE)
        # compiler doesnt like `data16 data16 ... <op>`
        for x in [16, 32]:
            asm_in = sub(r'^(data%s\s){2,}' % x, r'data%s ' % x, asm_in,
                         count=0, flags=IGNORECASE)
        # mca likes neither rex.W nor .byte 0x*
        asm_in = sub(r'^(rex.W$|\.byte\s+0x.*)', r'nop #\1', asm_in,
                     count=0, flags=IGNORECASE)
        # XXX: aarch64/a64fx
        # mca needs tbz and tbnz instructions with label or integer pc offset
        # (not hex) -> ignore 0x part and add + or - as offset indicator
        asm_in = sub(r'^([tc]b[n]{0,1}z\s+.*)(0x\w+)$', lambda m: m.group(1)+hex(int(m.group(2),16)-int(asm_os,16)), asm_in,
                     count=0, flags=IGNORECASE)
        # same for b.eq/b.ne/...
        #print('_fix_stupid_llvmasm_and_mca_quirks', asm_os, asm_in)
        asm_in = sub(r'^(b.[a-z]{2}\s+.*)(0x\w+)$', lambda m: m.group(1)+hex(int(m.group(2),16)-int(asm_os,16)), asm_in,
                     count=0, flags=IGNORECASE)
        #if int(asm_os,16)==int('0x1886c',16):
        #    print(asm_os, asm_in)
        #    exit()
        # same for adr
        asm_in = sub(r'^(adr\s+.*)(0x\w+)$', lambda m: m.group(1)+hex(int(m.group(2),16)-int(asm_os,16)), asm_in,
                     count=0, flags=IGNORECASE)

        asm_out.append([asm_os, asm_in])

    return (asm_out, num_asm)

def simulate_cycles_with_LLVM_MCA(blockdata=None, mapper=None, arch=None,
                                  keep=False):
    assert(isinstance(blockdata, dict) and isinstance(mapper, dict)
           and isinstance(arch, str) and isinstance(keep, bool))

    # make the llvm-mca simulation more realistic / first step from gut feeling
    # assuming we have 3 basic blocks (random index fn of ld-linux-x86-64.so.2)
    # 1.
    #   mov    %rdi,%rdx
    #   and    $0x7,%edx
    #   mov    %rdi,%rax
    #   je     0x19c2a
    # 2.
    #   neg    %edx
    #   add    $0x8,%edx
    # 3.
    #   mov    (%rax),%cl
    #   cmp    %cl,%sil
    #   je     0x19da0
    # getting the timeline for each of them individually looks like this:
    #   [0,0]     DeER .  movq  %rdi, %rdx
    #   [0,1]     D=eER.  andl  $7, %edx
    #   [0,2]     DeE-R.  movq  %rdi, %rax
    #   [0,3]     D==eER  je   105514
    #  and
    #   [0,0]     DeER.   negl  %edx
    #   [0,1]     D=eER   addl  $8, %edx
    #  and
    #   [0,0]     DeeeeeER .   movb     (%rax), %cl
    #   [0,1]     D=====eER.   cmpb     %cl, %sil
    #   [0,2]     D======eER   je       105888
    # so 1. needs 6 cycles; second needs 5 cycles; last needs 10 cycles
    # but this is awfully pessimistic, so what if we add the previous block as
    # "preheating" phase and check the instruction retirement instead of the
    # pure cycles we can get more reasonable results maybe
    # assuming we combine 2. and 3. block for example:
    #   [0,0]     DeER .   .   negl     %edx
    #   [0,1]     D=eER.   .   addl     $8, %edx
    #   [0,2]     DeeeeeER .   movb     (%rax), %cl
    #   [0,3]     D=====eER.   cmpb     %cl, %sil
    #   [0,4]     .D=====eER   je       105888
    # and check the difference from last R of 2. block to last R of 3. block,
    # which is 5, or 10 respectively... meaning the "runtime for the 3. block
    # is 10-5=5 cycles and not 10 as predicted for standalone kernel

    asm_cnt = compile(r'^Instructions:\s+(\d+)$')
    cyc_cnt = compile(r'^Total\s+Cycles:\s+(\d+)$')
    rtp_cnt = compile(r'^Block\s+RThroughput:\s+(\d+)$')
    tl_pipe = compile(r'^(\[[\d,]+)\]\s+([\.D]+[DReE=\-\.\s]+)\s+([\.\(]?\w{1,}.*)$')

    # info from `llvm-mca -mtriple=ARCH-unknown-linux-gnu -mcpu=help /dev/null`
    # ARCH can be x86-64, aarch64, ppc64, sparc[v9] (more: `llvm-mca -version`)
    ARCHS = deepcopy(KNOWN_ARCHS)
    ARCHS['broadwell'] = ['x86_64', 'broadwell']
    ARCHS['cannonlake'] = ['x86_64', 'cannonlake']
    ARCHS['cascadelake'] = ['x86_64', 'cascadelake']
    ARCHS['core2'] = ['x86_64', 'core2']
    ARCHS['haswell'] = ['x86_64', 'haswell']
    ARCHS['icelake'] = ['x86_64', 'icelake-server']
    ARCHS['ivybridge'] = ['x86_64', 'ivybridge']
    ARCHS['mic_knl'] = ['x86_64', 'knl']
    ARCHS['nehalem'] = ['x86_64', 'nehalem']
    ARCHS['sandybridge'] = ['x86_64', 'sandybridge']
    ARCHS['skylake'] = ['x86_64', 'skylake']
    ARCHS['skylake_avx512'] = ['x86_64', 'skylake-avx512']
    ARCHS['westmere'] = ['x86_64', 'westmere']
    ARCHS['x86_64'] = ['x86_64', 'x86-64']
    ARCHS['aarch64'] = ['aarch64', 'generic']
    ARCHS['thunderx2'] = ['aarch64', 'thunderx2t99']
    ARCHS['a64fx'] = ['aarch64', 'a64fx'] #'generic -mattr=+fp-armv8,+v8.2a,+neon,+sve']
    ARCHS['power7'] = ['ppc64', 'pwr7']
    ARCHS['power8'] = ['ppc64', 'pwr8']
    ARCHS['power9'] = ['ppc64', 'pwr9']
    assert(ARCHS[arch])

    #fid2fn_m, bbid2fid_m, sbid2sbn_m = \
    #    mapper['fid2fn'], mapper['bbid2fid'], mapper['sbid2sbn']
    #filter_list = [] #['/libmpi.so', '/libmpifort.so',
    #                 # '/librdmacm.so', '/libibverbs.so',
    #                 # '/libibverbs/', '/libfabric/']

    for bbid, bdata in blockdata.items():
        for sink_bbid, edge_data in bdata['out_edges'].items():

            sink_bdata = blockdata[sink_bbid]

            # if either of the blocks (or both) is a part of a filtered file
            # (like libmpi) then simply set the block's CPU cycles to 0
            #blocks_on_filter_list = False
            #for filter_n in filter_list:
            #    if bbid in sbid2sbn_m or sink_bbid in sbid2sbn_m:
            #        break
            #    if fid2fn_m[bbid2fid_m[sink_bbid]].find(filter_n) > -1 or \
            #            fid2fn_m[bbid2fid_m[bbid]].find(filter_n) > -1:
            #        edge_data['CyclesPerIter'] = 0
            #        blocks_on_filter_list = True
            #if blocks_on_filter_list:
            #    continue

            # llvm-mca read assembly from file, so dump a copy to ramdisk
            mca_in_fn = '/dev/shm/asm_%s_%s_%s.s' % (getpid(), bbid, sink_bbid)

            selfloop, twoblockloop, icnt = (bbid == sink_bbid), \
                (bbid != sink_bbid and bbid in sink_bdata['out_edges']), 1
            # (1) self-edges indicate long running loops and compute phases
            # hence we skip adding sink_block and increase iteration count
            # (2) in case of a two-block loop we do that too but merge assembly
            # but need to /2 the cycles, because the loop is counted twice
            if selfloop or twoblockloop:
                icnt = 1000

            bdata_asm, num_asm_bbid = _fix_stupid_llvmasm_and_mca_quirks(bdata['ASM'], bdata['NumASM'])
            sink_bdata_asm, num_asm_sink_bbid = _fix_stupid_llvmasm_and_mca_quirks(sink_bdata['ASM'], sink_bdata['NumASM'])

            with open(mca_in_fn, 'w') as mca_in_file:
                if not selfloop:
                    mca_in_file.write('\n'.join([instr for _, instr in bdata_asm]) + '\n')
                mca_in_file.write('\n'.join([instr for _, instr in sink_bdata_asm]) + '\n')

            # mtriple: see http://clang.llvm.org/docs/CrossCompilation.html
            # get 'Total Cycles' from llvm-mca for each basic block
            p = run(['llvm-mca',
                     '--mtriple=%s-unknown-linux-gnu' % ARCHS[arch][0],
                     '--mcpu=%s' % ARCHS[arch][1],
                     '--iterations=%s' % icnt,
                     '-timeline',
                     '-timeline-max-iterations=1',
                     '-timeline-max-cycles=%s' % pow(2, 31), # call asm is long
                     '-all-stats',
                     '-print-imm-hex', mca_in_fn], stdout=PIPE, stderr=PIPE)

            stderr = p.stderr.decode()
            stderr = sub(r'warning: found a return instruction in the input' +
                         ' assembly sequence.\nnote: program counter updates' +
                         ' are ignored.\n',
                         r'', stderr, count=0, flags=IGNORECASE)
            stderr = sub(r'warning: found a call in the input assembly' +
                         ' sequence.\nnote: call instructions are not' +
                         ' correctly modeled. Assume a latency of 100cy.\n',
                         r'', stderr, count=0, flags=IGNORECASE)
            if len(stderr):
                with open(mca_in_fn, 'r') as mca_in_file:
                    print('ERR in llvm-mca:\nstderr: ', stderr,
                          '  for input (%s):\n```\n%s\n```\n'
                          % (mca_in_fn, mca_in_file.read()))
                exit()

            num_instr, num_cycles, timeline_data = 0, 0, []
            for line in p.stdout.decode().splitlines():
                if asm_cnt.match(line):
                    num_instr = int(asm_cnt.match(line).group(1).strip())

                elif cyc_cnt.match(line):
                    num_cycles = int(cyc_cnt.match(line).group(1).strip())

                elif rtp_cnt.match(line):
                    # RThroughput is reciprocal of maximum number of blocks
                    # that can be executed per clock cycle (assume: no LCD)
                    rthroughput = float(rtp_cnt.match(line).group(1).strip())
                    # tp = 1/rthroughput; NOTE: if LCD is ignored then the
                    # resulting number is rather useless (which is why OSACA
                    # uses max(TP,LCD) => so ignore the rthroughput hereafter
                    # and stick to Total Cycles / Iterations

                elif tl_pipe.match(line):
                    tl = tl_pipe.match(line)
                    index, timeline, asm = \
                        tl.group(1).strip(), tl.group(2).strip(), \
                        tl.group(3).strip()
                    timeline_data.append([index, timeline, asm])

            #if (num_instr != len(timeline_data) and num_instr != icnt * len(timeline_data)): print('jj', num_instr,len(timeline_data))
            assert(num_instr == len(timeline_data)              # merge 2 blk
                   or num_instr == icnt * len(timeline_data))   # self-edge

            # getting avg. estimated cycles per block is easy for self-edges
            if selfloop:
                cycles_per_iter = float(num_cycles) / icnt
                #NOTE: llvm-mca completely messes up movs[b/w/q] estimates
                #      so we get estimated cycles from sdetest3C.c  (~0.52)
                if num_instr == icnt \
                        and search(r'^rep\s+movs[bwq]\s+', bdata['ASM'][0][1]):
                    cycles_to_move_byte = 0.52 /4   # /4 from polybench durbin
                    if search(r'\s+movsb\s+', bdata['ASM'][0][1]):
                        cycles_per_iter = cycles_to_move_byte
                    elif search(r'\s+movsw\s+', bdata['ASM'][0][1]):
                        cycles_per_iter = 2 * cycles_to_move_byte
                    else:
                        cycles_per_iter = 4 * cycles_to_move_byte
            # div2 cycles for two-block loops to adjust for later counting algo
            elif twoblockloop:
                cycles_per_iter = float(num_cycles) / icnt / 2
            # but for others we have to compare retirement (R) time difference
            # between the last instruction of the two blocks
            else:
                #print('simulate_cycles_with_LLVM_MCA', mca_in_fn, timeline_data, num_instr, num_asm_bbid)
                cycles_per_iter = \
                    timeline_data[num_instr - 1][1].find('R') \
                    - timeline_data[num_asm_bbid - 1][1].find('R')
            assert(cycles_per_iter >= 0)

            #NOTE: llvm-mca assumption of 100 cycles for a 'call[q]' is far too
            #      much as measurements with sdetest4C.c show, more like ~30
            #      minus the 12 cycles overhead for assembly around the test
            #      => so, lets assume ~20 cycles if its a ton of calls (>1000)
            #      (https://www.agner.org/optimize/instruction_tables.pdf also
            #      lists on 74 cycles for old Nehalem => maybe set somewhere
            #      in between 70 and 20 as compromise...?)
            assumed_cycle_per_call = 20
            if cycles_per_iter > assumed_cycle_per_call \
                    and search(r'call[q]?\s+', sink_bdata['ASM'][-1][1]) \
                    and max(edge_data['ThreadExecCnts']) > 1000:
                cycles_per_iter -= (100 - assumed_cycle_per_call)

            if cycles_per_iter == 0:
                # leave a tiny weight, otherwise we get into trouble if we
                # filter by {ThreadExecCnts|CyclesPerIter}=0 in bb_graph fn
                edge_data['CyclesPerIter'] = pow(10, -10)
            else:
                edge_data['CyclesPerIter'] = cycles_per_iter

            # clean up the temp file under /dev/shm
            if not keep:
                if path.isfile(mca_in_fn):
                    remove(mca_in_fn)


def second_opinion_from_other_tools(blkdata=None, mapper=None, arch=None,
                                       keep=False):
    assert(isinstance(blkdata, dict) and isinstance(mapper, dict)
           and isinstance(arch, str) and isinstance(keep, bool))

    # we don't check them all, just the most computational heavy blocks
    branches = [[c_bbid, n_bbid,
                 max(blkdata[c_bbid]['out_edges'][n_bbid]['ThreadExecCnts'])
                 * blkdata[c_bbid]['out_edges'][n_bbid]['CyclesPerIter']]
                for c_bbid in blkdata
                for n_bbid in blkdata[c_bbid]['out_edges'].keys()]

    # sort descending by runtime
    branches.sort(key=lambda x: x[2], reverse=True)
    # get a sublist which has (in sum) 99% of the entire runtime
    total = reduce(lambda x,y: x+y, (b[2] for b in branches))
    i, subtotal = 0, 0
    for i in range(len(branches)):
        subtotal += branches[i][2]
        if subtotal > 0.99 * total:
            break
    # remove useless tail
    branches = branches[:i+1]

    for bbid, sink_bbid, _ in branches:
        edge_data = blkdata[bbid]['out_edges'][sink_bbid]
        edge_data['CyclesPerIter'] = 4 * [edge_data['CyclesPerIter']]

    simulate_cycles_with_IACA(True, arch, blkdata, branches)    # uiCA needs same files
    simulate_cycles_with_uiCA(keep, arch, blkdata, branches)
    simulate_cycles_with_OSACA(keep, arch, blkdata, branches)


def build_bb_graph(blockdata=None, mapper=None, thread_id=0):
    assert(isinstance(blockdata, dict) and isinstance(mapper, dict)
           and isinstance(thread_id, int) and thread_id > -1)

    # do depth-first traversal from START to build graph while avoiding cycles
    start_bbid = mapper['sbn2sbid']['START']
    # but sanity check if we are not out-of-bounds with the thread number
    first_out_edge =  next(iter(blockdata[start_bbid]['out_edges'].values()))
    if thread_id >= len(first_out_edge['ThreadExecCnts']):
        return None

    G = DiGraph()

    #for bbid, bdata in blockdata.items():
    #    for sink_bbid, sink_data in bdata['out_edges'].items():
    #        for thread in range(len(sink_data['ThreadExecCnts'])):
    #            w = sink_data['ThreadExecCnts'][thread] \
    #                * sink_data['CyclesPerIter']
    #            G.add_edge(bbid, sink_bbid, cpu_cycles=w)
    #    if bbid==1:
    #        print(bdata)

    branches = [[start_bbid, out_edge]
                for out_edge in blockdata[start_bbid]['out_edges'].keys()]
    #if thread_id>0:
    #    print('build_bb_graph', branches)
    #    exit()
    # build spanning tree
    while len(branches) > 0:
        curr_bbid, next_bbid = branches.pop()
        curr2next_bbid_edge = blockdata[curr_bbid]['out_edges'][next_bbid]

        iter_cnt, cycle_cnt = \
            curr2next_bbid_edge['ThreadExecCnts'][thread_id], \
            curr2next_bbid_edge['CyclesPerIter']
        if iter_cnt == 0: iter_cnt =1 #XXX TODO XXX QEMU IS MISSING ENTRY FOR THREADS (this is a diry workaround)
        # if edge (curr_bbid->next_bbid) isn't used or filtered for the thread?
        if iter_cnt == 0 \
                or (isinstance(cycle_cnt, list) and cycle_cnt[0] == 0) \
                or (not isinstance(cycle_cnt, list) and cycle_cnt == 0):
            continue
        else:
            if isinstance(cycle_cnt, list):
                edge_weight = [iter_cnt * cnt for cnt in cycle_cnt]
            else:
                edge_weight = 4 * [iter_cnt * cycle_cnt]

        # check if we would close a (self-)loop -> convert to leaf
        if curr_bbid == next_bbid or G.has_node(next_bbid):
            G.add_edge(curr_bbid, '%s->%s->|' % (curr_bbid, next_bbid),
                       llvm_cycles=edge_weight[0],
                       iaca_cycles=edge_weight[1],
                       uica_cycles=edge_weight[2],
                       osaca_cycles=edge_weight[3])
            continue

        # or simply add the edge and continue the DFS
        G.add_edge(curr_bbid, next_bbid,
                   llvm_cycles=edge_weight[0],
                   iaca_cycles=edge_weight[1],
                   uica_cycles=edge_weight[2],
                   osaca_cycles=edge_weight[3])

        branches += [[next_bbid, out_edge]
                     for out_edge in blockdata[next_bbid]['out_edges'].keys()]

    #if thread_id>0:
    #    print('build_bb_graph', G)
    #    exit()
    return G


def postprocess_bb_graph(bb_graph=None, blockdata=None, mapper=None):
    assert(isinstance(bb_graph, DiGraph) and isinstance(blockdata, dict) and
           isinstance(mapper, dict))

    start_bbid = mapper['sbn2sbid']['START']

    fid2fn_m, bbid2fid_m, sbid2sbn_m = \
        mapper['fid2fn'], mapper['bbid2fid'], mapper['sbid2sbn']
    filter_libs = ['/libmpi.so', '/libmpifort.so']
    fid_blacklist = [fid for fid, fn in mapper['fid2fn'].items()
                     if len([f for f in filter_libs if fn.find(f) > -1]) > 0]

    print('blacklist:', [[x, fid2fn_m[x]] for x in fid_blacklist])

    # add 'processed' label to all edges
    for edge in bb_graph.edges():
        bb_graph.edges[edge]['processed'] = False

    # iterate over all edges in the graph
    for curr_bbid, next_bbid in dfs_edges(bb_graph, source=start_bbid):
        print('g1:', curr_bbid, next_bbid)
        try:
            print(next_bbid in bbid2fid_m, bbid2fid_m[next_bbid] in fid_blacklist, bbid2fid_m[curr_bbid] not in fid_blacklist, bb_graph.edges[curr_bbid, next_bbid]['processed'])
        except:
            print(next_bbid in bbid2fid_m, curr_bbid in bbid2fid_m)
            pass
        if bb_graph.edges[curr_bbid, next_bbid]['processed']:
            continue
        else:
            bb_graph.edges[curr_bbid, next_bbid]['processed'] = True

        # start second manual DFS if jump from non-filtered file (e.g. the app)
        # into a filtered file (e.g. the MPI lib) and set cycles to 0 for
        # all successors until jump back to where we initially jumped in from
        if not (next_bbid in bbid2fid_m \
                and bbid2fid_m[next_bbid] in fid_blacklist \
                and bbid2fid_m[curr_bbid] not in fid_blacklist):
            continue

        print('g2:', curr_bbid, next_bbid)

        # set all incoming to 'processed' so that we don't do it multiple times
        for bbid in bb_graph.predecessors(next_bbid):
            bb_graph.edges[bbid, next_bbid]['processed'] = True

        # also get all fid which enter the filtered region
        fid_whitelist = [bbid2fid_m[bbid]
                         for bbid in bb_graph.predecessors(next_bbid)]
        assert(set(fid_blacklist).isdisjoint(set(fid_whitelist)))
        print('whitelist:', [[x, fid2fn_m[x]] for x in fid_whitelist])

        ignore_subtree = None
        # traverse down the DFS and set cycles to 0 until we jump back out
        for curr2_bbid, next2_bbid in dfs_edges(bb_graph, source=next_bbid):

            # ignore subtrees below the break point
            if ignore_subtree and (curr2_bbid, next2_bbid) in ignore_subtree:
                continue
            elif ignore_subtree:
                ignore_subtree = None

            if not (next2_bbid in bbid2fid_m \
                    and bbid2fid_m[next2_bbid] in fid_whitelist):
                bb_graph.edges[curr2_bbid, next2_bbid]['cpu_cycles'] = 0
                bb_graph.edges[curr2_bbid, next2_bbid]['processed'] = True
                print('g3:', curr2_bbid, next2_bbid)
            else:
                # if jump out we have to stop the DFS traversal below here
                ignore_subtree = dfs_edges(bb_graph, source=next2_bbid)


def get_cpu_arch():
    try:
        with open('/sys/devices/cpu/caps/pmu_name', 'r') as pmu:
            cpu_info = pmu.read()
        return search(r'(\w+)', cpu_info, flags=DOTALL).group(1)
    except:
        pass

    try:
        from archspec.cpu import host
        return host().to_dict()['name']
    except:
        exit('ERR: cannot determine arch')


def _id_in_range(interval, testid):
    if interval[0] > 0 and testid < interval[0]:
        return False
    if interval[1] > 0 and testid > interval[1]:
        return False
    return True


def fn_graph(data=None, mapper=None, block_id_range=None, fn_name=None):
    assert(isinstance(data, dict) and isinstance(mapper, dict)
           and isinstance(block_id_range, list) and isinstance(fn_name, str))

    import plotly.graph_objs as go

    G = DiGraph()

    # show all functions and their call-dependency
    for fid in mapper['func2fpbb']:
        for func, fpbbs in mapper['func2fpbb'][fid].items():
            for fpbb in fpbbs:
                added = []
                for block_id, block_data in data.items():
                    if block_data['Func'] != func:
                        continue
                    if mapper['rpbb2fpbb'][mapper['bbid2rpbb'][block_id]] \
                            != fpbb:
                        continue

                    for adj_func in set([data[blk]['Func']
                                         for blk in block_data['out_edges']]):
                        if [func, adj_func] in added:
                            continue
                        added.append([func, adj_func])
                        G.add_edge(func, adj_func)

    pos = kamada_kawai_layout(G)
    # pos = spectral_layout(G)
    for node in G.nodes:
        G.nodes[node]['pos'] = list(pos[node])

    plt_data, anno = [], []
    for edge in G.edges:
        x0, y0 = G.nodes[edge[0]]['pos']
        x1, y1 = G.nodes[edge[1]]['pos']
        trace = go.Scattergl(x=tuple([x0, x1, None]), y=tuple([y0, y1, None]),
                             mode='lines', line={'color': 'black'}, opacity=1)
        plt_data.append(trace)
        anno.append(
            dict(
                ax=x0,
                ay=y0,
                axref='x',
                ayref='y',
                x=(x1 - x0) / 2 + x0,
                y=(y1 - y0) / 2 + y0,
                xref='x',
                yref='y',
                showarrow=True,
                arrowhead=3,
                arrowsize=1.5,
                arrowwidth=1.5,
                opacity=1))

    trace = go.Scattergl(
        x=[],
        y=[],
        hovertext=[],
        text=[],
        mode='markers+text',
        textposition='bottom center',
        hoverinfo='text',
        marker={
            'size': 10,
            'color': 'LightSkyBlue'})
    for node in G.nodes():
        x, y = G.nodes[node]['pos']
        hovertext = 'NodeID: %s' % node
        trace['x'] += tuple([x])
        trace['y'] += tuple([y])
        trace['hovertext'] += tuple([hovertext])
        trace['text'] += tuple([hovertext])
    plt_data.append(trace)

    figure = {
        'data': plt_data,
        'layout': go.Layout(title='', showlegend=False, hovermode='closest',
                            margin={'b': 0, 'l': 0, 'r': 0, 't': 0},
                            xaxis={'showgrid': False, 'zeroline': False,
                                   'showticklabels': False},
                            yaxis={'showgrid': False, 'zeroline': False,
                                   'showticklabels': False},
                            height=800, clickmode='event+select',
                            annotations=anno,
                            )}

    return figure


def init_dash_for_vis(data=None, mapper=None):
    assert(isinstance(data, dict) and isinstance(mapper, dict))

    import dash
    import dash_core_components as dcc
    import dash_html_components as html

    block_id_range = ['', '']
    search_fn_name = ''

    # import a css template, and pass it into dash
    css = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
    app = dash.Dash(__name__, external_stylesheets=css)
    app.title = 'Basic Block Graph Visualizer'

    styles = {
        'data': {
            'border': 'thin lightgrey solid',
            'overflowX': 'scroll',
            'overflowY': 'scroll'}}

    app.layout = html.Div([
        # Title
        html.Div([html.H1('%s' % app.title)],
                 className='row',
                 style={'textAlign': 'center'}),
        # define the full page layout
        html.Div(
            className='row',
            children=[
                # left side : input components on top and info stuff at bottom
                html.Div(
                    className='two columns',
                    children=[
                        html.Div(
                            className='twelve columns',
                            children=[
                                dcc.Markdown('**RANGE: From Block ID**'),
                                dcc.Input(
                                    id='my-block-from', type='text',
                                    value=block_id_range[0], debounce=True,
                                    placeholder='Block ID'),
                                html.Br(),
                                html.Div(id='output-text-block-id-from')
                            ],
                            style={'height': '100px'}
                        ),
                        html.Div(
                            className='twelve columns',
                            children=[
                                dcc.Markdown('**RANGE: To Block ID**'),
                                dcc.Input(
                                    id='my-block-to', type='text',
                                    value=block_id_range[1], debounce=True,
                                    placeholder='Block ID'),
                                html.Br(),
                                html.Div(id='output-text-block-id-to')
                            ],
                            style={'height': '100px'}
                        ),
                        html.Div(
                            className='twelve columns',
                            children=[
                                dcc.Markdown('**Search for Function Name**'),
                                dcc.Input(
                                    id='my-fn-input', type='text',
                                    value=search_fn_name, debounce=True,
                                    placeholder='Function Name'),
                                html.Br(),
                                html.Div(id='output-text-func-name')
                            ],
                            style={'height': '100px'}
                        ),
                        html.Div(
                            className='twelve columns',
                            children=[
                                dcc.Markdown(
                                    '**Hover-over Data**\n\n' +
                                    'Mouse over values in the graph.'),
                                html.Pre(id='hover-data', style=styles['data'])
                            ],
                            style={'height': '500px'}
                        ),
                    ]
                ),
                # middle : basic block graph component
                html.Div(
                    className='eight columns',
                    children=[dcc.Graph(id='my-graph',
                                        figure=fn_graph(data, mapper,
                                                        block_id_range,
                                                        search_fn_name))],
                ),
                html.Div(
                    className='two columns',
                    children=[
                        html.Div(
                            className='twelve columns',
                            children=[
                                dcc.Markdown(
                                    '**Full Block Data**\n\n' +
                                    'Click on vertices in the graph.'),
                                html.Pre(id='click-data', style=styles['data'])
                            ],
                            style={'height': '800px'}
                        ),
                    ],
                ),
            ],
        ),
    ])
    ###########################################################################
    # callback subroutines to control the interactivity in dash: ##############
    #   callback for left side components

    @app.callback(
        dash.dependencies.Output('my-graph', 'figure'),
        [dash.dependencies.Input('my-block-from', 'value'),
         dash.dependencies.Input('my-block-to', 'value'),
         dash.dependencies.Input('my-fn-input', 'value')])
    def update_block_range(input1, input2, input3):
        nonlocal data, mapper, block_id_range, search_fn_name
        block_id_range = [int(input1), int(input2)]
        search_fn_name = input2
        return fn_graph(data, mapper, [int(input1), int(input2)], input3)

    @app.callback(
        dash.dependencies.Output('hover-data', 'children'),
        [dash.dependencies.Input('my-graph', 'hoverData')])
    def display_hover_data(hoverData):
        return jsondumps(hoverData, indent=2)       # TODO: need correct update

    @app.callback(
        dash.dependencies.Output('click-data', 'children'),
        [dash.dependencies.Input('my-graph', 'clickData')])
    def display_click_data(clickData):
        return jsondumps(clickData, indent=2)       # TODO: need correct update
    ###########################################################################

    return app


def main():
    ARCHS = deepcopy(KNOWN_ARCHS)
    ARCHS['broadwell'] = []
    ARCHS['cannonlake'] = []
    ARCHS['cascadelake'] = []
    ARCHS['core2'] = []
    ARCHS['haswell'] = []
    ARCHS['icelake'] = []
    ARCHS['ivybridge'] = []
    ARCHS['mic_knl'] = []
    ARCHS['nehalem'] = []
    ARCHS['sandybridge'] = []
    ARCHS['skylake'] = []
    ARCHS['skylake_avx512'] = []
    ARCHS['westmere'] = []
    ARCHS['x86_64'] = []
    ARCHS['aarch64'] = []
    ARCHS['thunderx2'] = []
    ARCHS['a64fx'] = [1800.0, 2000.0, 2200.0]
    ARCHS['power7'] = []
    ARCHS['power8'] = []
    ARCHS['power9'] = []

    from psutil import cpu_freq
    from argparse import ArgumentParser

    arg_parser = ArgumentParser()
    arg_parser.add_argument('-j', '--sde_json', dest='__sde_json_f__',
                            help='name of existing *.dcfg.json.bz2 file',
                            type=str, metavar='<input file>', default=None,
                            required=True)
    arg_parser.add_argument('-v', '--vis', dest='__visualize__',
                            help='run dash server and show basic block graph',
                            action='store_true', default=False)
    arg_parser.add_argument('-l', '--load_objd', dest='__load_objdump__',
                            help='load previously stored objdump data from' +
                            ' file instead of accessing all objects locally',
                            type=str, metavar='<input file>', default=None)
    arg_parser.add_argument('-s', '--store_objd', dest='__store_objdump__',
                            help='backup objdump data to file to postprocess' +
                            ' on a different computer or get speedup locally',
                            type=str, metavar='<output file>', default=None,)
    arg_parser.add_argument('-a', '--cpu_arch', dest='__cpu_arch__',
                            help='change CPU architecture which should be' +
                            ' simulated [default: native]',
                            type=str, metavar='<arch>', default=None,)
    arg_parser.add_argument('-k', '--keep', dest='__keep__',
                            help='keep intermediate input/output files',
                            action='store_true', default=False,)
    args = vars(arg_parser.parse_args())

    assert(args.get('__sde_json_f__') is not None
           and path.isfile(path.realpath(args.get('__sde_json_f__'))))
    if args.get('__load_objdump__') is not None:
        assert(path.isfile(path.realpath(args.get('__load_objdump__'))))

    arch = args.get('__cpu_arch__')
    if arch is None:
        arch = get_cpu_arch()
        cpufreq = cpu_freq()
        cpufmin, cpufcur, cpufmax = cpufreq.min, cpufreq.current, cpufreq.max
    else:
        assert(ARCHS[arch])
        cpufmin, cpufcur, cpufmax = ARCHS[arch][0], ARCHS[arch][1], ARCHS[arch][2]
    assert(arch in KNOWN_ARCHS)

    sde_data = {}
    parse_SDE_JSON(args, sde_data, arch)
    #print('main', sde_data)

    data, mapper = convert_sde_data_to_something_usable(sde_data)
    del sde_data

    simulate_cycles_with_LLVM_MCA(data, mapper, arch, args.get('__keep__'))
    #second_opinion_from_other_tools(data, mapper, arch, args.get('__keep__'))
    total_cycles_per_thread, thread_id = [], -1
    while True:
        thread_id += 1
        G = build_bb_graph(data, mapper, thread_id)
        if G == None:
            break

        ## apply some lib filtering or other stuff
        #postprocess_bb_graph(G, data, mapper)

        if 1:
            print('jens G:', G)
            bbids= set(data.keys())
            nodes= set(list(G))
            print('jens bbids:', bbids)
            print('jens nodes:', nodes)
            print('jens diff1:', nodes.difference(bbids))
            print('jens diff2:', bbids.difference(nodes))
            print("Edges of graph: ")
            #print(G.edges.data())
            for d in G.edges.data():
                print(d, '  ', end='')
                if isinstance(d[1], str): dstbb = int(findall(r'\d+', d[1])[1])
                else                    : dstbb = d[1]
                print('fn: ', data[dstbb]['Func'])

        total_cycles = G.size(weight='llvm_cycles')
        print('LLVM: Total CPU cycles on rank %s and thread ID %s : %s\n'
              % (0, thread_id, total_cycles) +
              'LLVM: (Converted to time (with min/curr/max freq.): %ss / %ss / %ss)'
              % (total_cycles / (cpufmin * pow(10, 6)),
                 total_cycles / (cpufcur * pow(10, 6)),
                 total_cycles / (cpufmax * pow(10, 6))))

        #total_cycles = G.size(weight='iaca_cycles')
        #print('IACA: Total CPU cycles on rank %s and thread ID %s : %s\n'
        #      % (0, thread_id, total_cycles) +
        #      'IACA: (Converted to time (with min/curr/max freq.): %ss / %ss / %ss)'
        #      % (total_cycles / (cpufmin * pow(10, 6)),
        #         total_cycles / (cpufcur * pow(10, 6)),
        #         total_cycles / (cpufmax * pow(10, 6))))

        #total_cycles = G.size(weight='uica_cycles')
        #print('uiCA: Total CPU cycles on rank %s and thread ID %s : %s\n'
        #      % (0, thread_id, total_cycles) +
        #      'uiCA: (Converted to time (with min/curr/max freq.): %ss / %ss / %ss)'
        #      % (total_cycles / (cpufmin * pow(10, 6)),
        #         total_cycles / (cpufcur * pow(10, 6)),
        #         total_cycles / (cpufmax * pow(10, 6))))

        #total_cycles = G.size(weight='osaca_cycles')
        #print('OSACA: Total CPU cycles on rank %s and thread ID %s : %s\n'
        #      % (0, thread_id, total_cycles) +
        #      'OSACA: (Converted to time (with min/curr/max freq.): %ss / %ss / %ss)'
        #      % (total_cycles / (cpufmin * pow(10, 6)),
        #         total_cycles / (cpufcur * pow(10, 6)),
        #         total_cycles / (cpufmax * pow(10, 6))))

        G.clear()
        del G

    #for x in nx.simple_cycles(G):
    #    if 3 not in x:
    #        print(x)

#    total_cycles = nx.dag_longest_path_length(G, weight='cycles')
#    print('Extrapolated runtime: %s', total_cycles)

    if args.get('__visualize__'):
        dash_app = init_dash_for_vis(data, mapper)
        dash_app.run_server(debug=False)


if __name__ == '__main__':
    main()
