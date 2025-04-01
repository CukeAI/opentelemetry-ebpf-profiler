// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package art // import "go.opentelemetry.io/ebpf-profiler/interpreter/art"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const MAX_JIT_SYMFILE_SIZE uint64 = 1024 * 1024 * 1024

type artInstance struct {
	interpreter.InstanceStubs

	d    *artData
	rm   remotememory.RemoteMemory
	bias libpf.Address

	sdp nativeunwind.StackDeltaProvider

	// Currently mapped prefixes for entire memory regions
	prefixes  map[regionKey][]lpm.Prefix
	vmRegions regionMap
	cycle     int

	last_jit_desc *JitDescriptor
	last_dex_desc *JitDescriptor

	dexDebugInfo []DexDebugInfo
	mappings     []process.Mapping

	newJitDebugInfo map[host.FileID]*JitDebugInfo
	oldJitDebugInfo map[host.FileID]*JitDebugInfo

	oldJitRegions []JitRegion
}

type artCodeEntry struct {
	addr         uint64
	symfile_addr uint64
	symfile_size uint64
	timestamp    uint64
}

type regionMap map[process.Mapping]int

type regionKey struct {
	start, end uint64
}

func (e *artCodeEntry) DebugString() string {
	return fmt.Sprintf("addr=%x symfile_addr=%x size=%d timestamp=%d", e.addr, e.symfile_addr, e.symfile_size, e.timestamp)
}

func (e *artCodeEntry) ToFileID() (host.FileID, error) {
	buf := make([]byte, 8)
	h := fnv.New64a()
	binary.BigEndian.PutUint64(buf, e.addr)
	_, _ = h.Write(buf)
	binary.BigEndian.PutUint64(buf, e.symfile_addr)
	_, _ = h.Write(buf)
	binary.BigEndian.PutUint64(buf, e.symfile_size)
	_, _ = h.Write(buf)
	binary.BigEndian.PutUint64(buf, e.timestamp)
	_, _ = h.Write(buf)
	return host.FileIDFromBytes(h.Sum(nil))
}

/*
template <typename ADDRT>

	struct JITCodeEntry {
	  ADDRT next_addr;
	  ADDRT prev_addr;
	  ADDRT symfile_addr;
	  uint64_t symfile_size;
	  uint64_t register_timestamp;  // CLOCK_MONOTONIC time of entry registration

	  bool Valid() const { return symfile_addr > 0u && symfile_size > 0u; }
	};

template <typename ADDRT>

	struct JITCodeEntryV2 {
	  ADDRT next_addr;
	  ADDRT prev_addr;
	  ADDRT symfile_addr;
	  uint64_t symfile_size;
	  uint64_t register_timestamp;  // CLOCK_MONOTONIC time of entry registration
	  uint32_t seqlock;             // even value if valid
	};
*/

func (ai *artInstance) readNewCodeEntries(desc *JitDescriptor, last_action_timestamp uint64, read_entry_limit uint32) ([]artCodeEntry, error) {
	var entries []artCodeEntry
	cur_entry_addr := desc.first_entry_addr
	prev_entry_addr := uint64(0)
	entry_addr_set := make(map[uint64]bool)
	for i := 0; i < int(read_entry_limit) && cur_entry_addr != 0; i++ {
		if entry_addr_set[cur_entry_addr] {
			return nil, fmt.Errorf("duplicate entry found")
		}
		next_addr := ai.rm.Uint64(libpf.Address(cur_entry_addr))
		prev_addr := ai.rm.Uint64(libpf.Address(cur_entry_addr + 8))
		symfile_addr := ai.rm.Uint64(libpf.Address(cur_entry_addr + 16))
		symfile_size := ai.rm.Uint64(libpf.Address(cur_entry_addr + 24))
		register_timestamp := ai.rm.Uint64(libpf.Address(cur_entry_addr + 32))
		seqlock := uint32(0)
		if desc.android_version == 2 {
			seqlock = ai.rm.Uint32(libpf.Address(cur_entry_addr + 40))
		}

		log.Tracef("cur_entry_addr: 0x%x, next_addr: 0x%x, prev_addr: 0x%x, symfile_addr: 0x%x, symfile_size: %d, seqlock: %d",
			cur_entry_addr, next_addr, prev_addr, symfile_addr, symfile_size, seqlock)

		if prev_entry_addr != prev_addr {
			return nil, fmt.Errorf("prev_entry_addr != prev_addr")
		}

		if (desc.android_version == 1 && (symfile_addr == 0 || symfile_size == 0)) ||
			(desc.android_version == 2 && (seqlock&1) != 0) {
			return nil, fmt.Errorf("invalid entry")
		}

		if register_timestamp <= last_action_timestamp {
			break
		}

		var entry artCodeEntry
		if symfile_size > 0 {
			entry.addr = cur_entry_addr
			entry.symfile_addr = symfile_addr
			entry.symfile_size = symfile_size
			entry.timestamp = register_timestamp
			entries = append(entries, entry)
		}
		entry_addr_set[cur_entry_addr] = true
		prev_entry_addr = cur_entry_addr
		cur_entry_addr = next_addr
	}
	return entries, nil
}

type JitDebugInfo struct {
	FileID  host.FileID
	Entry   artCodeEntry
	ElfRef  *pfelf.Reference
	symbols []libpf.Symbol
}

type JitRegion struct {
	start  uint64
	end    uint64
	FileID host.FileID
}

func (d *JitDebugInfo) FindSymbol(addr uint64) *libpf.Symbol {
	for _, sym := range d.symbols {
		if addr >= uint64(sym.Address) && addr < (uint64(sym.Address)+sym.Size) {
			return &sym
		}
	}
	return nil
}

func (d *JitDebugInfo) SortSymbols() {
	sort.Slice(d.symbols, func(i, j int) bool {
		return d.symbols[i].Address < d.symbols[j].Address
	})
}

func (d *JitDebugInfo) PrintAllSymbols() {
	log.Debugf("FileID: %x, Symbols: %d", d.FileID, len(d.symbols))
	for _, sym := range d.symbols {
		log.Debugf("addr: 0x%x, size: %d, name: %s", sym.Address, sym.Size, sym.Name)
	}
}

type JitDebugSymbols struct {
	sym   libpf.Symbol
	dinfo *JitDebugInfo
}

func (ai *artInstance) readJitDebugInfo(new_desc *JitDescriptor) ([]JitRegion, error) {
	//read_entry_limit := (new_desc.action_seqlock - old_desc.action_seqlock) / 2
	//entries, err := ai.readNewCodeEntries(new_desc, old_desc.action_timestamp, read_entry_limit)
	read_entry_limit := new_desc.action_seqlock / 2
	entries, err := ai.readNewCodeEntries(new_desc, 0, read_entry_limit)
	if err != nil {
		return nil, err
	}

	var sym_list []JitDebugSymbols

	for _, entry := range entries {
		log.Debugf("entry: %v", entry.DebugString())
		if entry.symfile_size > MAX_JIT_SYMFILE_SIZE {
			return nil, fmt.Errorf("symfile size too large")
		}
		data := make([]byte, entry.symfile_size)
		ai.rm.Read(libpf.Address(entry.symfile_addr), data)
		ef, err := pfelf.NewFile(bytes.NewReader(data), 0, false)
		if err != nil {
			return nil, err
		}

		fileID, err := entry.ToFileID()
		if err != nil {
			return nil, err
		}

		os.WriteFile(fmt.Sprintf("/data/local/tmp/jit/%x", fileID), data, 0644)

		syms, err := ef.ReadSymbols()
		if err != nil {
			// try gnu debug data
			ef = ef.ExtractAndOpenMiniDebugInfo()
			syms, err = ef.ReadSymbols()
			if err != nil {
				log.Debugf("failed to load symbols for %x: %v", fileID, err)
				continue
			}
		} else {
			if ef.Section(".gnu_debugdata") != nil {
				log.Debugf("debug symbol and gnu_debugdata both present for %x", fileID)
			}
		}

		dinfo := JitDebugInfo{
			FileID: fileID,
			Entry:  entry,
			ElfRef: pfelf.NewOpenedReference("", ef),
		}
		ai.newJitDebugInfo[fileID] = &dinfo

		syms.VisitAll(func(s libpf.Symbol) {
			if s.Address == 0 {
				return
			}
			log.Debugf("symbol: %s, 0x%x, 0x%x", s.Name, s.Address, s.Size)
			dinfo.symbols = append(dinfo.symbols, s)
			sym_list = append(sym_list, JitDebugSymbols{sym: s, dinfo: &dinfo})
		})

		dinfo.SortSymbols()
	}

	var regions []JitRegion
	sort.Slice(sym_list, func(i, j int) bool {
		return sym_list[i].sym.Address < sym_list[j].sym.Address
	})
	fileID := host.FileID(0)
	region_start := uint64(0)
	region_end := uint64(0)
	region_syms := 0
	for _, sym := range sym_list {
		if fileID != sym.dinfo.FileID {
			if region_start != 0 {
				log.Debugf("new region: 0x%x, 0x%x, %d, fileID: %x", region_start, region_end, region_syms, fileID)
				regions = append(regions, JitRegion{
					start:  region_start,
					end:    region_end,
					FileID: fileID,
				})
			}
			fileID = sym.dinfo.FileID
			region_syms = 1
			region_start = uint64(sym.sym.Address)
			region_end = uint64(sym.sym.Address) + uint64(sym.sym.Size)
		} else {
			region_end = uint64(sym.sym.Address) + uint64(sym.sym.Size)
			region_syms++
		}
	}
	if region_start != 0 {
		log.Debugf("new region: 0x%x, 0x%x, %d, fileID: %x", region_start, region_end, region_syms, fileID)
		regions = append(regions, JitRegion{
			start:  region_start,
			end:    region_end,
			FileID: fileID,
		})
	}
	return regions, nil
}

func inRegion(addr, length, start, end uint64) bool {
	return addr >= start && addr+length <= end
}

type DexDebugInfo struct {
	dex_file_path string
	dex_offset    uint64
	mapping       process.Mapping
}

func (ai *artInstance) readDexDebugInfo(new_desc *JitDescriptor, mappings []process.Mapping) ([]DexDebugInfo, error) {
	//read_entry_limit := (new_desc.action_seqlock - old_desc.action_seqlock) / 2
	//entries, err := ai.readNewCodeEntries(new_desc, old_desc.action_timestamp, read_entry_limit)
	read_entry_limit := new_desc.action_seqlock / 2
	entries, err := ai.readNewCodeEntries(new_desc, 0, read_entry_limit)
	if err != nil {
		return nil, err
	}

	var dinfo []DexDebugInfo

	for _, entry := range entries {
		var found_mapping *process.Mapping
		found_mapping = nil
		i := sort.Search(len(mappings), func(i int) bool {
			return mappings[i].Vaddr >= entry.symfile_addr
		})
		if i < len(mappings) && mappings[i].Vaddr == entry.symfile_addr {
			found_mapping = &mappings[i]
		} else {
			i--
			if i >= 0 {
				m := mappings[i]
				if inRegion(entry.symfile_addr, entry.symfile_size, m.Vaddr, m.Vaddr+m.Length) {
					found_mapping = &m
				} else {
					log.Warnf("invalid entry:%0x, entry_end:%0x mapping:0x%x, mapping_end:%x, %s", entry.symfile_addr, entry.symfile_addr+entry.symfile_size, m.Vaddr, m.Vaddr+m.Length, m.Path)
				}
			}
		}

		if found_mapping != nil {
			//log.Debugf("found entry:%0x, mapping:0x%x, %s", entry.symfile_addr, found_mapping.Vaddr, found_mapping.Path)
			dinfo = append(dinfo, DexDebugInfo{
				dex_file_path: found_mapping.Path,
				dex_offset:    entry.symfile_addr - found_mapping.Vaddr,
				mapping:       *found_mapping,
			})
		} else {
			log.Warnf("fail to find dex file for entry:%0x", entry.symfile_addr)
		}
	}
	return dinfo, nil
}

func (ai *artInstance) addJitRegion(ebpf interpreter.EbpfHandler, pid libpf.PID,
	start, end uint64, fileID host.FileID) error {
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		return fmt.Errorf("art: failed to calculate lpm: %v", err)
	}
	log.Debugf("art: add JIT region pid(%v) %#x:%#x", pid, start, end)
	for _, prefix := range prefixes {
		if err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindART, fileID, 0); err != nil {
			return err
		}
	}
	k := regionKey{start: start, end: end}
	ai.prefixes[k] = prefixes
	return nil
}

func (ai *artInstance) removeJitRegion(ebpf interpreter.EbpfHandler, pid libpf.PID,
	start, end uint64) error {
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		return fmt.Errorf("art: failed to calculate lpm: %v", err)
	}
	log.Debugf("art: remove JIT region pid(%v) %#x:%#x", pid, start, end)
	for _, prefix := range prefixes {
		if err := ebpf.DeletePidInterpreterMapping(pid, prefix); err != nil {
			return err
		}
	}
	return nil
}

func (ai *artInstance) getJitDebugELFs() (added, removed []*JitDebugInfo, err error) {
	err = nil

	if len(ai.newJitDebugInfo) == 0 {
		err = fmt.Errorf("no new JitDebugInfo found")
		return
	}

	for _, dinfo := range ai.newJitDebugInfo {
		if _, exists := ai.oldJitDebugInfo[dinfo.FileID]; !exists {
			added = append(added, dinfo)
		}
	}

	for _, dinfo := range ai.oldJitDebugInfo {
		if _, exists := ai.newJitDebugInfo[dinfo.FileID]; !exists {
			removed = append(removed, dinfo)
		}
	}
	return
}

func (ai *artInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	pid := pr.PID()
	log.Debugf("Synchronizing mappings for ART interpreter, pid: %v", pid)
	vmd, err := ai.d.GetOrInit(func() (artVMData, error) { return ai.d.newVMData(ai.rm, ai.bias) })
	if err != nil {
		return err
	}
	// Check for permanent errors
	if vmd.err != nil {
		return vmd.err
	}

	cycle := ai.cycle
	ai.cycle++
	for i := range mappings {
		m := &mappings[i]
		if !m.IsExecutable() {
			continue
		}
		if strings.HasPrefix(m.Path, "/memfd:jit-") {
			ai.vmRegions[*m] = cycle
		}
	}

	// Add new ones and remove garbage ones
	for m, c := range ai.vmRegions {
		k := regionKey{start: m.Vaddr, end: m.Vaddr + m.Length}
		if c != cycle {
			for _, prefix := range ai.prefixes[k] {
				if err := ebpf.DeletePidInterpreterMapping(pid, prefix); err != nil {
					return err
				}
			}
			delete(ai.vmRegions, m)
			delete(ai.prefixes, k)
		} else {
			if _, ok := ai.prefixes[k]; !ok {
				if err := ai.addJitRegion(ebpf, pid, m.Vaddr, m.Vaddr+m.Length, 0); err != nil {
					return err
				}
			}
		}
	}

	jit_desc, err := ai.d.ReadJitDebugDescriptor(ai.bias, ai.rm)
	if err != nil {
		return err
	}
	dex_desc, err := ai.d.ReadDexDebugDescriptor(ai.bias, ai.rm)
	if err != nil {
		return err
	}

	if ai.last_jit_desc.action_seqlock == jit_desc.action_seqlock &&
		ai.last_dex_desc.action_seqlock == dex_desc.action_seqlock {
		return nil
	}

	log.Debugf("Update jit debug info by desc for pid: %v", pr.PID())
	jitRegions, err := ai.readJitDebugInfo(jit_desc)
	if err != nil {
		return err
	}
	for _, region := range ai.oldJitRegions {
		err := ai.removeJitRegion(ebpf, pid, region.start, region.end)
		if err != nil {
			return err
		}
	}
	for _, region := range jitRegions {
		err := ai.addJitRegion(ebpf, pid, region.start, region.end, region.FileID)
		if err != nil {
			return err
		}
	}
	ai.oldJitRegions = jitRegions

	log.Debugf("Update dex debug info by desc for pid: %v", pr.PID())
	dex_dinfo, err := ai.readDexDebugInfo(dex_desc, mappings)
	if err != nil {
		return err
	}

	ai.dexDebugInfo = dex_dinfo
	ai.mappings = mappings

	ai.last_jit_desc = jit_desc
	ai.last_dex_desc = dex_desc

	log.Debugf("jit_desc_version: %v", jit_desc.DebugString())
	log.Debugf("dex_desc_version: %v", dex_desc.DebugString())

	return nil
}

type DexSymbol struct {
	FilePath string
	Offset   uint64
	Name     string
}

func (ai *artInstance) findJitSymbol(pc uint64, fileID host.FileID) (DexSymbol, error) {
	dinfo, exists := ai.oldJitDebugInfo[fileID]
	if !exists {
		log.Debugf("old: %d, new: %d", len(ai.oldJitDebugInfo), len(ai.newJitDebugInfo))
		return DexSymbol{FilePath: "jit", Offset: pc}, fmt.Errorf("not found jit debug info for pc: %#x, fileID: %x", pc, fileID)
	}
	sym := dinfo.FindSymbol(pc)
	if sym == nil {
		dinfo.PrintAllSymbols()
		return DexSymbol{FilePath: "jit", Offset: pc}, fmt.Errorf("not found jit symbol for pc: %#x, fileID: %x", pc, fileID)
	}
	return DexSymbol{FilePath: "jit", Offset: pc, Name: string(sym.Name)}, nil
}

func (ai *artInstance) findDexSymbol(dex_pc uint64) (DexSymbol, error) {
	for _, mapping := range ai.mappings {
		if uint64(dex_pc) >= mapping.Vaddr && uint64(dex_pc) < mapping.Vaddr+mapping.Length {
			log.Tracef("found dex symbol for dex_pc: %#x, dex_file:%v", dex_pc, mapping.Path)
			return DexSymbol{
				FilePath: mapping.Path,
				Offset:   dex_pc - mapping.Vaddr,
			}, nil
		}
	}
	return DexSymbol{}, fmt.Errorf("not found dex symbol for dex_pc: %#x", dex_pc)
}

func (ai *artInstance) Symbolize(symbolReporter reporter.SymbolReporter,
	frame *host.Frame, trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.ART) {
		return interpreter.ErrMismatchInterpreterType
	}

	file := frame.File
	pc := uint64(frame.Lineno)
	log.Debugf("Symbolize ART interpreter, pc(dex_pc): %#x, file: %#x", pc, file)

	var symbol DexSymbol
	var err error
	var fileID libpf.FileID

	if file == host.FileID(0) {
		// This may happen because JIT debug info may not be updated so fast when ebpf unwinder
		// already gets the frame. Just ignore it in this case. Otherwise it will be a problem.
		log.Debugf("JIT unwind info not found for pc: %#x", pc)
		symbol = DexSymbol{FilePath: "jit", Offset: pc}
		fileID = libpf.NewFileID(0xdeadbeef, pc)
	} else if file != ai.d.libartFileID {
		// JIT
		symbol, err = ai.findJitSymbol(pc, file)
		if err != nil {
			log.Debugf("Failed to find symbol: %v", err)
		}
		fileID = libpf.NewFileID(uint64(frame.File), pc)
	} else {
		// interpreter
		symbol, err = ai.findDexSymbol(pc)
		if err != nil {
			log.Debugf("Failed to find symbol: %v", err)
		}
		h := fnv.New128a()
		_, _ = h.Write([]byte(symbol.FilePath))
		fileID, err = libpf.FileIDFromBytes(h.Sum(nil))
		if err != nil {
			return fmt.Errorf("failed to create file id")
		}
	}

	var frameID libpf.FrameID
	log.Debugf("Append ART frame, file: %s", symbol.FilePath)
	frameID = libpf.NewFrameID(fileID, libpf.AddressOrLineno(pc))
	trace.AppendFrameID(libpf.ARTFrame, frameID)
	if !symbolReporter.FrameKnown(frameID) {
		log.Debugf("Add ART frame metadata, FrameID: %v, FileID: %v", frameID, fileID)
		if symbol.Name == "" {
			symbol.Name = fmt.Sprintf("0x%x", symbol.Offset)
		}
		symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
			FrameID:        frameID,
			FunctionName:   symbol.Name,
			SourceFile:     symbol.FilePath,
			SourceLine:     0,
			FunctionOffset: 0,
		})
	}

	return nil
}

func (ai *artInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	log.Debugf("GetAndResetMetrics for ART interpreter")
	return nil, nil
}

func (ai *artInstance) GetAndResetJitDebugELFs() ([]interpreter.ElfBundle, []interpreter.ElfBundle, error) {
	log.Debugf("GetAndResetJitDebugElfs for ART interpreter")
	var added, removed []interpreter.ElfBundle
	if len(ai.newJitDebugInfo) == 0 {
		return []interpreter.ElfBundle{}, []interpreter.ElfBundle{}, nil
	}

	for _, dinfo := range ai.newJitDebugInfo {
		if _, exists := ai.oldJitDebugInfo[dinfo.FileID]; !exists {
			added = append(added, interpreter.ElfBundle{
				FileID: dinfo.FileID,
				ElfRef: dinfo.ElfRef,
			})
		}
	}

	for _, dinfo := range ai.oldJitDebugInfo {
		if _, exists := ai.newJitDebugInfo[dinfo.FileID]; !exists {
			removed = append(removed, interpreter.ElfBundle{
				FileID: dinfo.FileID,
				ElfRef: dinfo.ElfRef,
			})
		}
	}

	ai.oldJitDebugInfo = ai.newJitDebugInfo
	ai.newJitDebugInfo = make(map[host.FileID]*JitDebugInfo)
	return added, removed, nil
}

func (ai *artInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	log.Debugf("Detach ART interpreter")
	return nil
}
