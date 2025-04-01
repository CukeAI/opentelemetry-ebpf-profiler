// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package art // import "go.opentelemetry.io/ebpf-profiler/interpreter/art"

import (
	"fmt"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var (
	_ interpreter.Data     = &artData{}
	_ interpreter.Instance = &artInstance{}
)

func findSymbol(ef *pfelf.File, s string) (libpf.Address, error) {
	addr, err := ef.LookupSymbolAddress(libpf.SymbolName(s))
	if err != nil {
		return libpf.Address(0), fmt.Errorf("symbol '%v' not found: %w", s, err)
	}
	log.Debugf("ART found symbol '%v' at 0x%x", s, addr)
	return libpf.Address(addr), nil
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	base := path.Base(info.FileName())
	if !strings.HasPrefix(base, "libart.so") && !strings.HasPrefix(base, "libartd.so") {
		return nil, nil
	}

	log.Infof("ART inspecting %v", info.FileName())
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	d := &artData{}

	syms, _ := ef.ReadSymbols()

	/*entry_start, err := findSymbol(ef, "ExecuteNterpImpl")*/
	entry_start, err := syms.LookupSymbolAddress("ExecuteNterpImpl")
	if err != nil {
		log.Errorf("%v", err)
		return nil, err
	}

	/*entry_end, err := findSymbol(ef, "EndExecuteNterpImpl")*/
	entry_end, err := syms.LookupSymbolAddress("EndExecuteNterpImpl")
	if err != nil {
		log.Errorf("%v", err)
		return nil, err
	}

	log.Debugf("ART ExecuteNterpImpl: 0x%x, EndExecuteNterpImpl: 0x%x\n", entry_start, entry_end)
	sym_range := []util.Range{}
	sym_range = append(sym_range, util.Range{
		Start: uint64(entry_start),
		End:   uint64(entry_end),
	})
	if err := ebpf.UpdateInterpreterOffsets(support.ProgUnwindArt, info.FileID(), sym_range); err != nil {
		return nil, err
	}

	jit_desc_addr, err := findSymbol(ef, "__jit_debug_descriptor")
	if err != nil {
		log.Errorf("%v", err)
		return nil, err
	}
	dex_desc_addr, err := findSymbol(ef, "__dex_debug_descriptor")
	if err != nil {
		log.Errorf("%v", err)
		return nil, err
	}

	d.jitDescAddr = jit_desc_addr
	d.dexDescAddr = dex_desc_addr
	d.libartFileID = info.FileID()

	return d, nil
}
