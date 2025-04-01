// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package art // import "go.opentelemetry.io/ebpf-profiler/interpreter/art"

import (
	"fmt"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// #include "../../support/ebpf/types.h"
import "C"

type artData struct {
	jitDescAddr  libpf.Address
	dexDescAddr  libpf.Address
	libartFileID host.FileID

	// Once protected artVMData
	xsync.Once[artVMData]
}

type JitDescriptor struct {
	first_entry_addr uint64
	action_seqlock   uint32 // incremented before and after any modification
	action_timestamp uint64 // CLOCK_MONOTONIC time of last action
	android_version  uint32
}

func (jd *JitDescriptor) DebugString() string {
	return fmt.Sprintf("first_entry_addr=0x%x, action_seqlock=%d, action_timestamp=%d, android_version=%d}",
		jd.first_entry_addr, jd.action_seqlock, jd.action_timestamp, jd.android_version)
}

/*
	Jit Descriptor Layout

template <typename ADDRT>

	struct JITDescriptor {
	  uint32_t version;
	  uint32_t action_flag;
	  ADDRT relevant_entry_addr;
	  ADDRT first_entry_addr;
	  uint8_t magic[8];
	  uint32_t flags;
	  uint32_t sizeof_descriptor;
	  uint32_t sizeof_entry;
	  uint32_t action_seqlock;    // incremented before and after any modification
	  uint64_t action_timestamp;  // CLOCK_MONOTONIC time of last action
	};
*/
func (d *artData) readDebugDescriptor(offset libpf.Address, rm remotememory.RemoteMemory) (*JitDescriptor, error) {
	magic_bytes := make([]byte, 8)
	rm.Read(offset+24, magic_bytes)
	magic := string(magic_bytes)
	if magic != "Android1" && magic != "Android2" {
		return nil, fmt.Errorf("jit debug desc magic mismatch: %s", magic)
	}
	return &JitDescriptor{
		first_entry_addr: rm.Uint64(offset + 16),
		action_seqlock:   rm.Uint32(offset + 44),
		action_timestamp: rm.Uint64(offset + 48),
		android_version:  uint32(magic[7] - '0'),
	}, nil
}

func (d *artData) ReadJitDebugDescriptor(bias libpf.Address, rm remotememory.RemoteMemory) (*JitDescriptor, error) {
	return d.readDebugDescriptor(d.jitDescAddr+bias, rm)
}

func (d *artData) ReadDexDebugDescriptor(bias libpf.Address, rm remotememory.RemoteMemory) (*JitDescriptor, error) {
	return d.readDebugDescriptor(d.dexDescAddr+bias, rm)
}

func (d *artData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory) (ii interpreter.Instance, err error) {
	log.Debugf("Attach ART interpreter for %d", pid)
	cdata := C.ArtProcInfo{
		interpreter: C.u64(d.libartFileID),
	}
	if err := ebpf.UpdateProcData(libpf.ART, pid, unsafe.Pointer(&cdata)); err != nil {
		return nil, err
	}

	return &artInstance{
		d:               d,
		rm:              rm,
		bias:            bias,
		sdp:             elfunwindinfo.NewStackDeltaProvider(),
		vmRegions:       make(regionMap),
		prefixes:        make(map[regionKey][]lpm.Prefix),
		last_jit_desc:   &JitDescriptor{},
		last_dex_desc:   &JitDescriptor{},
		newJitDebugInfo: make(map[host.FileID]*JitDebugInfo),
		oldJitDebugInfo: make(map[host.FileID]*JitDebugInfo),
	}, nil
}

func (d *artData) Unload(_ interpreter.EbpfHandler) {
}

type artVMData struct {
	err error
}

func (d *artData) newVMData(rm remotememory.RemoteMemory, bias libpf.Address) (artVMData, error) {
	avd := artVMData{}
	avd.err = nil

	return avd, nil
}
