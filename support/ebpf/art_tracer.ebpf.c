// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// This file contains the code and map definitions for the Luajit tracer

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "stackdeltatypes.h"
#include "extmaps.h"

#ifdef OPTI_DEBUG
#define ART_FRAMES_PER_PROGRAM 4
#else
#define ART_FRAMES_PER_PROGRAM 10
#endif

#if !defined(__aarch64__)
#error "unsupported architecture"
#endif

bpf_map_def SEC("maps") art_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(ArtProcInfo),
  .max_entries = 4096,
};

// In Android ART unwinder is also based on dwarf based unwinder. So we copy
// stack delta and cfa based unwinder codes from native_stack_trace.ebpf.c

#define STACK_DELTA_BUCKET(X)                                                            \
  extern bpf_map_def SEC("maps") exe_id_to_##X##_stack_deltas;

// Create buckets to hold the stack delta information for the executables.
STACK_DELTA_BUCKET(8);
STACK_DELTA_BUCKET(9);
STACK_DELTA_BUCKET(10);
STACK_DELTA_BUCKET(11);
STACK_DELTA_BUCKET(12);
STACK_DELTA_BUCKET(13);
STACK_DELTA_BUCKET(14);
STACK_DELTA_BUCKET(15);
STACK_DELTA_BUCKET(16);
STACK_DELTA_BUCKET(17);
STACK_DELTA_BUCKET(18);
STACK_DELTA_BUCKET(19);
STACK_DELTA_BUCKET(20);
STACK_DELTA_BUCKET(21);
STACK_DELTA_BUCKET(22);
STACK_DELTA_BUCKET(23);

// Unwind info value for invalid stack delta
#define STACK_DELTA_INVALID (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_INVALID)
#define STACK_DELTA_STOP    (STACK_DELTA_COMMAND_FLAG | UNWIND_COMMAND_STOP)

extern bpf_map_def SEC("maps") unwind_info_array;
extern bpf_map_def SEC("maps") stack_delta_page_to_info;

// A single step for the bsearch into the big_stack_deltas array. This is really a textbook bsearch
// step, built in a way to update the value of *lo and *hi. This function will be called repeatedly
// (since we cannot do loops). The return value signals whether the bsearch came to an end / found
// the right element or whether it needs to continue.
static inline __attribute__((__always_inline__)) bool
bsearch_step(void *inner_map, u32 *lo, u32 *hi, u16 page_offset)
{
  u32 pivot         = (*lo + *hi) >> 1;
  StackDelta *delta = bpf_map_lookup_elem(inner_map, &pivot);
  if (!delta) {
    *hi = 0;
    return false;
  }
  if (page_offset >= delta->addrLow) {
    *lo = pivot + 1;
  } else {
    *hi = pivot;
  }
  return *lo < *hi;
}

// Get the outer map based on the number of stack delta entries.
static inline __attribute__((__always_inline__)) void *get_stack_delta_map(int mapID)
{
  switch (mapID) {
  case 8: return &exe_id_to_8_stack_deltas;
  case 9: return &exe_id_to_9_stack_deltas;
  case 10: return &exe_id_to_10_stack_deltas;
  case 11: return &exe_id_to_11_stack_deltas;
  case 12: return &exe_id_to_12_stack_deltas;
  case 13: return &exe_id_to_13_stack_deltas;
  case 14: return &exe_id_to_14_stack_deltas;
  case 15: return &exe_id_to_15_stack_deltas;
  case 16: return &exe_id_to_16_stack_deltas;
  case 17: return &exe_id_to_17_stack_deltas;
  case 18: return &exe_id_to_18_stack_deltas;
  case 19: return &exe_id_to_19_stack_deltas;
  case 20: return &exe_id_to_20_stack_deltas;
  case 21: return &exe_id_to_21_stack_deltas;
  case 22: return &exe_id_to_22_stack_deltas;
  case 23: return &exe_id_to_23_stack_deltas;
  default: return NULL;
  }
}

// Get the stack offset of the given instruction.
static ErrorCode get_stack_delta(UnwindState *state, int *addrDiff, u32 *unwindInfo)
{
  u64 exe_id = state->text_section_id;

  // Look up the stack delta page information for this address.
  StackDeltaPageKey key = {};
  key.fileID            = state->text_section_id;
  key.page              = state->text_section_offset & ~STACK_DELTA_PAGE_MASK;
  DEBUG_PRINT(
    "art: look up stack delta for %lx:%lx",
    (unsigned long)state->text_section_id,
    (unsigned long)state->text_section_offset);
  StackDeltaPageInfo *info = bpf_map_lookup_elem(&stack_delta_page_to_info, &key);
  if (!info) {
    DEBUG_PRINT(
      "art: failure to look up stack delta page fileID %lx, page %lx",
      (unsigned long)key.fileID,
      (unsigned long)key.page);
    state->error_metric = metricID_UnwindArtErrLookupTextSection;
    return ERR_NATIVE_LOOKUP_TEXT_SECTION;
  }

  void *outer_map = get_stack_delta_map(info->mapID);
  if (!outer_map) {
    DEBUG_PRINT(
      "art: failure to look up outer map for text section %lx in mapID %d",
      (unsigned long)exe_id,
      (int)info->mapID);
    state->error_metric = metricID_UnwindArtErrLookupStackDeltaOuterMap;
    return ERR_ART_LOOKUP_STACK_DELTA_OUTER_MAP;
  }

  void *inner_map = bpf_map_lookup_elem(outer_map, &exe_id);
  if (!inner_map) {
    DEBUG_PRINT("art: failure to look up inner map for text section %lx", (unsigned long)exe_id);
    state->error_metric = metricID_UnwindArtErrLookupStackDeltaInnerMap;
    return ERR_ART_LOOKUP_STACK_DELTA_INNER_MAP;
  }

  // Preinitialize the idx for the index to use for page without any deltas.
  u32 idx         = info->firstDelta;
  u16 page_offset = state->text_section_offset & STACK_DELTA_PAGE_MASK;
  if (info->numDeltas) {
    // Page has deltas, so find the correct one to use using binary search.
    u32 lo = info->firstDelta;
    u32 hi = lo + info->numDeltas;

    DEBUG_PRINT(
      "art: intervals should be from %lu to %lu (mapID %d)",
      (unsigned long)lo,
      (unsigned long)hi,
      (int)info->mapID);

    // Do the binary search, up to 16 iterations. Deltas are paged to 64kB pages.
    // They can contain at most 64kB deltas even if everything is single byte opcodes.
    int i;
#pragma unroll
    for (i = 0; i < 16; i++) {
      if (!bsearch_step(inner_map, &lo, &hi, page_offset)) {
        break;
      }
    }
    if (i >= 16 || hi == 0) {
      DEBUG_PRINT("art: failed bsearch in 16 steps. Corrupt data?");
      state->error_metric = metricID_UnwindArtErrLookupIterations;
      return ERR_ART_EXCEEDED_DELTA_LOOKUP_ITERATIONS;
    }
    // After bsearch, 'hi' points to the first entry greater than the requested.
    idx = hi;
  }

  // The code above found the first entry with greater address than requested,
  // so it needs to be decremented by one to get the entry with equal-or-less.
  // This makes also the logic work cross-pages: if the first entry in within
  // the page is too large, this actually gets the entry from the previous page.
  idx--;

  StackDelta *delta = bpf_map_lookup_elem(inner_map, &idx);
  if (!delta) {
    state->error_metric = metricID_UnwindArtErrLookupRange;
    return ERR_ART_LOOKUP_RANGE;
  }

  DEBUG_PRINT(
    "art: delta index %d, addrLow 0x%x, unwindInfo %d", idx, delta->addrLow, delta->unwindInfo);

  // Calculate PC delta from stack delta for merged delta comparison
  int deltaOffset = (int)page_offset - (int)delta->addrLow;
  if (idx < info->firstDelta) {
    // PC is below the first delta of the corresponding page. This means that
    // delta->addrLow contains address relative to one page before the page_offset.
    // Fix up the deltaOffset with this difference of base pages.
    deltaOffset += 1 << STACK_DELTA_PAGE_BITS;
  }

  *addrDiff   = deltaOffset;
  *unwindInfo = delta->unwindInfo;

  if (delta->unwindInfo == STACK_DELTA_INVALID) {
    state->error_metric = metricID_UnwindArtErrStackDeltaInvalid;
    return ERR_ART_STACK_DELTA_INVALID;
  }
  if (delta->unwindInfo == STACK_DELTA_STOP) {
    increment_metric(metricID_UnwindArtStackDeltaStop);
  }

  return ERR_OK;
}



// unwind_register_address calculates the given expression ('opcode'/'param') to get
// the CFA (canonical frame address, to recover PC and be used in further calculations),
// or the address where a register is stored (FP currently), so that the value of
// the register can be recovered.
//
// Currently the following expressions are supported:
//   1. Not recoverable -> NULL is returned.
//   2. When UNWIND_OPCODEF_DEREF is not set:
//      BASE + param
//   3. When UNWIND_OPCODEF_DEREF is set:
//      *(BASE + preDeref) + postDeref
static inline __attribute__((__always_inline__))
u64 unwind_register_address(UnwindState *state, u64 cfa, u8 opcode, s32 param) {
  unsigned long addr, val;
  s32 preDeref = param, postDeref = 0;

  if (opcode & UNWIND_OPCODEF_DEREF) {
    // For expressions that dereference the base expression, the parameter is constructed
    // of pre-dereference and post-derefence operands. Unpack those.
    preDeref = (param & ~UNWIND_DEREF_MASK) / UNWIND_DEREF_MULTIPLIER;
    postDeref = param & UNWIND_DEREF_MASK;
  }

  // Resolve the 'BASE' register, and fetch the CFA/FP/SP value.
  switch (opcode & ~UNWIND_OPCODEF_DEREF) {
  case UNWIND_OPCODE_BASE_CFA:
    addr = cfa;
    break;
  case UNWIND_OPCODE_BASE_FP:
    addr = state->fp;
    break;
  case UNWIND_OPCODE_BASE_SP:
    addr = state->sp;
    break;
#if defined(__aarch64__)
  case UNWIND_OPCODE_BASE_LR:
    DEBUG_PRINT("unwind: lr");

    if (state->lr == 0) {
        increment_metric(metricID_UnwindArtLr0);
        DEBUG_PRINT("Failure to unwind frame: zero LR at %llx", state->pc);
        return 0;
    }

    return state->lr;
  case UNWIND_OPCODE_BASE_REG:
    addr = state->r25;
    break;
#endif
#if defined(__x86_64__)
  case UNWIND_OPCODE_BASE_REG:
    val = (param & ~UNWIND_REG_MASK) >> 1;
    DEBUG_PRINT("unwind: r%d+%lu", param & UNWIND_REG_MASK, val);
    switch (param & UNWIND_REG_MASK) {
    case 0: // rax
      addr = state->rax;
      break;
    case 9: // r9
      addr = state->r9;
      break;
    case 11: // r11
      addr = state->r11;
      break;
    case 15: // r15
      addr = state->r15;
      break;
    default:
      return 0;
    }
    return addr + val;
#endif
  default:
    DEBUG_PRINT("unsupported unwind");
    return 0;
  }

#ifdef OPTI_DEBUG
  switch (opcode) {
  case UNWIND_OPCODE_BASE_CFA:
    DEBUG_PRINT("unwind: cfa+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_FP:
    DEBUG_PRINT("unwind: fp+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_SP:
    DEBUG_PRINT("unwind: sp+%d", preDeref);
    break;
  case UNWIND_OPCODE_BASE_CFA | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(cfa+%d)+%d", preDeref, postDeref);
    break;
  case UNWIND_OPCODE_BASE_FP | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(fp+%d)+%d", preDeref, postDeref);
    break;
  case UNWIND_OPCODE_BASE_SP | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(sp+%d)+%d", preDeref, postDeref);
    break;
#if defined(__aarch64__)
  case UNWIND_OPCODE_BASE_REG | UNWIND_OPCODEF_DEREF:
    DEBUG_PRINT("unwind: *(r25+%d)+%d", preDeref, postDeref);
    break;
#endif
  }
#endif

  // Adjust based on parameter / preDereference adder.
  addr += preDeref;
  if ((opcode & UNWIND_OPCODEF_DEREF) == 0) {
    // All done: return "BASE + param"
    return addr;
  }

  // Dereference, and add the postDereference adder.
  if (bpf_probe_read_user(&val, sizeof(val), (void*) addr)) {
    DEBUG_PRINT("unwind failed to dereference address 0x%lx", addr);
    return 0;
  }
  // Return: "*(BASE + preDeref) + postDeref"
  return val + postDeref;
}

#if defined(__aarch64__)
static inline __attribute__((__always_inline__))
ErrorCode resolve_unwind_info_and_cfa(struct UnwindState *state, struct UnwindInfo **result_info, u64 *cfa) {
  int addrDiff = 0;
  u32 unwindInfo = 0;

  // The relevant executable is compiled with frame pointer omission, so
  // stack deltas need to be retrieved from the relevant map.
  ErrorCode error = get_stack_delta(state, &addrDiff, &unwindInfo);
  if (error) {
    return ERR_ART_EMPTY_STACK;
  }

  UnwindInfo *info = bpf_map_lookup_elem(&unwind_info_array, &unwindInfo);
  if (!info) {
    increment_metric(metricID_UnwindArtErrBadUnwindInfoIndex);
    DEBUG_PRINT("art: giving up due to invalid unwind info array index");
    return ERR_ART_NO_UNWIND_INFO;
  }
  *result_info = info;

  s32 param = info->param;
  if (info->mergeOpcode) {
    DEBUG_PRINT("art: addrDiff %d, merged delta %#02x", addrDiff, info->mergeOpcode);
    if (addrDiff >= (info->mergeOpcode & ~MERGEOPCODE_NEGATIVE)) {
      param += (info->mergeOpcode & MERGEOPCODE_NEGATIVE) ? -8 : 8;
      DEBUG_PRINT("art: merged delta match: cfaDelta=%d", unwindInfo);
    }
  }

  *cfa = unwind_register_address(state, 0, info->opcode, param);
  if (!cfa) {
    // report failure to resolve RA and stop unwinding
    increment_metric(metricID_UnwindArtBadCFA);
    DEBUG_PRINT("art: giving up due to failure to resolve cfa");
    return ERR_ART_BAD_CFA;
  }

  return ERR_OK;
}

static inline __attribute__((__always_inline__))
ErrorCode resolve_dex_pc(struct UnwindInfo *info, u64 cfa, struct UnwindState *state, u64 *dex_pc) {
  u64 address = 0;
  if (!dex_pc) {
    return ERR_ART_INVALID_PARAM;
  }

  *dex_pc = 0;

  // skip art unwinding if we can't use dex pc
  if (info->archdef2Opcode != UNWIND_OPCODE_BASE_DEX_PC) {
    DEBUG_PRINT("art: skip art unwinding due to no dex_pc");
    return ERR_ART_SKIP;
  }

  if (info->archdef2Param == 22) {
    // Try to resolve r22 for ART unwinder
    // TODO: r22 is always CFA - 72 in this case, can we remove archdef1 to reduce size of delta map
    if (info->archdef1Opcode != UNWIND_OPCODE_COMMAND) {
      address = unwind_register_address(state, cfa, info->archdef1Opcode, info->archdef1Param);
      bpf_probe_read_user(dex_pc, sizeof(*dex_pc), (void*)(address));
    }
  } else {
    DEBUG_PRINT("art: failed to load dex_pc(r%u)", info->archdef2Param)
  }
  DEBUG_PRINT("art: cfa 0x%llx, dex_pc 0x%llx", cfa, *dex_pc);

  return ERR_OK;
}

static ErrorCode unwind_one_art_frame(struct UnwindInfo *info, u64 cfa, u64 pid, u32 frame_idx, struct UnwindState *state, bool* stop) {
  *stop = false;

  // Resolve Return Address, it is either the value of link register or
  // stack address where RA is stored
  u64 ra = unwind_register_address(state, cfa, info->fpOpcode, info->fpParam);
  if (ra) {
    if (info->fpOpcode == UNWIND_OPCODE_BASE_LR) {
      // set return address location to link register
      state->pc = ra;
    } else {
      DEBUG_PRINT("art: RA: %016llX", (u64)ra);

      // read the value of RA from stack
      if (bpf_probe_read_user(&state->pc, sizeof(state->pc), (void*)ra)) {
        // error reading memory, mark RA as invalid
        ra = 0;
      }
    }

    state->pc = normalize_pac_ptr(state->pc);
  }

  if (!ra) {
  err_native_pc_read:
    // report failure to resolve RA and stop unwinding
    increment_metric(metricID_UnwindArtErrPCRead);
    DEBUG_PRINT("art: giving up due to failure to resolve RA");
    return ERR_NATIVE_PC_READ;
  }

  // Try to resolve r25 for ART unwinder
  if (info->archdefOpcode != UNWIND_OPCODE_COMMAND) {
    state->r25 = unwind_register_address(state, cfa, info->archdefOpcode, info->archdefParam);
    bpf_probe_read_user(&state->r25, sizeof(state->r25), (void*)(state->r25));
  }
  DEBUG_PRINT("art: r25: 0x%llx", (u64)state->r25);

  // Try to resolve r22 for ART unwinder
  if (info->archdef1Opcode != UNWIND_OPCODE_COMMAND) {
    state->r22 = unwind_register_address(state, cfa, info->archdef1Opcode, info->archdef1Param);
    bpf_probe_read_user(&state->r22, sizeof(state->r22), (void*)(state->r22));
  }
  DEBUG_PRINT("art: r22: 0x%llx", (u64)state->r22);

  // Try to resolve frame pointer
  // UNWIND_OPCODE_COMMAND means regSame in CIE
  if (info->realFpOpcode != UNWIND_OPCODE_COMMAND) {
    state->fp = unwind_register_address(state, cfa, info->realFpOpcode, info->realFpParam);
    // we can assume the presence of frame pointers
    if (info->fpOpcode != UNWIND_OPCODE_BASE_LR) {
      // FP precedes the RA on the stack (Aarch64 ABI requirement)
      bpf_probe_read_user(&state->fp, sizeof(state->fp), (void*)(state->fp));
    }
  }

  state->sp = cfa;
  unwinder_mark_nonleaf_frame(state);
frame_ok:
  increment_metric(metricID_UnwindArtFrames);
  return ERR_OK;
}

#else
#error "Unsupported architecture"
#endif

static inline __attribute__((__always_inline__)) int unwind_art(struct pt_regs *ctx) {
  ErrorCode err = ERR_OK;
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  Trace *trace = &record->trace;
  
  int unwinder = get_next_unwinder_after_interpreter(record);

  u32 pid = record->trace.pid;
  ArtProcInfo *ainfo = bpf_map_lookup_elem(&art_procs, &pid);
  if (!ainfo) {
    DEBUG_PRINT("art: no art introspection data");
    err = ERR_ART_NO_PROC_INFO;
    increment_metric(metricID_UnwindArtErrNoProcInfo);
    goto exit;
  }

  UnwindState *state = &record->state;
  u8 frame_type = FRAME_MARKER_ART; 
  u64 file_id = state->text_section_id;
  u64 line = state->text_section_offset;
#pragma unroll
  for (int i = 0; i < ART_FRAMES_PER_PROGRAM; i++) {
    state = &record->state;
    u32 frame_idx = trace->stack_len;
    frame_type = FRAME_MARKER_ART; 
    file_id = state->text_section_id;
    line = state->text_section_offset;
    bool is_jitted = state->text_section_id != ainfo->interpreter;
    u64 cfa = 0;
    DEBUG_PRINT("enter art unwinder: text_section_id: 0x%llx, text_section_bias: 0x%llx, text_section_offset: 0x%llx",
      state->text_section_id, state->text_section_bias, state->text_section_offset);

    if (state->text_section_bias == 0) {
      DEBUG_PRINT("art: unwinding unmapped JIT frame");
      // JIT info are not yet mapped, tell the userspace to rescan maps
      report_pid(ctx, record->trace.pid, RATELIMIT_ACTION_DEFAULT);
    }

    increment_metric(metricID_UnwindArtAttempts);
    struct UnwindInfo *uinfo = NULL;
    err = resolve_unwind_info_and_cfa(state, &uinfo, &cfa);
    if (err) {
      DEBUG_PRINT("failed to resolve unwind info and cfa, err: %d", err);
      unwinder = PROG_UNWIND_STOP;
      break;
    }
    if (is_jitted) {
      DEBUG_PRINT("art: jitted code");
    } else {
      //state->pc -= 4;
      u64 dex_pc = 0;
      err = resolve_dex_pc(uinfo, cfa, state, &dex_pc);
      if (err) {
        DEBUG_PRINT("art: native code");
        frame_type = FRAME_MARKER_NATIVE;
      } else {
        DEBUG_PRINT("art: interpreted code");
        line = dex_pc;
      }
    }

    DEBUG_PRINT("Pushing art frame: %llx %llx to position %u on stack",
                  file_id, line, record->trace.stack_len);
    err = _push_with_return_address(trace, file_id, line, frame_type, record->state.return_address);
    if (err) {
      DEBUG_PRINT("failed to push art frame");
      break;
    }

    bool stop;
    err = unwind_one_art_frame(uinfo, cfa, pid, frame_idx, &record->state, &stop);
    if (err || stop) {
      DEBUG_PRINT("failed to unwind art frame");
      break;
    }

    err = get_next_unwinder_after_native_frame(record, &unwinder);
    if (err || unwinder != PROG_UNWIND_ART) {
      if (err)
        DEBUG_PRINT("failed to get next unwinder after art frame");
      break;
    }
  }

exit:
  record->state.unwind_error = err;
  if (unwinder == PROG_UNWIND_STOP) {
    DEBUG_PRINT("Pushing art frame before stop: %llx %llx to position %u on stack",
                  file_id, line, record->trace.stack_len);
    _push_with_return_address(trace, file_id, line, frame_type, record->state.return_address);
  }
  tail_call(ctx, unwinder);
  return -1;
}
MULTI_USE_FUNC(unwind_art)
