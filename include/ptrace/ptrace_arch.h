#ifndef __ptrace_arch_h
#define __ptrace_arch_h

#include "config.h"

#include <boost/predef.h>
#include <cstdint>
#include <elfutils/libdw.h>
#include <sys/user.h>
#include <tuple>
#include <vector>

#include "dwarf_util/dwarf_helpers.h"
#include "ptrace/ptrace_exceptions.h"

namespace Ptrace {

#ifdef BOOST_ARCH_X86_64

typedef uint64_t ARCH_WORD;
constexpr size_t TRAP_INSN_LEN = 1;

// gets around not being able to define a char array in a header file...
static inline std::vector<uint8_t> TRAP_INSN() { return std::vector<uint8_t>{0xCC}; }

static inline uint64_t GET_IP(user_regs_struct &regs) { return regs.rip; }

static inline void SET_IP(user_regs_struct &regs, uint64_t ip) { regs.rip = ip; }

BOOST_STATIC_ASSERT(sizeof(ARCH_WORD) >= TRAP_INSN_LEN);

static inline std::pair<std::vector<uint8_t>, std::vector<ssize_t>>
function_arguments(Dwarf_Die *fn, const pid_t pid, const user_regs_struct &gp_regs,
                   const user_fpregs_struct &fp_regs) {
  // TODO - variardic arguments
  // TODO - can't actually read floating point registers
  // TODO - can't read arguments spilled to stack
  int nth_gp_arg = 0;
  int nth_float_arg = 0;
  int nth_stack_arg = 0;
  auto args_opt = DwarfUtil::die_function_args(fn);
  if (!args_opt.has_value()) {
    throw PtraceError("die was not a function");
  }
  auto args = args_opt.value();

  std::vector<uint8_t> arg_data;
  std::vector<ssize_t> arg_offsets;

  for (size_t i = 0; i < args.size(); i++) {
    auto die = &args[i];
    auto die_type = DwarfUtil::die_type(die);
    size_t die_size = 0;
    if (die_type.has_value()) {
      die_size = DwarfUtil::die_size(&die_type.value()).value_or(0);
    }
    if (DwarfUtil::die_is_float(die)) {
      nth_float_arg++;
      arg_offsets.push_back(-1); // TODO - actually implement this
    } else if (die_size > sizeof(ARCH_WORD)) {
      nth_stack_arg++;
      arg_offsets.push_back(-1); // TODO - actually implement this
    } else if (die_size != 0) {
      ARCH_WORD arg_value;
      switch (nth_gp_arg) {
      case 0:
        arg_value = gp_regs.rdi;
        break;
      case 1:
        arg_value = gp_regs.rsi;
        break;
      case 2:
        arg_value = gp_regs.rdx;
        break;
      case 3:
        arg_value = gp_regs.rcx;
        break;
      case 4:
        arg_value = gp_regs.r8;
        break;
      case 5:
        arg_value = gp_regs.r9;
        break;
      default:
        BOOST_ASSERT_MSG(false, "unreachable - 6 gp args");
      }
      // Copy the low die_size bytes of the argument to our storage
      auto ix = arg_data.size();
      auto arg_ptr = reinterpret_cast<uint8_t *>(&arg_value);
      std::copy(arg_ptr, arg_ptr + die_size, std::back_inserter(arg_data));
      arg_offsets.push_back(ix);
      nth_gp_arg++;
    }
  }

  return std::make_pair(arg_data, arg_offsets);
}

#else
#error "This architecture is unsupported"
#endif

} // namespace Ptrace

#endif
