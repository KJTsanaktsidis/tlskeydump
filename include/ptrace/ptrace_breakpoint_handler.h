// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __ptrace_breakpoint_handler_h
#define __ptrace_breakpoint_handler_h

#include "config.h"

#include <elfutils/libdw.h>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace Ptrace {

class PtraceProcess;
struct FunctionArguments;

struct FunctionName {
  std::string name;
  std::string soname;

  friend bool operator==(const FunctionName &first, const FunctionName &second) {
    return first.name == second.name && first.soname == second.soname;
  }
  friend bool operator!=(const FunctionName &first, const FunctionName &second) {
    return !(first == second);
  }
};

struct FunctionInfo {
  FunctionName name;
  Dwarf_Die die;
};

class BreakpointHandler {
public:
  virtual ~BreakpointHandler() {}

  virtual std::vector<FunctionName> trap_functions() { return std::vector<FunctionName>(); }
  virtual void on_attach(PtraceProcess *proc, FunctionInfo function_info) {}
  virtual void on_trap(PtraceProcess *proc, FunctionInfo function_info, FunctionArguments *args) {}
};

} // namespace Ptrace

#endif
