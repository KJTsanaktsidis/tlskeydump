#ifndef __ptraced_process
#define __ptraced_process

#include "config.h"

#include <cstring>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <memory>
#include <optional>
#include <string>
#include <sys/user.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "cleanup_pointers.h"
#include "debuginfo_search/debuginfo_search.h"
#include "dwfl_handle.h"
#include "log.h"
#include "ptrace_arch.h"
#include "ptrace_breakpoint_handler.h"

namespace Ptrace {

struct FunctionArguments {
  pid_t pid;
  user_regs_struct gp_regs;
  user_fpregs_struct fp_regs;
  Dwarf_Die fn;
  std::vector<uint8_t> argument_buffer;
  std::vector<ssize_t> argument_indexes;

  template <typename T> T at(size_t nth) {
    ssize_t nth_size;
    if (nth < argument_indexes.size() - 1) {
      nth_size = argument_indexes[nth + 1] - argument_indexes[nth];
    } else {
      nth_size = argument_buffer.size() - argument_indexes[nth];
    }
    uint8_t *arg_ptr = argument_buffer.data() + argument_indexes[nth];
    T result;
    std::memcpy(&result, arg_ptr, nth_size);
    return result;
  }
};

struct Breakpoint {
  uintptr_t trap_addr;
  std::vector<uint8_t> original_data;
  std::vector<uint8_t> trap_data;
  Dwfl_Module *fn_module;
  std::optional<Dwarf_Die> fn;
  std::optional<FunctionName> name;
};

enum class State {
  RUNNING,
  STOPPED,
  BREAKPOINT,
  REAPED,
};

class PtraceProcess {
public:
  PtraceProcess(std::string binary, std::vector<std::string> argv,
                std::vector<BreakpointHandler *> breakpoint_handlers,
                DebuginfoSearch::Options debuginfo_opts);
  ~PtraceProcess();

  PtraceProcess(const PtraceProcess &other) = delete;
  PtraceProcess(PtraceProcess &&other) = delete;
  PtraceProcess &operator=(PtraceProcess &&other) = delete;
  PtraceProcess &operator=(const PtraceProcess &other) = delete;

  pid_t pid();
  void signal_tracee(int signal);
  State state();
  void handle_ptrace_event(int wait_result);
  DwflHandle *dwfl();
  int mem_fd();

private:
  Logger _logger;

  pid_t _pid;
  FDDestroyer _pidfd;
  FDDestroyer _proc_mem_fd;
  bool _owns_process;
  State _state;
  std::unique_ptr<DwflHandle> _dwfl;
  std::unordered_map<uintptr_t, Breakpoint> _breakpoints;
  uintptr_t _current_breakpoint_addr;
  std::optional<FunctionArguments> _current_fn_args;
  DebuginfoSearch::Options _debuginfo_opts;
  std::vector<BreakpointHandler *> _breakpoint_handlers;

  void handle_ptrace_stop(int wait_result);
  void handle_ptrace_continue(int wait_result);
  void set_breakpoint(Dwfl_Module *mod, Dwarf_Die fn, FunctionName fnname);
  void set_breakpoint(uintptr_t addr);
  std::optional<Breakpoint> current_breakpoint();
  std::optional<FunctionArguments> current_breakpoint_args();
  void attach_breakpoint_handlers();
};

} // namespace Ptrace

#endif
