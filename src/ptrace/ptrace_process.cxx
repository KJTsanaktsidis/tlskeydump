// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <algorithm>
#include <boost/assert.hpp>
#include <boost/format.hpp>
#include <boost/log/common.hpp>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <filesystem>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <utility>

#include "dwarf_util/dwarf_die_cache.h"
#include "dwarf_util/dwarf_helpers.h"
#include "ptrace/dwfl_handle.h"
#include "ptrace/ptrace_arch.h"
#include "ptrace/ptrace_breakpoint_handler.h"
#include "ptrace/ptrace_exceptions.h"
#include "ptrace/ptrace_mem.h"
#include "ptrace/ptrace_process.h"

namespace Ptrace {

static inline int get_ptrace_event(int status) { return (status >> 16) & 0x0F; }

static pid_t fork_child(std::string binary, std::vector<std::string> argv) {
  pid_t pid = fork();
  if (pid == -1) {
    char errbuf[512];
    char *err = strerror_r(errno, errbuf, sizeof(errbuf));
    throw ForkExecError("error forking child: %s", err);
  }
  if (pid == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);

    // once we are, exec the child
    char **argv_ptrs = new char *[argv.size() + 2];

    // need to copy the binary name to argv[0]
    argv_ptrs[0] = new char[binary.size() + 1];
    std::copy(binary.c_str(), binary.c_str() + binary.size() + 1, argv_ptrs[0]);

    for (unsigned int i = 0; i < argv.size(); i++) {
      char *data = new char[argv[i].size() + 1];
      std::copy(argv[i].c_str(), argv[i].c_str() + argv[i].size() + 1, data);
      argv_ptrs[i + 1] = data;
    }
    argv_ptrs[argv.size() + 1] = nullptr;

    // now exec
    execvp(binary.c_str(), argv_ptrs);
    // control should not reach here
    throw ForkExecError("error exec'ing child");
  }

  // Make the absolute first thing we do, right here, to set PTRACE_O_EXITKILL so that no
  // matter what happens elsewhere, we don't let the child outlive us.
  // We intentionally don't check the return value here either - we're going to call this
  // again very soon and check it there anyway.
  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
  return pid;
}

static ARCH_WORD ptrace_ex(__ptrace_request op, pid_t pid, uintptr_t addr, ARCH_WORD data) {
  errno = 0;
  long ret = ptrace(op, pid, addr, data);
  if (errno == ESRCH) {
    throw ChildExitedError("child process has exited");
  } else if (errno != 0) {
    char errbuf[512];
    char *err = strerror_r(errno, errbuf, sizeof(errbuf));
    throw PtraceError("error calling ptrace op %d on pid %d: %s", op, pid, err);
  }
  return ret;
}

static FDDestroyer open_proc_mem(pid_t pid) {
  FDDestroyer fd(open((std::filesystem::path("/proc") / std::to_string(pid) / "mem").c_str(),
                      O_RDWR | O_CLOEXEC, 0));
  if (fd.fd == -1) {
    char errbuf[512];
    char *err = strerror_r(errno, errbuf, sizeof(errbuf));
    throw ForkExecError("failed to open tracer /proc/%d/pid: %s", pid, err);
  }
  return fd;
}

PtraceProcess::PtraceProcess(std::string binary, std::vector<std::string> argv,
                             std::vector<BreakpointHandler *> breakpoint_handlers,
                             DebuginfoSearch::Options debuginfo_opts) {
  // Make the child
  _pid = fork_child(binary, argv);
  configure_logger_component(_logger, (boost::format("PtraceProcess pid=%d") % _pid).str());

  _owns_process = true;
  _state = State::RUNNING;

  // Try an open a pidfd, if that's supported
#ifdef HAVE_PIDFD
  int pidfd = syscall(SYS_pidfd_open, _pid, 0);
  if (pidfd != -1) {
    // pidfd is supported
    _pidfd = FDDestroyer(pidfd);
  }
#endif

  // Open /proc/pid/mem
  _proc_mem_fd = open_proc_mem(_pid);

  // Wait until it hits the initial trap, and then set the options.
  while (true) {
    int status;
    int r = waitpid(_pid, &status, __WALL);
    if (r == -1) {
      char errbuf[512];
      char *err = strerror_r(errno, errbuf, sizeof(errbuf));
      throw ForkExecError("failed on initial wait for child: %s", err);
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      throw ForkExecError("child process unexpectedly died on initial wait");
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
      _state = State::STOPPED;
      break;
    }
  }

  ptrace_ex(PTRACE_SETOPTIONS, _pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL);
  _debuginfo_opts = debuginfo_opts;
  _debuginfo_opts.pid = _pid;
  _breakpoint_handlers = breakpoint_handlers;
  // As an optimisation, don't load up a dwfl handle yet; defer doing that until
  // we get exec() to happen. That will avoid having to load and parse all of our
  // _own_ code.
  ptrace_ex(PTRACE_CONT, _pid, 0, 0);
  _state = State::RUNNING;
}

PtraceProcess::~PtraceProcess() {
  if (_owns_process) {
    if (_state != State::REAPED) {
      signal_tracee(SIGKILL);
      int status;
      waitpid(_pid, &status, __WALL);
      _state = State::REAPED;
    }
  }
}

void PtraceProcess::signal_tracee(int signal) {
  int signal_ret;
#ifdef HAVE_PIDFD
  if (_pidfd.fd != -1) {
    signal_ret = syscall(SYS_pidfd_send_signal, _pidfd.fd, signal, nullptr, 0);
  } else {
    signal_ret = kill(_pid, signal);
  }
#else
  signal_ret = kill(_pid, signal);
#endif

  if (signal_ret == -1 && errno != ESRCH) {
    char errbuf[512];
    char *err = strerror_r(errno, errbuf, sizeof(errbuf));
    throw PtraceError("failed sending signal %d to pid %d: %s", signal, _pid, err);
  }
}

State PtraceProcess::state() { return _state; }

DwflHandle *PtraceProcess::dwfl() { return _dwfl.get(); }

void PtraceProcess::handle_ptrace_stop(int status) {
  if (WIFEXITED(status) || WIFSIGNALED(status)) {
    _state = State::REAPED;
    int exit_status = 0;
    if (WIFEXITED(status)) {
      exit_status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      exit_status = -WTERMSIG(status);
    }
    BOOST_LOG_SEV(_logger, Sev::INFO) << "child exited with status " << exit_status;
    return;
  }

  try {
    if (WIFSTOPPED(status)) {
      _state = State::STOPPED;
      int signal = WSTOPSIG(status);
      int ptrace_event = get_ptrace_event(status);

      if (ptrace_event == PTRACE_EVENT_EXEC) {
        // The memory map just returns EOF once exec hapens; reopen it.
        _proc_mem_fd = open_proc_mem(_pid);
        // When exec'ing, we need to reload the DWARF data.
        _breakpoints.clear();

        if (!_dwfl.get()) {
          _dwfl.reset(new DwflHandle(_pid, _debuginfo_opts));
        }
        _dwfl->reload_maps();
        // We also need to set a breakpoint at _start (if the binary
        // is dynamic), so we can call reload_maps _again_.
        if (_dwfl->is_dynamic()) {
          set_breakpoint(_dwfl->elf_start_address());
        }

        // Attach the breakpoints from all our breakpoint handlers
        attach_breakpoint_handlers();
      }

      if (signal == SIGTRAP) {
        user_regs_struct regs;
        ptrace_ex(PTRACE_GETREGS, _pid, 0, reinterpret_cast<uintptr_t>(&regs));
        uintptr_t original_ip = GET_IP(regs);
        uintptr_t trap_insn_start = original_ip - TRAP_INSN_LEN;
        if (_breakpoints.contains(trap_insn_start)) {
          // replace the original instruction
          auto bp = _breakpoints[trap_insn_start];
          SET_IP(regs, trap_insn_start);
          Ptrace::write_process_mem_bytes(_proc_mem_fd.fd, trap_insn_start, bp.original_data.data(),
                                          bp.original_data.size());
          ptrace_ex(PTRACE_SETREGS, _pid, 0, reinterpret_cast<uintptr_t>(&regs));

          // Now we have everything how it was.
          _current_breakpoint_addr = trap_insn_start;
          if (bp.fn.has_value()) {
            FunctionArguments fnargs;
            fnargs.fn = bp.fn.value();
            fnargs.gp_regs = regs;
            fnargs.pid = _pid;
            ptrace_ex(PTRACE_GETFPREGS, _pid, 0, reinterpret_cast<uintptr_t>(&fnargs.fp_regs));
            auto arg_data =
                function_arguments(&fnargs.fn, fnargs.pid, fnargs.gp_regs, fnargs.fp_regs);
            fnargs.argument_buffer = arg_data.first;
            fnargs.argument_indexes = arg_data.second;
            _current_fn_args = fnargs;
          } else {
            _current_fn_args = std::nullopt;
          }

          _state = State::BREAKPOINT;
        }
      }
    }
  } catch (ChildExitedError &) {
  }
}

void PtraceProcess::handle_ptrace_continue(int status) {
  // If we were broken, unbreak
  if (_state == State::BREAKPOINT) {
    try {
      // Single step over the breakpoint
      ptrace_ex(PTRACE_SINGLESTEP, _pid, 0, 0);
      // This is going to be pretty broken on architectures where the trap instruction is bigger
      // than the instruction that proceeds it - we might singlestep one byte, but then put a
      // two byte trap over the top of that. I doubt that includes any architecture I care about
      // though, so just assert it rather than looping through PTRACE_SINGLESTEP
      user_regs_struct regs;
      ptrace_ex(PTRACE_GETREGS, _pid, 0, reinterpret_cast<uintptr_t>(&regs));
      BOOST_ASSERT(GET_IP(regs) - _current_breakpoint_addr >= TRAP_INSN_LEN);
      // Put the breakpoint back.
      auto bp = _breakpoints[_current_breakpoint_addr];
      Ptrace::write_process_mem_bytes(_proc_mem_fd.fd, bp.trap_addr, bp.trap_data.data(),
                                      bp.trap_data.size());
    } catch (ChildExitedError &) {
    }
  }

  int sig = 0;
  if (WIFSTOPPED(status)) {
    int stopsig = WSTOPSIG(status);
    if (stopsig != SIGTRAP) {
      sig = stopsig;
    }
  }

  try {
    ptrace_ex(PTRACE_CONT, _pid, 0, sig);
    _state = State::RUNNING;
  } catch (ChildExitedError &) {
  }
}

void PtraceProcess::handle_ptrace_event(int status) {
  handle_ptrace_stop(status);
  // As a special case, if we're broken at _start, reload the maps.
  // TODO - when we handle dlopen(), that will go here too.
  if (_state == State::BREAKPOINT &&
      current_breakpoint().value().trap_addr == _dwfl->elf_start_address()) {
    _dwfl->reload_maps();
    attach_breakpoint_handlers();
  }

  // TODO - cache this
  if (_state == State::BREAKPOINT && current_breakpoint_args().has_value()) {
    FunctionInfo info;
    info.name = current_breakpoint().value().name.value();
    info.die = current_breakpoint().value().fn.value();
    for (auto &h : _breakpoint_handlers) {
      auto trap_fns = h->trap_functions();
      auto found = std::find(trap_fns.begin(), trap_fns.end(), info.name);
      if (found != trap_fns.end()) {
        h->on_trap(this, info, &_current_fn_args.value());
      }
    }
  }

  handle_ptrace_continue(status);
}

void PtraceProcess::set_breakpoint(Dwfl_Module *mod, Dwarf_Die fn, FunctionName fnname) {
  BOOST_ASSERT(_state == State::STOPPED || _state == State::BREAKPOINT);

  Dwarf_Addr bias;
  Dwarf *dw = dwfl_module_getdwarf(mod, &bias);
  BOOST_ASSERT(dw);
  auto addrs = DwarfUtil::die_function_entry(&fn, bias);

  for (auto addr : addrs) {
    if (_breakpoints.contains(addr)) {
      continue;
    }

    Breakpoint bp;
    bp.original_data = std::vector<uint8_t>(TRAP_INSN_LEN);
    Ptrace::read_process_mem_bytes(_proc_mem_fd.fd, addr, bp.original_data.data(),
                                   sizeof(uint8_t) * TRAP_INSN_LEN);
    bp.trap_addr = addr;
    bp.trap_data = TRAP_INSN();
    Ptrace::write_process_mem_bytes(_proc_mem_fd.fd, addr, bp.trap_data.data(),
                                    sizeof(uint8_t) * TRAP_INSN_LEN);
    bp.fn_module = mod;
    bp.fn = fn;
    bp.name = fnname;

    _breakpoints[addr] = bp;
  }
}

void PtraceProcess::set_breakpoint(uintptr_t addr) {
  if (_breakpoints.contains(addr)) {
    return;
  }

  Breakpoint bp;
  bp.original_data = std::vector<uint8_t>(TRAP_INSN_LEN);
  Ptrace::read_process_mem_bytes(_proc_mem_fd.fd, addr, bp.original_data.data(),
                                 sizeof(uint8_t) * TRAP_INSN_LEN);
  bp.trap_addr = addr;
  bp.trap_data = TRAP_INSN();
  Ptrace::write_process_mem_bytes(_proc_mem_fd.fd, addr, bp.trap_data.data(),
                                  sizeof(uint8_t) * TRAP_INSN_LEN);

  _breakpoints[addr] = bp;
}

std::optional<Breakpoint> PtraceProcess::current_breakpoint() {
  if (_state != State::BREAKPOINT) {
    return std::nullopt;
  }
  if (!_breakpoints.contains(_current_breakpoint_addr)) {
    return std::nullopt;
  }
  return _breakpoints[_current_breakpoint_addr];
}

std::optional<FunctionArguments> PtraceProcess::current_breakpoint_args() {
  if (_state != State::BREAKPOINT) {
    return std::nullopt;
  }
  return _current_fn_args;
}

void PtraceProcess::attach_breakpoint_handlers() {
  for (auto h : _breakpoint_handlers) {
    for (auto break_fn : h->trap_functions()) {
      auto die_entry = _dwfl->get_function(break_fn.name, break_fn.soname);
      if (die_entry.has_value()) {
        set_breakpoint(die_entry->module->mod, die_entry->die, break_fn);
        FunctionInfo info;
        info.name = break_fn;
        info.die = die_entry.value().die;
        h->on_attach(this, info);
      } else {
        // TODO - implement static searching etc.
      }
    }
  }
}

pid_t PtraceProcess::pid() { return _pid; }
int PtraceProcess::mem_fd() { return _proc_mem_fd.fd; }

} // namespace Ptrace
