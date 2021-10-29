// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __process_monitor_h
#define __process_monitor_h

#include "config.h"

#include <chrono>
#include <signal.h>
#include <vector>

#include "log.h"
#include "ptrace_process.h"

namespace Ptrace {

class ProcessMonitor {
public:
  ProcessMonitor(int graceful_shutdown_signal, std::chrono::milliseconds graceful_shutdown_timeout);
  ~ProcessMonitor();

  // I could probably make this class moveable, but definitely not
  // copyable. Implement moveable if required.
  ProcessMonitor(ProcessMonitor &&other) = delete;
  ProcessMonitor &operator=(ProcessMonitor &&other) = delete;
  ProcessMonitor(const ProcessMonitor &other) = delete;
  ProcessMonitor &operator=(const ProcessMonitor &other) = delete;

  void configure_signals();
  int run_procs(std::vector<PtraceProcess *> procs);

private:
  Logger _logger;
  int _signalfd;
  int _graceful_shutdown_signal;
  std::chrono::milliseconds _graceful_shutdown_timeout;
  sigset_t _old_mask;
};

} // namespace Ptrace

#endif
