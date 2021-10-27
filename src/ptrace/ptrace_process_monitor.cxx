#include "config.h"

#include <algorithm>
#include <boost/assert.hpp>
#include <boost/format.hpp>
#include <boost/log/common.hpp>
#include <cstring>
#include <errno.h>
#include <memory>
#include <signal.h>
#include <stdexcept>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "ptrace/ptrace_process.h"
#include "ptrace/ptrace_process_monitor.h"

namespace Ptrace {

ProcessMonitor::ProcessMonitor(int graceful_shutdown_signal,
                               std::chrono::milliseconds graceful_shutdown_timeout)
    : _signalfd(-1), _graceful_shutdown_signal(graceful_shutdown_signal),
      _graceful_shutdown_timeout(graceful_shutdown_timeout) {
  configure_logger_component(_logger, "ProcessMonitor");
}

ProcessMonitor::~ProcessMonitor() {
  if (_signalfd != -1) {
    alarm(0);
    sigprocmask(SIG_SETMASK, &_old_mask, nullptr);
    close(_signalfd);
  }
}

void ProcessMonitor::configure_signals() {
  sigset_t mask;
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGALRM);

  _signalfd = signalfd(-1, &mask, SFD_CLOEXEC);
  if (_signalfd == -1) {
    char buf[512];
    throw std::runtime_error(
        (boost::format("failed setting signalfd: %s") % strerror_r(errno, buf, sizeof(buf))).str());
  }

  int res = sigprocmask(SIG_BLOCK, &mask, &_old_mask);
  if (res == -1) {
    char buf[512];
    throw std::runtime_error(
        (boost::format("failed setting sigprocmask: %s") % strerror_r(errno, buf, sizeof(buf)))
            .str());
  }
}

int ProcessMonitor::run_procs(std::vector<PtraceProcess *> procs) {
  BOOST_ASSERT(_signalfd != -1);

  while (true) {
    signalfd_siginfo next_sig;
    int sigbytes_read = read(_signalfd, &next_sig, sizeof(next_sig));
    if (sigbytes_read == 0) {
      throw std::runtime_error((boost::format("signalfd unexpectedly EOF")).str());
    } else if (sigbytes_read == -1) {
      char buf[512];
      throw std::runtime_error(
          (boost::format("error reading from signalfd: %s") % strerror_r(errno, buf, sizeof(buf)))
              .str());
    }

    switch (next_sig.ssi_signo) {
    case SIGCHLD:
      // ptrace dealio
      while (procs.size() > 0) {
        int status;
        pid_t waited_pid = waitpid(-1, &status, __WALL | WNOHANG);
        if (waited_pid == 0) {
          // not an error, no children ready.
          break;
        } else if (waited_pid == -1) {
          char buf[512];
          throw std::runtime_error(
              (boost::format("error from waitpid: %s") % strerror_r(errno, buf, sizeof(buf)))
                  .str());
        }

        // which proc is it?
        auto proc_it =
            std::find_if(procs.begin(), procs.end(),
                         [waited_pid](PtraceProcess *p) -> bool { return p->pid() == waited_pid; });
        if (proc_it == procs.end()) {
          BOOST_LOG_SEV(_logger, Sev::WARNING)
              << "got waitpid result from unknown child pid " << waited_pid;
          continue;
        }

        // Found which process it was; let it handle any callbacks/breakpoints/etc
        auto proc = *proc_it;
        proc->handle_ptrace_event(status);
        if (proc->state() == State::REAPED) {
          procs.erase(proc_it);
        }
      }

      // Return if everything we were watching is shut down.
      if (procs.size() == 0) {
        return 0;
      }
      break;
    case SIGALRM:
      BOOST_LOG_SEV(_logger, Sev::WARNING) << "graceful shutdown timeout expired, killing";
      // falls through
    case SIGTERM:
      BOOST_LOG_SEV(_logger, Sev::INFO) << "doing non graceful shutdown of children";
      // non-graceful shutdown
      for (auto &proc : procs) {
        proc->signal_tracee(SIGKILL);
      }
      break;
    case SIGINT:
      // graceful shutdown
      BOOST_LOG_SEV(_logger, Sev::INFO) << "doing graceful shutdown of children";
      for (auto &proc : procs) {
        proc->signal_tracee(_graceful_shutdown_signal);
      }
      // TODO - something less incredibly gross than sigalarm.
      alarm(_graceful_shutdown_timeout.count() / 1000);
      break;
    default:
      BOOST_LOG_SEV(_logger, Sev::WARNING)
          << "got unknown signal " << next_sig.ssi_signo << " from signalfd";
      break;
    }
  }
}

} // namespace Ptrace
