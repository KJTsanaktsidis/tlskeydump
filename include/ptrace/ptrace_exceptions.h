// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __ptrace_exceptions_h
#define __ptrace_exceptions_h

#include "config.h"
#include "log.h"

namespace Ptrace {

struct RemoteMemError : public FormattedError {
  template <typename... Args>
  RemoteMemError(std::string format, Args... args) : FormattedError(format, args...) {}
  RemoteMemError(std::string format) : FormattedError(format) {}
};

struct PtraceError : public FormattedError {
  template <typename... Args>
  PtraceError(std::string format, Args... args) : FormattedError(format, args...) {}
};

struct ForkExecError : public FormattedError {
  template <typename... Args>
  ForkExecError(std::string format, Args... args) : FormattedError(format, args...) {}
};

struct ChildExitedError : public FormattedError {
  template <typename... Args>
  ChildExitedError(std::string format, Args... args) : FormattedError(format, args...) {}
};

} // namespace Ptrace

#endif