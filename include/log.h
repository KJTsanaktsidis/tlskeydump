// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __log_h
#define __log_h

#include "config.h"

#include <boost/format.hpp>
#include <boost/log/common.hpp>
#include <boost/log/expressions/keyword.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <iostream>
#include <stdexcept>
#include <string>

enum class Sev { PANIC, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG };
BOOST_LOG_ATTRIBUTE_KEYWORD(Severity, "Severity", Sev)
std::ostream &operator<<(std::ostream &out, Sev &sev);

extern const char *COMPONENT_ATTRIBUTE;
BOOST_LOG_ATTRIBUTE_KEYWORD(Component, COMPONENT_ATTRIBUTE, std::string)

typedef boost::log::sources::severity_logger_mt<Sev> Logger;
void configure_logging(bool verbose);
void configure_logger_component(Logger &logger, const std::string &component);
Logger new_logger(const std::string &component);

class FormattedError : public std::runtime_error {
public:
  template <typename... Args>
  FormattedError(std::string format, Args... args)
      : std::runtime_error(_format_apply(boost::format(format), args...)) {}

  FormattedError(std::string format) : std::runtime_error(format) {}

private:
  template <typename T, typename... Args>
  static std::string _format_apply(boost::format f, T first, Args... rest) {
    return _format_apply((f % first), rest...);
  }

  template <typename T> static std::string _format_apply(boost::format f, T first) {
    return (f % first).str();
  }
};

#endif
