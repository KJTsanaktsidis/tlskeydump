#include "config.h"

#include <boost/date_time.hpp>
#include <boost/log/detail/default_attribute_names.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <iostream>

#include "log.h"

const char *COMPONENT_ATTRIBUTE = "Component";

void configure_logging(bool verbose) {
  boost::log::add_common_attributes();

  auto core = boost::log::core::get();
  auto stdout_sink = boost::make_shared<
      boost::log::sinks::synchronous_sink<boost::log::sinks::text_ostream_backend>>();
  // Log to stdout (in a shared pointer with no deleter)
  stdout_sink->locked_backend()->add_stream(
      boost::shared_ptr<std::ostream>(&std::cerr, [](std::ostream *e) {}));
  stdout_sink->locked_backend()->auto_flush(true);
  stdout_sink->set_formatter(
      boost::log::expressions::format("[%1%] %2%: (%3%) %4%") %
      boost::log::expressions::format_date_time<boost::posix_time::ptime>(
          boost::log::aux::default_attribute_names::timestamp(), "%Y-%m-%d %H:%M:%S.%f") %
      boost::log::expressions::attr<Sev>(boost::log::aux::default_attribute_names::severity()) %
      boost::log::expressions::attr<std::string>(COMPONENT_ATTRIBUTE) %
      boost::log::expressions::smessage);
  if (!verbose) {
    stdout_sink->set_filter(Severity <= Sev::WARNING);
  }
  core->add_sink(stdout_sink);
}

std::ostream &operator<<(std::ostream &out, Sev &sev) {
  switch (sev) {
  case Sev::PANIC:
    out << "PANIC";
    break;
  case Sev::ALERT:
    out << "ALERT";
    break;
  case Sev::CRITICAL:
    out << "CRITICAL";
    break;
  case Sev::ERROR:
    out << "ERROR";
    break;
  case Sev::WARNING:
    out << "WARNING";
    break;
  case Sev::NOTICE:
    out << "NOTICE";
    break;
  case Sev::INFO:
    out << "INFO";
    break;
  case Sev::DEBUG:
    out << "DEBUG";
    break;
  }
  return out;
}

void configure_logger_component(Logger &logger, const std::string &component) {
  logger.add_attribute(COMPONENT_ATTRIBUTE,
                       boost::log::attributes::constant<std::string>(component));
}

Logger new_logger(const std::string &component) {
  Logger lg;
  lg.add_attribute(COMPONENT_ATTRIBUTE, boost::log::attributes::constant<std::string>(component));
  return lg;
}
