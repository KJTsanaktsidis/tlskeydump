#ifndef __cli_args_h
#define __cli_args_h

#include "config.h"

#include <boost/program_options.hpp>
#include <chrono>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

class CLIArgs {
public:
  CLIArgs(int argc, char **argv);
  std::optional<int> parse();

  bool verbose();
  std::vector<pid_t> pids();
  std::optional<std::string> program_binary();
  std::vector<std::string> program_argv();
  int graceful_shutdown_signal();
  std::chrono::milliseconds graceful_shutdown_timeout();
  bool debuginfod_enabled();
  std::optional<std::string> out_file();
  std::vector<std::string> debug_dirs();

private:
  boost::program_options::variables_map _parsed_vars;
  boost::program_options::command_line_parser _parser;
  boost::program_options::options_description _visible_opts;
  boost::program_options::options_description _all_opts;
  boost::program_options::options_description _positional_only_opts;
  boost::program_options::positional_options_description _positional_spec;

  // parsed arguments
  int _graceful_shutdown_signal;
  std::chrono::milliseconds _graceful_shutdown_timeout;
  bool _debuginfod_enabled;
  std::optional<std::string> _out_file;
  std::vector<std::string> _debug_dirs;
};

#endif
