// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <algorithm>
#include <boost/program_options.hpp>
#include <boost/tokenizer.hpp>
#include <cstddef>
#include <iostream>
#include <iterator>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <vector>

#include "cli_args.h"
#include "debuginfo_search/debuginfo_search.h"
#include "parse_util.h"

const char *usage_string = "Usage: tlskeydump -p|--pid <pid> [options...]\n"
                           "       tlskeydump [options...] [--] /bin/program argv1 argv2 ...";

template <typename T, T (*TParser)(std::string), std::string (*TDelim)()>
struct DelimSeparatedOpts {
  std::vector<T> values;
  void add_tokens(const std::string &str) {
    boost::char_separator<char> sep(TDelim().c_str());
    std::vector<std::string> str_values;
    boost::tokenizer<boost::char_separator<char>> tok(str, sep);
    std::copy(tok.begin(), tok.end(), std::back_inserter(str_values));
    for (auto &s : str_values) {
      values.push_back(TParser(s));
    }
  }
  friend std::istream &operator>>(std::istream &in, DelimSeparatedOpts<T, TParser, TDelim> &ol) {
    std::string token;
    in >> token;
    ol.add_tokens(token);
    return in;
  }
  static std::vector<T> squash_values(std::vector<DelimSeparatedOpts<T, TParser, TDelim>> list) {
    std::vector<T> res;
    for (auto &v : list) {
      std::copy(v.values.begin(), v.values.end(), std::back_inserter(res));
    }
    return res;
  }
};

static pid_t parse_pid_option(std::string t) {
  try {
    size_t pos;
    pid_t ret = std::stol(t, &pos);
    if (t.begin() + pos != t.end()) {
      throw boost::program_options::invalid_option_value(t);
    }
    return ret;
  } catch (std::invalid_argument &e) {
    throw boost::program_options::invalid_option_value(t);
  }
}

static std::string parse_ident_option(std::string t) { return t; }

static std::string comma_delim() { return ","; }
static std::string colon_delim() { return ":"; }

typedef DelimSeparatedOpts<pid_t, parse_pid_option, comma_delim> PidTCommaSeparatedOpts;
typedef DelimSeparatedOpts<std::string, parse_ident_option, colon_delim> StringColonSeparatedOpts;

CLIArgs::CLIArgs(int argc, char **argv) : _parser(argc, argv), _visible_opts(usage_string) {

  _visible_opts.add_options()("help,h", "Print help message");
  _visible_opts.add_options()("pid,p",
                              boost::program_options::value<std::vector<PidTCommaSeparatedOpts>>(),
                              "PID of the process to trace");
  _visible_opts.add_options()("verbose,v", "Print verbose output");
  _visible_opts.add_options()("graceful-shutdown-signal,s",
                              boost::program_options::value<std::string>(),
                              "Name or number of a signal to send to an owned child process");
  _visible_opts.add_options()("graceful-shutdown-timeout,t",
                              boost::program_options::value<std::string>(),
                              "How long to wait for graceful shutdown of children");
  _visible_opts.add_options()("enable-debuginfod,d", "Enable debuginfod symbol resolution");
  _visible_opts.add_options()("out,o", boost::program_options::value<std::string>(),
                              "File to send keylog output to");
  _visible_opts.add_options()(
      "debug-dir", boost::program_options::value<std::vector<StringColonSeparatedOpts>>(),
      "Colon-separated list of directories to search for debuginfo in (default: "
      "/usr/lib/debug).");

  _positional_only_opts.add_options()("prog-binary", boost::program_options::value<std::string>());
  _positional_only_opts.add_options()("prog-argv",
                                      boost::program_options::value<std::vector<std::string>>());

  _positional_spec.add("prog-binary", 1);
  _positional_spec.add("prog-argv", -1);

  _all_opts.add(_visible_opts).add(_positional_only_opts);

  _parser.options(_all_opts);
  _parser.positional(_positional_spec);
}

std::optional<int> CLIArgs::parse() {
  try {
    boost::program_options::store(_parser.run(), _parsed_vars);

    if (_parsed_vars.contains("help")) {
      std::cerr << _visible_opts;
      return 0;
    }

    // Validate the arguments.
    if (pids().empty() && !program_binary().has_value()) {
      std::cerr << "tlskeydump: either --pid or a program to start must be provided.\n";
      return 1;
    }
    if (!pids().empty() && program_binary().has_value()) {
      std::cerr << "tlskeydump: a program to start cannot be provided if --pid is also passed.\n";
      return 1;
    }

    if (_parsed_vars["graceful-shutdown-signal"].empty()) {
      _graceful_shutdown_signal = SIGINT;
    } else {
      std::string signame = _parsed_vars["graceful-shutdown-signal"].as<std::string>();
      _graceful_shutdown_signal = signame_to_num(signame);
    }

    if (_parsed_vars["graceful-shutdown-timeout"].empty()) {
      _graceful_shutdown_timeout = std::chrono::milliseconds(5000);
    } else {
      std::string duration_str = _parsed_vars["graceful-shutdown-timeout"].as<std::string>();
      _graceful_shutdown_timeout = parse_duration(duration_str);
    }

    if (_parsed_vars.contains("enable-debuginfod")) {
      _debuginfod_enabled = true;
    } else {
      _debuginfod_enabled = false;
    }

    if (_parsed_vars["out"].empty()) {
      _out_file = std::nullopt;
    } else {
      _out_file = _parsed_vars["out"].as<std::string>();
    }

    if (_parsed_vars["debug-dir"].empty()) {
      _debug_dirs = DebuginfoSearch::default_global_debug_directories();
    } else {
      _debug_dirs = StringColonSeparatedOpts::squash_values(
          _parsed_vars["debug-dir"].as<std::vector<StringColonSeparatedOpts>>());
    }

    return std::nullopt;

  } catch (boost::program_options::unknown_option &e) {
    std::cerr << "tlskeydump: " << e.what() << "\n";
    std::cerr << "Try 'tlskeydump --help' for more information.\n";
    return 1;
  } catch (boost::program_options::invalid_option_value &e) {
    std::cerr << "tlskeydump: " << e.what() << "\n";
    std::cerr << "Try 'tlskeydump --help' for more information.\n";
    return 1;
  } catch (std::invalid_argument &e) {
    std::cerr << "tlskeydump: " << e.what() << "\n";
    std::cerr << "Try 'tlskeydump --help' for more information.\n";
    return 1;
  }
}

bool CLIArgs::verbose() { return _parsed_vars.contains("verbose"); }

std::vector<pid_t> CLIArgs::pids() {
  if (_parsed_vars["pid"].empty()) {
    return std::vector<pid_t>();
  } else {
    return PidTCommaSeparatedOpts::squash_values(
        _parsed_vars["pid"].as<std::vector<PidTCommaSeparatedOpts>>());
  }
}

std::optional<std::string> CLIArgs::program_binary() {
  if (_parsed_vars["prog-binary"].empty()) {
    return std::nullopt;
  } else {
    return _parsed_vars["prog-binary"].as<std::string>();
  }
}

std::vector<std::string> CLIArgs::program_argv() {
  if (_parsed_vars["prog-argv"].empty()) {
    return std::vector<std::string>();
  } else {
    return _parsed_vars["prog-argv"].as<std::vector<std::string>>();
  }
}

int CLIArgs::graceful_shutdown_signal() { return _graceful_shutdown_signal; }

std::chrono::milliseconds CLIArgs::graceful_shutdown_timeout() {
  return _graceful_shutdown_timeout;
}

bool CLIArgs::debuginfod_enabled() { return _debuginfod_enabled; }

std::optional<std::string> CLIArgs::out_file() { return _out_file; }

std::vector<std::string> CLIArgs::debug_dirs() { return _debug_dirs; }
