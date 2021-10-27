#include "config.h"

#include <boost/format.hpp>
#include <boost/program_options.hpp>
#include <elf.h>
#include <iostream>
#include <libelf.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "cli_args.h"
#include "debuginfo_search/debuginfo_search.h"
#include "log.h"
#include "probes/openssl_probe.h"
#include "ptrace/ptrace_process.h"
#include "ptrace/ptrace_process_monitor.h"
#include "tls_key_collector.h"

static void init_libelf() {
  int elfver = elf_version(EV_CURRENT);
  if (elfver == EV_NONE) {
    auto err = (boost::format("error initializing libelf: %s") % elf_errmsg(-1)).str();
    throw std::runtime_error(err);
  }
}

int main(int argc, char **argv) {
  try {
    CLIArgs cli(argc, argv);
    auto parse_ret = cli.parse();
    if (parse_ret.has_value()) {
      // means that the CLI class printed something and we just need to exit
      return parse_ret.value();
    }

    configure_logging(cli.verbose());
    Logger logger;
    configure_logger_component(logger, "main");
    init_libelf();

    DebuginfoSearch::Options debuginfo_base_opts;
    debuginfo_base_opts.pid = 0;
    debuginfo_base_opts.global_debug_directories = cli.debug_dirs();
    debuginfo_base_opts.enable_debuginfod = cli.debuginfod_enabled();

    std::unique_ptr<TLSKeyCollector> collector;
    if (cli.out_file().has_value()) {
      collector = std::make_unique<TLSKeyCollector>(cli.out_file().value());
    } else {
      collector = std::make_unique<TLSKeyCollector>();
    }

    // Important that the probes outlive the monitor so that we capture
    // _all_ traffic right up to the end.
    Probes::OpenSSLProbe openssl_probe(collector.get());
    std::vector<Ptrace::BreakpointHandler *> probe_breakpoints;
    probe_breakpoints.push_back(&openssl_probe);

    // ProbeOpenSSL11 openssl_1_1_probe(collector);

    Ptrace::ProcessMonitor mon(cli.graceful_shutdown_signal(), cli.graceful_shutdown_timeout());
    mon.configure_signals();

    Ptrace::PtraceProcess child_proc(cli.program_binary().value(), cli.program_argv(),
                                     probe_breakpoints, debuginfo_base_opts);

    std::vector<Ptrace::PtraceProcess *> procs;
    procs.push_back(&child_proc);
    mon.run_procs(procs);

  } catch (std::runtime_error &e) {
    std::cerr << "tlskeydump: fatal error: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
