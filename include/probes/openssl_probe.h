// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __openssl_probe_h
#define __openssl_probe_h

#include "config.h"

#include <cstddef>
#include <vector>

#include "dwarf_util/dwarf_helpers.h"
#include "log.h"
#include "lru_set.h"
#include "ptrace/ptrace_breakpoint_handler.h"
#include "tls_key_collector.h"

namespace Probes {

class OpenSSLProbe : public Ptrace::BreakpointHandler {
public:
  OpenSSLProbe(TLSKeyCollector *tlskc);
  virtual ~OpenSSLProbe();

  virtual std::vector<Ptrace::FunctionName> trap_functions();
  virtual void on_attach(Ptrace::PtraceProcess *proc, Ptrace::FunctionInfo function_info);
  virtual void on_trap(Ptrace::PtraceProcess *proc, Ptrace::FunctionInfo function_info,
                       Ptrace::FunctionArguments *args);

private:
  Logger _logger;
  TLSKeyCollector *_tlskc;
  LRUSet<std::vector<uint8_t>> _seen_client_randoms;

  // Offsets computed from dwarf data
  bool _computed_offsets = false;
  bool _computed_offsets_failed = false;

  // Members for TLS up to v1.2
  DwarfUtil::MemberLocation _loc_ssl_version;               // ssl->version
  DwarfUtil::MemberLocation _loc_ssl_s3;                    // ssl->s3
  DwarfUtil::MemberLocation _loc_s3_client_random;          // ssl->s3->client_random
  DwarfUtil::MemberLocation _loc_ssl_session;               // ssl->session
  DwarfUtil::MemberLocation _loc_session_master_key;        // ssl->session->master_key
  DwarfUtil::MemberLocation _loc_session_master_key_length; // ssl->sesson->master_key_length

  // Members for TLS v1.3 (older versions of OpenSSL won't actually have these)
  bool has_tls13_members = false;
  DwarfUtil::MemberLocation _loc_ssl_early_secret;           // ssl->early_secret
  DwarfUtil::MemberLocation _loc_ssl_handshake_secret;       // ssl->handshake_secret
  DwarfUtil::MemberLocation _loc_ssl_handshake_traffic_hash; // ssl->handshake_traffic_hash
  DwarfUtil::MemberLocation _loc_ssl_master_secret;          // ssl->master_secret
  DwarfUtil::MemberLocation _loc_ssl_server_finished_hash;   // ssl->server_finished_hash
  DwarfUtil::MemberLocation _loc_ssl_exporter_master_secret; // ssl->exporter_master_secret
  DwarfUtil::MemberLocation _loc_session_cipher;             // ssl->session->cipher
  DwarfUtil::MemberLocation _loc_cipher_id;                  // ssl->session->cipher->id
};

} // namespace Probes

#endif
