// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <algorithm>
#include <boost/endian/arithmetic.hpp>
#include <boost/log/common.hpp>
#include <cstdint>
#include <cstring>
#include <elfutils/libdw.h>
#include <iterator>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <optional>
#include <string>

#include "dwarf_util/dwarf_die_cache.h"
#include "dwarf_util/dwarf_helpers.h"
#include "probes/openssl_probe.h"
#include "ptrace/dwfl_handle.h"
#include "ptrace/ptrace_mem.h"
#include "ptrace/ptrace_process.h"
#include "tls_key_collector.h"

namespace Probes {

static const EVP_MD *hash_for_cipher_id(uint32_t cipher_id) {
  // The two-byte values here are taken from the table ssl_ciphers_tbl in
  // OpenSSL's t1_trce.c
  switch (cipher_id & 0x0000FFFF) {
  case 0x1301:
  case 0x1303:
  case 0x1304:
  case 0x1305:
    return EVP_sha256();
  case 0x1302:
    return EVP_sha384();
    break;
  default:
    BOOST_ASSERT_MSG(false, "non-tls 1.3 ciphersuite in tls13_hkdf_expand");
  }
}

// This is an implementation of tls13_hkdf_expand from OpenSSL, in terms of only public API's.
// This is used to derive the server/client handshake secret from the handshake secret + the
// server/client handshake hash.
std::vector<uint8_t> tls13_hkdf_expand(uint32_t cipher_id, const std::vector<uint8_t> &secret,
                                       const std::string &label, const std::vector<uint8_t> &data) {
  std::string label_with_prefix = "tls13 " + label;
  BOOST_ASSERT(label_with_prefix.size() <= UINT8_MAX);
  BOOST_ASSERT(data.size() <= UINT8_MAX);

  const EVP_MD *md = hash_for_cipher_id(cipher_id);
  size_t hashlen = EVP_MD_size(md);
  BOOST_ASSERT(hashlen < UINT16_MAX);

  // The OpenSSL implementation allows passing in variable length data, but for our purposes here
  // it's sufficient to just assume that the data length is equal to the hashlen (since that's all
  // that OpenSSL will pass into the KDF anyway, hashes). This nicely also trims our very-large
  // buffer from the struct into the actual size for this cipher, trimming all the zeros off the
  // end.
  std::vector<uint8_t> sized_secret(hashlen, 0);
  std::copy_n(secret.begin(), std::min(secret.size(), hashlen), sized_secret.begin());
  std::vector<uint8_t> sized_data(hashlen, 0);
  std::copy_n(data.begin(), std::min(data.size(), hashlen), sized_data.begin());

  std::vector<uint8_t> hkdf_label;
  // First two bytes are the length of the derived secret
  // This is in BIG ENDIAN order.
  boost::endian::big_uint16_t hashlen_be = static_cast<uint16_t>(hashlen);
  std::copy_n(hashlen_be.data(), sizeof(uint16_t), std::back_inserter(hkdf_label));
  // One byte for the length of the full label w/prefix  (no null terminators)
  hkdf_label.push_back(static_cast<uint8_t>(label_with_prefix.size()));
  // The label itself
  std::copy(label_with_prefix.c_str(), label_with_prefix.c_str() + label_with_prefix.size(),
            std::back_inserter(hkdf_label));
  // One byte for the length of the data
  hkdf_label.push_back(static_cast<uint8_t>(sized_data.size()));
  // the data itself
  std::copy(sized_data.begin(), sized_data.end(), std::back_inserter(hkdf_label));

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx_deleter(pctx, EVP_PKEY_CTX_free);

  std::vector<uint8_t> result(hashlen);
  int ret = EVP_PKEY_derive_init(pctx) <= 0 ||
            EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx, sized_secret.data(), sized_secret.size()) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label.data(), hkdf_label.size()) <= 0 ||
            EVP_PKEY_derive(pctx, result.data(), &hashlen) <= 0;

  if (ret != 0) {
    throw std::runtime_error("got an error from OpenSSL HKDF derivation");
  }
  return result;
}

OpenSSLProbe::OpenSSLProbe(TLSKeyCollector *tlskc) : _tlskc(tlskc), _seen_client_randoms(500) {
  configure_logger_component(_logger, "OpenSSLProbe");
}

OpenSSLProbe::~OpenSSLProbe() {}

std::vector<Ptrace::FunctionName> OpenSSLProbe::trap_functions() {
  // What functions are we trapping here?
  std::vector<Ptrace::FunctionName> r;
  r.push_back({.name = "SSL_read", .soname = "libssl.so.1.1"});
  r.push_back({.name = "SSL_read_ex", .soname = "libssl.so.1.1"});
  r.push_back({.name = "ssl_read_internal", .soname = "libssl.so.1.1"});
  r.push_back({.name = "SSL_write", .soname = "libssl.so.1.1"});
  r.push_back({.name = "SSL_write_ex", .soname = "libssl.so.1.1"});
  r.push_back({.name = "ssl_write_internal", .soname = "libssl.so.1.1"});
  return r;
}

void OpenSSLProbe::on_attach(Ptrace::PtraceProcess *proc, Ptrace::FunctionInfo function_info) {
  // Compute the struct offsets we need.
  if (_computed_offsets || _computed_offsets_failed) {
    return;
  }

  try {
    // Get the core ssl_st struct (which is typedef'd to SSL)
    auto ssl_st = proc->dwfl()->get_type("ssl_st", "libssl.so.1.1").value();

    auto ssl_version = DwarfUtil::die_member(&ssl_st.die, "version").value();
    _loc_ssl_version = DwarfUtil::die_member_location(&ssl_version).value();

    auto ssl_s3 = DwarfUtil::die_member(&ssl_st.die, "s3").value();
    _loc_ssl_s3 = DwarfUtil::die_member_location(&ssl_s3).value();
    auto typeof_s3_ptr = DwarfUtil::die_type(&ssl_s3).value();
    auto typeof_s3_struct = DwarfUtil::die_dereference_type(&typeof_s3_ptr).value();
    auto s3_client_random = DwarfUtil::die_member(&typeof_s3_struct, "client_random").value();
    _loc_s3_client_random = DwarfUtil::die_member_location(&s3_client_random).value();

    auto ssl_session = DwarfUtil::die_member(&ssl_st.die, "session").value();
    _loc_ssl_session = DwarfUtil::die_member_location(&ssl_session).value();
    auto typeof_session_ptr = DwarfUtil::die_type(&ssl_session).value();
    auto typeof_session_struct = DwarfUtil::die_dereference_type(&typeof_session_ptr).value();
    auto session_master_key = DwarfUtil::die_member(&typeof_session_struct, "master_key").value();
    _loc_session_master_key = DwarfUtil::die_member_location(&session_master_key).value();
    auto session_master_key_length =
        DwarfUtil::die_member(&typeof_session_struct, "master_key_length").value();
    _loc_session_master_key_length =
        DwarfUtil::die_member_location(&session_master_key_length).value();

    // These offsets are for TLS 1.3, only in OpenSSL 1.1.1+
    try {
      auto session_cipher = DwarfUtil::die_member(&typeof_session_struct, "cipher").value();
      _loc_session_cipher = DwarfUtil::die_member_location(&session_cipher).value();
      auto typeof_session_cipher_ptr = DwarfUtil::die_type(&session_cipher).value();
      auto typeof_session_cipher_struct =
          DwarfUtil::die_dereference_type(&typeof_session_cipher_ptr).value();
      auto cipher_id = DwarfUtil::die_member(&typeof_session_cipher_struct, "id").value();
      _loc_cipher_id = DwarfUtil::die_member_location(&cipher_id).value();

      auto ssl_early_secret = DwarfUtil::die_member(&ssl_st.die, "early_secret").value();
      _loc_ssl_early_secret = DwarfUtil::die_member_location(&ssl_early_secret).value();
      auto ssl_handshake_secret = DwarfUtil::die_member(&ssl_st.die, "handshake_secret").value();
      _loc_ssl_handshake_secret = DwarfUtil::die_member_location(&ssl_handshake_secret).value();
      auto ssl_handshake_traffic_hash =
          DwarfUtil::die_member(&ssl_st.die, "handshake_traffic_hash").value();
      _loc_ssl_handshake_traffic_hash =
          DwarfUtil::die_member_location(&ssl_handshake_traffic_hash).value();
      auto ssl_master_secret = DwarfUtil::die_member(&ssl_st.die, "master_secret").value();
      _loc_ssl_master_secret = DwarfUtil::die_member_location(&ssl_master_secret).value();
      auto ssl_server_finished_hash =
          DwarfUtil::die_member(&ssl_st.die, "server_finished_hash").value();
      _loc_ssl_server_finished_hash =
          DwarfUtil::die_member_location(&ssl_server_finished_hash).value();
      auto ssl_exporter_master_secret =
          DwarfUtil::die_member(&ssl_st.die, "exporter_master_secret").value();
      _loc_ssl_exporter_master_secret =
          DwarfUtil::die_member_location(&ssl_exporter_master_secret).value();
      has_tls13_members = true;
    } catch (std::bad_optional_access &e) {
      BOOST_LOG_SEV(_logger, Sev::DEBUG) << "could not find TLS1.3 secret offsets in OpenSSL "
                                            "struct; assuming OpenSSL version < 1.1.1";
    }

    _computed_offsets = true;

  } catch (std::bad_optional_access &e) {
    // means that we didn't find what we were expecting.
    _computed_offsets_failed = true;
    BOOST_LOG_SEV(_logger, Sev::WARNING)
        << "structure of debuginfo on libssl.so.1.1 was not as expected: " << e.what();
  } catch (DwarfUtil::DwarfLogicalError &e) {
    // means that we didn't find what we were expecting.
    _computed_offsets_failed = true;
    BOOST_LOG_SEV(_logger, Sev::WARNING)
        << "structure of debuginfo on libssl.so.1.1 was not as expected: " << e.what();
  }
}

void OpenSSLProbe::on_trap(Ptrace::PtraceProcess *proc, Ptrace::FunctionInfo function_info,
                           Ptrace::FunctionArguments *args) {
  if (!_computed_offsets) {
    return;
  }

  try {
    // For all six functions, the first argument is SSL_CTX
    uintptr_t ssl_ptr = args->at<uintptr_t>(0);
    // Chase down ssl->s3
    uintptr_t ptr_to_s3 = ssl_ptr + _loc_ssl_s3.offset;
    uintptr_t s3 =
        Ptrace::read_process_mem_sz<uintptr_t>(proc->mem_fd(), ptr_to_s3, _loc_ssl_s3.size);
    // ssl->s3->client_random
    uintptr_t ptr_to_client_random = s3 + _loc_s3_client_random.offset;
    std::vector<uint8_t> client_random(_loc_s3_client_random.size);
    Ptrace::read_process_mem_bytes(proc->mem_fd(), ptr_to_client_random, client_random.data(),
                                   client_random.size());

    // If we've already processed this client_random, we can skip the rest of this
    if (_seen_client_randoms.contains_with_insert(client_random)) {
      return;
    }

    // ssl->session
    uintptr_t ptr_to_session = ssl_ptr + _loc_ssl_session.offset;
    uintptr_t session = Ptrace::read_process_mem_sz<uintptr_t>(proc->mem_fd(), ptr_to_session,
                                                               _loc_ssl_session.size);

    // ssl->version
    uintptr_t ptr_to_version = ssl_ptr + _loc_ssl_version.offset;
    int ssl_version =
        Ptrace::read_process_mem_sz<int>(proc->mem_fd(), ptr_to_version, _loc_ssl_version.size);

    if (ssl_version == TLS1_3_VERSION && has_tls13_members) {
      // ssl->session->cipher
      uintptr_t ptr_to_cipher = session + _loc_session_cipher.offset;
      uintptr_t cipher = Ptrace::read_process_mem_sz<uintptr_t>(proc->mem_fd(), ptr_to_cipher,
                                                                _loc_session_cipher.size);
      // ssl->session->cipher->id
      uintptr_t ptr_to_id = cipher + _loc_cipher_id.offset;
      uint32_t cipher_id =
          Ptrace::read_process_mem_sz<uint32_t>(proc->mem_fd(), ptr_to_id, _loc_cipher_id.size);
      // ssl->exporter_master_secret
      uintptr_t ptr_to_exporter_master_secret = ssl_ptr + _loc_ssl_exporter_master_secret.offset;
      std::vector<uint8_t> exporter_master_secret(_loc_ssl_exporter_master_secret.size);
      Ptrace::read_process_mem_bytes(proc->mem_fd(), ptr_to_exporter_master_secret,
                                     exporter_master_secret.data(), exporter_master_secret.size());
      // ssl->handshake_secret
      uintptr_t ptr_to_handshake_secret = ssl_ptr + _loc_ssl_handshake_secret.offset;
      std::vector<uint8_t> handshake_secret(_loc_ssl_handshake_secret.size);
      Ptrace::read_process_mem_bytes(proc->mem_fd(), ptr_to_handshake_secret,
                                     handshake_secret.data(), handshake_secret.size());
      // ssl->handshake_traffic_hash
      uintptr_t ptr_to_handshake_traffic_hash = ssl_ptr + _loc_ssl_handshake_traffic_hash.offset;
      std::vector<uint8_t> handshake_traffic_hash(_loc_ssl_handshake_traffic_hash.size);
      Ptrace::read_process_mem_bytes(proc->mem_fd(), ptr_to_handshake_traffic_hash,
                                     handshake_traffic_hash.data(), handshake_traffic_hash.size());
      // ssl->master_secret
      uintptr_t ptr_to_master_secret = ssl_ptr + _loc_ssl_master_secret.offset;
      std::vector<uint8_t> master_secret(_loc_ssl_master_secret.size);
      Ptrace::read_process_mem_bytes(proc->mem_fd(), ptr_to_master_secret, master_secret.data(),
                                     master_secret.size());
      // ssl->server_finished_hash
      uintptr_t ptr_to_server_finished_hash = ssl_ptr + _loc_ssl_server_finished_hash.offset;
      std::vector<uint8_t> server_finished_hash(_loc_ssl_server_finished_hash.size);
      Ptrace::read_process_mem_bytes(proc->mem_fd(), ptr_to_server_finished_hash,
                                     server_finished_hash.data(), server_finished_hash.size());

      auto client_handshake_secret =
          tls13_hkdf_expand(cipher_id, handshake_secret, "c hs traffic", handshake_traffic_hash);
      auto server_handshake_secret =
          tls13_hkdf_expand(cipher_id, handshake_secret, "s hs traffic", handshake_traffic_hash);
      auto client_traffic_secret_0 =
          tls13_hkdf_expand(cipher_id, master_secret, "c ap traffic", server_finished_hash);
      auto server_traffic_secret_0 =
          tls13_hkdf_expand(cipher_id, master_secret, "s ap traffic", server_finished_hash);

      // need to trim exporter_master_secret down to the actual size of the hash
      auto hash = hash_for_cipher_id(cipher_id);
      size_t hash_size = EVP_MD_size(hash);
      std::vector<uint8_t> exporter_master_secret_trimmed(
          std::min(exporter_master_secret.size(), hash_size));
      std::copy_n(exporter_master_secret.begin(), exporter_master_secret_trimmed.size(),
                  exporter_master_secret_trimmed.data());

      _tlskc->record_key(TLSKeyLabel::EXPORTER_SECRET, client_random,
                         exporter_master_secret_trimmed);
      _tlskc->record_key(TLSKeyLabel::CLIENT_HANDSHAKE_TRAFFIC_SECRET, client_random,
                         client_handshake_secret);
      _tlskc->record_key(TLSKeyLabel::SERVER_HANDSHAKE_TRAFFIC_SECRET, client_random,
                         server_handshake_secret);
      _tlskc->record_key(TLSKeyLabel::CLIENT_TRAFFIC_SECRET_0, client_random,
                         client_traffic_secret_0);
      _tlskc->record_key(TLSKeyLabel::SERVER_TRAFFIC_SECRET_0, client_random,
                         server_traffic_secret_0);
    } else {
      // Life is easy = just read the master key
      uintptr_t ptr_to_master_key_length = session + _loc_session_master_key_length.offset;
      size_t master_key_length = Ptrace::read_process_mem_sz<size_t>(
          proc->mem_fd(), ptr_to_master_key_length, _loc_session_master_key_length.size);
      std::vector<uint8_t> master_key(master_key_length);
      uintptr_t ptr_to_master_key = session + _loc_session_master_key.offset;
      Ptrace::read_process_mem_bytes(proc->mem_fd(), ptr_to_master_key, master_key.data(),
                                     master_key.size());

      _tlskc->record_key(TLSKeyLabel::CLIENT_RANDOM, client_random, master_key);
    }

  } catch (Ptrace::RemoteMemError &e) {
    // It's not really an error if the process we're tracing does something we're not expecting,
    // like calling SSL_* with a null context or something.
    BOOST_LOG_SEV(_logger, Sev::DEBUG)
        << "got remote mem error " << e.what() << " in trap for fn " << function_info.name.name;
  }
}

} // namespace Probes