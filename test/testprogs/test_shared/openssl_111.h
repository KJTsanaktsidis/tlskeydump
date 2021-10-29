// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __test_shared_openssl_111
#define __test_shared_openssl_111

#include <cstdint>
#include <memory>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <string>
#include <vector>

class OpenSSL111Tester {
public:
  OpenSSL111Tester();
  ~OpenSSL111Tester();
  OpenSSL111Tester(const OpenSSL111Tester &other) = delete;
  OpenSSL111Tester(OpenSSL111Tester &&other) = delete;
  OpenSSL111Tester &operator=(const OpenSSL111Tester &other) = delete;
  OpenSSL111Tester &operator=(OpenSSL111Tester &&other) = delete;

  void set_tls_version(int v);
  void connect_to(const std::string &server_addr);
  void send_string(const std::string &str);
  std::vector<uint8_t> receive_bytes_until_close();
  const std::vector<std::string> captured_keylog_lines();

private:
  int _tls_version = TLS1_2_VERSION;
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> _ssl_ctx =
      std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(nullptr, SSL_CTX_free);
  std::unique_ptr<BIO, decltype(&BIO_free_all)> _bio =
      std::unique_ptr<BIO, decltype(&BIO_free_all)>(nullptr, BIO_free_all);
  std::vector<std::string> _captured_keylog_lines;

  void keylog_callback(const SSL *ssl, const char *line);
  friend void _keylog_callback_thunk(const SSL *ssl, const char *line);
};

#endif
