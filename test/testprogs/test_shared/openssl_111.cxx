#include <boost/format.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <unordered_map>

#include "test_shared/openssl_111.h"

static std::unordered_map<const SSL *, OpenSSL111Tester*> __global_tester_retriever;

void _keylog_callback_thunk(const SSL *ssl, const char *line) {
  __global_tester_retriever[ssl]->keylog_callback(ssl, line);
}

OpenSSL111Tester::OpenSSL111Tester() {

}

OpenSSL111Tester::~OpenSSL111Tester() {
  for (auto it = __global_tester_retriever.begin(); it != __global_tester_retriever.end();) {
    if ((*it).second == this) {
      __global_tester_retriever.erase(it++);
    } else {
      ++it;
    }
  }
}

void OpenSSL111Tester::set_tls_version(int v) {
  _tls_version = v;
}


const std::vector<std::string> OpenSSL111Tester::captured_keylog_lines() {
  return _captured_keylog_lines;
}

void OpenSSL111Tester::connect_to(const std::string &server_addr) {
  const SSL_METHOD *tls_method = TLS_client_method();
  if (!tls_method) {
    throw std::runtime_error("TLS_client_method failed");
  }

  SSL_CTX *ctx_ptr = SSL_CTX_new(tls_method);
  if (!ctx_ptr) {
    throw std::runtime_error("SSL_CTX_new failed");
  }
  _ssl_ctx.reset(ctx_ptr);

  SSL_CTX_set_keylog_callback(ctx_ptr, _keylog_callback_thunk);
  SSL_CTX_set_min_proto_version(_ssl_ctx.get(), _tls_version);
  SSL_CTX_set_max_proto_version(_ssl_ctx.get(), _tls_version);

  BIO *bio_ptr = BIO_new_ssl_connect(_ssl_ctx.get());
  if (!bio_ptr) {
    throw std::runtime_error("BIO_new_ssl_connect failed");
  }
  _bio.reset(bio_ptr);

  SSL *ssl;
  BIO_get_ssl(_bio.get(), &ssl);
  __global_tester_retriever[ssl] = this;

  BIO_set_conn_hostname(_bio.get(), server_addr.c_str());
  int res = BIO_do_connect(_bio.get());
  if (res <= 0) {
    throw std::runtime_error((boost::format("BIO_do_connect to %s failed: %d") % server_addr % res).str());
  }
}

void OpenSSL111Tester::keylog_callback(const SSL *ssl, const char *line) {
  _captured_keylog_lines.push_back(line);
}

void OpenSSL111Tester::send_string(const std::string &str) {
  int res = BIO_puts(_bio.get(), str.c_str());
  if (res <= 0) {
    throw std::runtime_error((boost::format("BIO_puts failed: %d") % res).str());
  }
}

std::vector<uint8_t> OpenSSL111Tester::receive_bytes_until_close() {
  std::vector<uint8_t> rbuf;
  size_t read_so_far = 0;
  while (true) {
    rbuf.resize(rbuf.size() + 512);
    int n = BIO_read(_bio.get(), rbuf.data() + read_so_far, 512);
    if (n == 0) {
      break;
    }
    if (n < 0) {
      throw std::runtime_error((boost::format("BIO_read failed: %d") % n).str());
    }
    read_so_far += n;
    rbuf.resize(read_so_far);
  }
  return rbuf;
}