// SPDX-License-Identifier: GPL-2.0-or-later

#include <boost/assert.hpp>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include "test_shared/openssl_111.h"
#include "test_shared/util.h"

int main(int argc, char **argv) {
  BOOST_ASSERT(argc >= 2);
  std::string out_file_name(argv[1]);

  OpenSSL111Tester ts;
  ts.set_tls_version(TLS1_3_VERSION);
  ts.connect_to("google.com:443");
  ts.send_string("HELLO THAR\n");
  ts.receive_bytes_until_close();

  std::fstream out_file(out_file_name, std::ios_base::out | std::ios_base::trunc);
  for (auto line : ts.captured_keylog_lines()) {
    out_file << line << "\n";
  }
}
