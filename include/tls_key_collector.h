// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __tls_key_collector_h
#define __tls_key_collector_h

#include "config.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>

enum class TLSKeyLabel {
  RSA,
  CLIENT_RANDOM,
  CLIENT_EARLY_TRAFFIC_SECRET,
  CLIENT_HANDSHAKE_TRAFFIC_SECRET,
  SERVER_HANDSHAKE_TRAFFIC_SECRET,
  CLIENT_TRAFFIC_SECRET_0,
  SERVER_TRAFFIC_SECRET_0,
  EARLY_EXPORTER_SECRET,
  EXPORTER_SECRET,
};

class TLSKeyCollector {
public:
  TLSKeyCollector();
  TLSKeyCollector(const std::string &filename);

  void record_key(TLSKeyLabel label, const std::vector<unsigned char> &client_random,
                  const std::vector<unsigned char> &secret);

private:
  std::mutex _lock;
  std::unique_ptr<std::ofstream> _file_own;
  std::ostream &_file_out;
};

#endif
