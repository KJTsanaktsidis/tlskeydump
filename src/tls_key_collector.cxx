#include "config.h"

#include <boost/algorithm/hex.hpp>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>

#include "tls_key_collector.h"

TLSKeyCollector::TLSKeyCollector() : _file_out(std::cout) {}
TLSKeyCollector::TLSKeyCollector(const std::string &filename)
    : _file_own(new std::ofstream(filename, std::ios_base::out | std::ios_base::app)),
      _file_out(*_file_own.get()) {}

std::string key_label_string(TLSKeyLabel l) {
  switch (l) {
  case TLSKeyLabel::RSA:
    return "RSA";
  case TLSKeyLabel::CLIENT_RANDOM:
    return "CLIENT_RANDOM";
  case TLSKeyLabel::CLIENT_EARLY_TRAFFIC_SECRET:
    return "CLIENT_EARLY_TRAFFIC_SECRET";
  case TLSKeyLabel::CLIENT_HANDSHAKE_TRAFFIC_SECRET:
    return "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
  case TLSKeyLabel::SERVER_HANDSHAKE_TRAFFIC_SECRET:
    return "SERVER_HANDSHAKE_TRAFFIC_SECRET";
  case TLSKeyLabel::CLIENT_TRAFFIC_SECRET_0:
    return "CLIENT_TRAFFIC_SECRET_0";
  case TLSKeyLabel::SERVER_TRAFFIC_SECRET_0:
    return "SERVER_TRAFFIC_SECRET_0";
  case TLSKeyLabel::EARLY_EXPORTER_SECRET:
    return "EARLY_EXPORTER_SECRET";
  case TLSKeyLabel::EXPORTER_SECRET:
    return "EXPORTER_SECRET";
  default:
    throw std::logic_error("unknown TLSKeyLabel");
  }
}

void TLSKeyCollector::record_key(TLSKeyLabel label, const std::vector<unsigned char> &client_random,
                                 const std::vector<unsigned char> &secret) {
  // very dumb implementation.
  std::string client_random_hex;
  boost::algorithm::hex_lower(client_random.begin(), client_random.end(),
                              std::back_inserter(client_random_hex));
  std::string secret_hex;
  boost::algorithm::hex_lower(secret.begin(), secret.end(), std::back_inserter(secret_hex));

  std::unique_lock<std::mutex> locker(_lock);
  _file_out << key_label_string(label) << " " << client_random_hex << " " << secret_hex << "\n";
}
