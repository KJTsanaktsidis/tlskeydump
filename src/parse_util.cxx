// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <algorithm>
#include <boost/format.hpp>
#include <cmath>
#include <cstring>
#include <iterator>
#include <ostream>
#include <signal.h>
#include <stdexcept>
#include <string.h>

#include "compat/sigabbrev_np.h"
#include "parse_util.h"

std::chrono::milliseconds parse_duration(const std::string &s) {
  size_t end_pos;
  double num;
  try {
    num = std::stod(s, &end_pos);
  } catch (...) {
    throw std::invalid_argument((boost::format("could not parse duration %s") % s).str());
  }

  std::string suffix;
  std::copy(s.begin() + end_pos, s.end(), std::back_inserter(suffix));

  int mult_factor;
  if (suffix == "") {
    // default to seconds
    mult_factor = 1000;
  } else if (suffix == "ms") {
    mult_factor = 1;
  } else if (suffix == "s") {
    mult_factor = 1000;
  } else if (suffix == "m") {
    mult_factor = 1000 * 60;
  } else if (suffix == "h") {
    mult_factor = 1000 * 60 * 60;
  } else {
    throw std::invalid_argument((boost::format("could not parse duration %s") % s).str());
  }

  return std::chrono::milliseconds(std::llround(num * mult_factor));
}

int signame_to_num(const std::string &s) {
  try {
    size_t end_pos;
    int num = std::stoi(s, &end_pos);
    if (s.begin() + end_pos == s.end()) {
      if (num > 0 && num <= SIGRTMAX) {
        return num;
      }
    }
  } catch (...) {
  }

  for (int i = 1; i <= SIGRTMAX; i++) {
    const char *signame = sigabbrev_np(i);
    if (signame == nullptr) {
      continue;
    }

    std::string signame_str(signame);
    if (signame_str == s) {
      return i;
    }
    signame_str.insert(0, "SIG");
    if (signame_str == s) {
      return i;
    }
  }

  throw std::invalid_argument((boost::format("invalid signal %s") % s).str());
}
