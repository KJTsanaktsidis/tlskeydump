// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __test_shared_util_h
#define __test_shared_util_h

#include <cstdlib>
#include <string>

static inline std::string must_get_env(const std::string &envname) {
  const char *testcase = std::getenv(envname.c_str());
  BOOST_ASSERT(testcase);
  return std::string(testcase);
}

#endif
