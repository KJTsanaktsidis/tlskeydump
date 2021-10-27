#ifndef __test_shared_util_h
#define __test_shared_util_h

#include <string>
#include <cstdlib>

static inline std::string must_get_env(const std::string &envname) {
  const char *testcase = std::getenv(envname.c_str());
  BOOST_ASSERT(testcase);
  return std::string(testcase);
}

#endif
