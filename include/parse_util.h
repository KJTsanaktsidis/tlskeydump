#ifndef __time_util_h
#define __time_util_h

#include "config.h"

#include <chrono>
#include <string>

std::chrono::milliseconds parse_duration(const std::string &s);
int signame_to_num(const std::string &s);

#endif
