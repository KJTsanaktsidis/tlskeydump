// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#if !HAVE_SIGABBREV_NP
extern "C" {
const char *sigabbrev_np(int sig);
}
#endif
