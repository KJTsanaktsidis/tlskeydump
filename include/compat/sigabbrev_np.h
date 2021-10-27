#include "config.h"

#if !HAVE_SIGABBREV_NP
extern "C" {
const char *sigabbrev_np(int sig);
}
#endif
