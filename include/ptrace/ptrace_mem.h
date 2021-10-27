#ifndef __ptrace_mem_h
#define __ptrace_mem_h

#include "config.h"

#include <bitset>
#include <boost/endian.hpp>
#include <fcntl.h>
#include <unistd.h>

#include "ptrace_exceptions.h"

namespace Ptrace {

static inline void read_process_mem_bytes(int mem_fd, uintptr_t addr, uint8_t *to, size_t bytes) {
  if (lseek64(mem_fd, addr, SEEK_SET) == -1) {
    throw RemoteMemError("error while seeking mem_fd");
  }

  size_t bytes_read = 0;
  while (bytes_read < bytes) {
    int res = read(mem_fd, to + bytes_read, (bytes - bytes_read));
    if (res == -1) {
      char errbuf[512];
      char *err = strerror_r(errno, errbuf, sizeof(errbuf));
      throw RemoteMemError("failed to read from process at %x: %s", addr, err);
    }
    bytes_read += res;
  }
}

template <typename T> static inline T read_process_mem(int mem_fd, uintptr_t addr) {
  static_assert(std::is_standard_layout<T>());
  T ret;
  read_process_mem_bytes(mem_fd, addr, reinterpret_cast<uint8_t *>(&ret), sizeof(T));
  return ret;
}

// This is needed on the off chance we're doing something insane like tracing an x32/x86 ABI
// program with 32-bit pointers while running as a 64bit process. Reads an integer of size
// sz bytes into the int type passed in the template parameter. sz could be smaller than the
// actual size of the integer it's being stored in.
template <typename T> static inline T read_process_mem_sz(int mem_fd, uintptr_t addr, size_t sz) {
  static_assert(std::is_integral<T>());
  BOOST_ASSERT(sz <= sizeof(T));
  T ret = 0;
  if constexpr (boost::endian::order::native == boost::endian::order::big) {
    // not that I think this block is ever going to run, but may as well
    read_process_mem_bytes(mem_fd, addr, reinterpret_cast<uint8_t *>(&ret) + sizeof(T) - sz, sz);
  } else {
    read_process_mem_bytes(mem_fd, addr, reinterpret_cast<uint8_t *>(&ret), sz);
  }
  // sign extend
  if constexpr (std::is_signed<T>()) {
    if (sz < sizeof(T)) {
      if constexpr (boost::endian::order::native == boost::endian::order::big) {
        uint8_t msb = *(reinterpret_cast<uint8_t *>(&ret) + sizeof(T) - sz);
        if (msb & 0x80) {
          // sign bit set
          std::memset(reinterpret_cast<uint8_t *>(&ret), sizeof(T) - sz, 0xFF);
        }
      } else {
        uint8_t msb = *(reinterpret_cast<uint8_t *>(&ret) + sizeof(T) - 1);
        if (msb & 0x80) {
          // sign bit set
          std::memset(reinterpret_cast<uint8_t *>(&ret) + sizeof(T), sizeof(T) - sz, 0xFF);
        }
      }
    }
  }
  return ret;
}

static inline void write_process_mem_bytes(int mem_fd, uintptr_t addr, uint8_t *from,
                                           size_t bytes) {
  if (lseek64(mem_fd, addr, SEEK_SET) == -1) {
    throw RemoteMemError("error while seeking mem_fd");
  }

  size_t bytes_written = 0;
  while (bytes_written < bytes) {
    int res = write(mem_fd, from + bytes_written, (bytes - bytes_written));
    if (res == -1) {
      char errbuf[512];
      char *err = strerror_r(errno, errbuf, sizeof(errbuf));
      throw RemoteMemError("failed to write to process at %x: %s", addr, err);
    }
    bytes_written += res;
  }
}

template <typename T>
static inline void write_process_mem(int mem_fd, uintptr_t addr, const T &from) {
  static_assert(std::is_standard_layout<T>());
  return write_process_mem_bytes(mem_fd, addr, reinterpret_cast<uint8_t *>(&from), sizeof(T));
}

} // namespace Ptrace

#endif
