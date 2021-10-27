#ifndef __common_h
#define __common_h

#include "config.h"

#include <elfutils/debuginfod.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <experimental/memory>
#include <iostream>
#include <libelf.h>
#include <memory>
#include <unistd.h>

struct ElfCloserFunc {
  void operator()(Elf *elf) {
    if (elf) {
      elf_end(elf);
    }
  }
};
typedef std::unique_ptr<Elf, ElfCloserFunc> ElfUniquePtr;

struct DwarfCloserFunc {
  void operator()(Dwarf *dw) {
    if (dw) {
      dwarf_end(dw);
    }
  }
};
typedef std::unique_ptr<Dwarf, DwarfCloserFunc> DwarfUniquePtr;

struct DebuginfodClientCloserFunc {
  void operator()(debuginfod_client *didcl) {
    if (didcl) {
      debuginfod_end(didcl);
    }
  }
};
typedef std::unique_ptr<debuginfod_client, DebuginfodClientCloserFunc> DebuginfodClientUniquePtr;

template <typename T> struct MallocFreerFunc {
  void operator()(T *t) {
    if (t) {
      free(t);
    }
  }
};
template <typename T> using MallocUniquePtr = std::unique_ptr<T, MallocFreerFunc<T>>;

// Class to act as a dead-mans switch on a file descriptor; will close it on destroy
// unless .release() is called first.
struct FDDestroyer {
  FDDestroyer() : fd(-1){};
  FDDestroyer(int monfd) : fd(monfd){};
  FDDestroyer(const FDDestroyer &other) = delete;
  FDDestroyer(FDDestroyer &&other) {
    if (fd != -1) {
      close(fd);
    }
    fd = other.fd;
    other.fd = -1;
  }
  ~FDDestroyer() {
    if (fd != -1) {
      close(fd);
    }
  }
  FDDestroyer &operator=(const FDDestroyer &other) = delete;
  FDDestroyer &operator=(FDDestroyer &&other) {
    if (fd != -1) {
      close(fd);
    }
    fd = other.fd;
    other.fd = -1;
    return *this;
  }
  int release() {
    int _fd = fd;
    fd = -1;
    return _fd;
  }

  int fd = -1;
};

namespace stdex {
template <typename T> using observer_ptr = std::experimental::observer_ptr<T>;
}

#endif
