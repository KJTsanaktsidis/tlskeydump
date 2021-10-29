// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __debuginfo_finder
#define __debuginfo_finder

#include "config.h"

#include <elfutils/libdwfl.h>
#include <libelf.h>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

#include "cleanup_pointers.h"
#include "log.h"

namespace DebuginfoSearch {

struct SearchError : public FormattedError {
  template <typename... Args>
  SearchError(std::string format, Args... args) : FormattedError(format, args...) {}
};

struct LibraryInfo {
  // The order of struct members here is important, so that the main
  // destructors run before the alt ones, and the elf_end/dwarf_end
  // functions are called before the FD's are closed.
  FDDestroyer alt_fd;
  ElfUniquePtr elf_alt;
  DwarfUniquePtr dw_alt;
  FDDestroyer main_fd;
  ElfUniquePtr elf_main;
  DwarfUniquePtr dw_main;
};

constexpr const char *DEFAULT_GLOBAL_DEBUG_DIRECTORIES[1] = {"/usr/lib/debug"};
std::vector<std::string> default_global_debug_directories();

class Options {
public:
  pid_t pid;
  std::vector<std::string> global_debug_directories;
  bool enable_debuginfod;

  // This returns a very annoying char** type (a C version of a nullable
  // string) so that it can be fed into libdwfl's callback structure.
  // The memory is backed by this object and freed when this object is.
  char **global_debug_directories_cstr();

private:
  std::vector<char> _global_debug_directories_cstr;
  char *__global_debug_directories_cstr_ptr;
};

// This function can be used in the libdwfl find_elf callback.
// Parameters are as follows:
//     mod (in):        The Dwfl_Module whose elf is being found here
//     modname (in):    This value is basically taken straight out of /proc/maps and passed to
//                      the callback by libdw. This is the path-on-disk to the ELF file as mapped
//                      into the process.
//     file_name (out): This is the full path to the file we report as being the ELF file for this
//                      module. In this implementation, it will basically be set to the value
//                      /proc/${opts.pid}/root/${modname}. This memory is malloc'd by us, and
//                      libdwfl takes ownership of it.
//     elfp (out):      This is a pointer returned by calling elf_begin on the file we opened.
//     opts (in):       This is a DebuginfoSearch::Options struct, which the caller will most
//                      likely retrieve from the userdata parameter to the libdwfl callback.
//     (return):        An opened file descriptor pointing to the ELF file we opened. libdwfl
//                      takes ownership of this and is responsible for closing it.
//
// This method _can_ throw, so it needs to be wrapped in try {} catch (...) {} for use inside
// a libdwfl callback (otherwise the stack will unwind through libdwfl).
std::optional<int> find_elf_dwfl_cb(Dwfl_Module *mod, const char *modname, char **file_name,
                                    Elf **elfp, Options opts);

// This function can be used in the libdwfl find_debuginfo callback.
// This will often be called TWICE for a module - once to get the debuginfo, and once to get the
// alt debug info. Depending on which of the two is happening, libdwfl will pass in some slightly
// different values for some parameters as follows;
//     mod (in):        The Dwfl_Module whose dwarf is being found here
//     modname (in):    Like in find_elf, the name of the module is basically the name of the
//                      mapped file as reported in /proc/pid/maps, and is the on-disk path to the
//                      library that's been loaded into the process.
//     file_name (in):  If we are looking for main debuginfo: This will be the filename of the ELF
//                      as reported by the find_elf callback.
//                      If we are looking for alt debuginfo: This will be the filename of the main
//                      debuginfo file that we previously reported from the find_debuginfo callback
//     debuglink_file_name (in):
//                      This will either be the contents of the ELF's .gnu_debuglink section (if
//                      we are looking for _main_ debuginfo), or the .gnu_debugaltlink section (if
//                      we are looking for _alt_ debuginfo)
//     debuginfo_file_name (out):
//                      The path on disk to a file containing the DWARF data that is being looked
//                      for, either the main or alt file as appropriate. This is malloc'd and
//                      libdwfl takes ownership of it.
//     opts (in):       This is a DebuginfoSearch::Options struct, which the caller will most
//                      likely retrieve from the userdata parameter to the libdwfl callback.
//     (return):        An opened file descriptor pointing to the ELF file we opened. libdwfl
//                      takes ownership of this and is responsible for closing it.
//
// This method _can_ throw, so it needs to be wrapped in try {} catch (...) {} for use inside
// a libdwfl callback (otherwise the stack will unwind through libdwfl).
std::optional<int> find_debuginfo_dwfl_cb(Dwfl_Module *mod, const char *modname,
                                          const char *file_name, const char *debuglink_file,
                                          char **debuginfo_file_name, Options opts);

// This function can be used outside libdwfl to open a particular library by filename, find its
// debuginfo and alt info, and return the resources to the caller. This is used to load up
// libraries that are not actualy linked in to a process to provide a "best guess" for struct
// offsets where we suspect a TLS library has been statically linked into a process.
// This function takes care of calling dwarf_setalt to attach the alt debuginfo to the real one.
std::optional<LibraryInfo> find_debuginfo_unloaded_file(const std::string filename, Options opts);

} // namespace DebuginfoSearch

#endif
