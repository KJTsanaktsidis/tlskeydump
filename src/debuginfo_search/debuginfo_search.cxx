#include "config.h"

#include <algorithm>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/assert.hpp>
#include <boost/crc.hpp>
#include <boost/log/common.hpp>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <elfutils/debuginfod.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <filesystem>
#include <gelf.h>
#include <iterator>
#include <libelf.h>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>

#include "debuginfo_search/debuginfo_search.h"
#include "dwarf_util/dwarf_helpers.h"
#include "log.h"

namespace DebuginfoSearch {

static Logger _logger = new_logger("DebuginfoSearch");

char **Options::global_debug_directories_cstr() {
  std::string colon_str = boost::algorithm::join(global_debug_directories, ":");
  _global_debug_directories_cstr.clear();
  _global_debug_directories_cstr.reserve(colon_str.length() + 1);
  std::copy_n(colon_str.c_str(), colon_str.length() + 1,
              std::back_inserter(_global_debug_directories_cstr));
  __global_debug_directories_cstr_ptr = _global_debug_directories_cstr.data();
  return &__global_debug_directories_cstr_ptr;
}

static std::filesystem::path prepend_proc_root(pid_t pid, std::filesystem::path path) {
  if (pid > 0) {
    // When prepending /proc/pid/root to a path, the path has to be absolute
    // Despite how silly ::absolute().relative_path() looks, it is doing the right thing.
    auto root_path_component = std::filesystem::absolute(path).relative_path();
    return (std::filesystem::path("/proc") / std::to_string(pid) / "root" / root_path_component);
  } else {
    return path;
  }
}

static std::filesystem::path strip_proc_root(std::filesystem::path path) {
  std::vector<std::string> components;
  std::copy(path.begin(), path.end(), std::back_inserter(components));
  if (components.size() >= 4 && components[0] == "/" && components[1] == "proc" &&
      components[3] == "root") {

    std::filesystem::path newp("/");
    for (auto it = components.begin() + 4; it != components.end(); it++) {
      newp = newp / *it;
    }
    return strip_proc_root(newp);
  } else {
    return path;
  }
}

static uint32_t file_crc32(int fd) {
  boost::crc_32_type crc32;

  char buf[1024];
  int bytes_read;
  while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
    crc32.process_bytes(buf, bytes_read);
  }

  return crc32.checksum();
}

std::vector<std::string> default_global_debug_directories() {
  std::vector<std::string> vec;
  constexpr auto gdirs = DEFAULT_GLOBAL_DEBUG_DIRECTORIES;
  constexpr auto gdirs_len = sizeof(gdirs) / sizeof(decltype(gdirs[0]));
  std::copy(gdirs, gdirs + gdirs_len, std::back_inserter(vec));
  return vec;
}

struct DebuginfoCandiate {
  std::filesystem::path path;

  // Which ways to validate the debuginfo
  std::optional<uint32_t> crc32;
  std::vector<uint8_t> build_id;
};

std::optional<int> find_elf_dwfl_cb(Dwfl_Module *mod, const char *modname, char **file_name,
                                    Elf **elfp, Options opts) {

  // The modname needs to be unconditionally prefixed with /proc/pid/root, since that's
  // kind of implied by the names in /proc/pid/maps.
  auto prepended_filename = prepend_proc_root(opts.pid, modname);
  FDDestroyer fd(open(prepended_filename.c_str(), O_RDONLY, 0));
  if (fd.fd == -1) {
    int e = errno;
    if (e == ENOENT) {
      // The file does not actually exist. Return a nothing to represent
      // that we couldn't find an ELF.
      return std::nullopt;
    } else {
      char errbuf[512];
      strerror_r(e, errbuf, sizeof(errbuf));
      throw SearchError("could not open file %s: %s", prepended_filename, errbuf);
    }
  }

  ElfUniquePtr elf(elf_begin(fd.fd, ELF_C_READ, nullptr));
  if (!elfp) {
    auto err = elf_errmsg(-1);
    throw SearchError("could not construct ELF for file %s: %s", prepended_filename, err);
  }

  auto prepended_filename_str = prepended_filename.string();
  size_t fname_len_with_null = prepended_filename_str.size() + 1;
  MallocUniquePtr<char> fname_out(static_cast<char *>(malloc(fname_len_with_null)));
  std::copy(prepended_filename_str.c_str(), prepended_filename_str.c_str() + fname_len_with_null,
            fname_out.get());

  // Everything proceeded happily without throwing, set the our params and return, releasing
  // the resources from the objects that woud otherwise destroy them.
  *elfp = elf.release();
  *file_name = fname_out.release();
  return fd.release();
}

std::optional<int> find_debuginfo_dwfl_cb(Dwfl_Module *mod, const char *modname,
                                          const char *file_name, const char *debuglink_file,
                                          char **debuginfo_file_name, Options opts) {

  // Extract the ELF out of the module. We'll need this to figure out if debuglink_file is the
  // alt file or the main file to look up.
  // Mostly we follow the same path for either, but the validation is a bit different for
  // either case.
  //
  // When looking up main debuglink info, we verify that the crc32 of the file we're loading
  // matches the crc32 in the .gnu_debuglink section
  // When looking up alt info, we verify that the build ID of the alt file we're loading
  // matches the build id in the .gnu_debugaltlink section.
  // Otherwise things are the same.
  //
  // We can tell the difference because dwfl_module_getdwarf will work when loading alt
  // data, but not when loading main data, and more concretely because debuglink_file will
  // match the contents of the alt section.

  std::optional<DwarfUtil::DebuglinkData> debuglink;
  std::optional<DwarfUtil::AltDebuglinkData> debugaltlink;
  std::vector<uint8_t> build_id;
  std::string build_id_hex;
  std::optional<std::string> debuglink_file_name;
  std::optional<std::filesystem::path> module_filename_abs;
  bool looking_for_alt = false;

  GElf_Addr elf_bias;
  Elf *elf = dwfl_module_getelf(mod, &elf_bias);
  BOOST_ASSERT(elf);
  debuglink = DwarfUtil::debuglink_data(elf);

  Dwarf_Addr dw_bias;
  Dwarf *dw = dwfl_module_getdwarf(mod, &dw_bias);
  if (dw) {
    debugaltlink = DwarfUtil::alt_debuglink_data(dw);
    if (debugaltlink.has_value()) {
      if (debugaltlink.value().file == debuglink_file) {
        looking_for_alt = true;
      }
    }
  }

  if (looking_for_alt) {
    build_id = debugaltlink.value().build_id;
    debuglink_file_name = debugaltlink.value().file;
  } else {
    build_id = DwarfUtil::build_id(elf);
    if (debuglink.has_value()) {
      debuglink_file_name = debuglink.value().file;
    } else {
      debuglink_file_name = std::nullopt;
    }
  }
  boost::algorithm::hex_lower(build_id.begin(), build_id.end(), std::back_inserter(build_id_hex));
  // Note that we need to strip /proc/pid/root, if present, from file_name; this is so
  // we can re-append it _once_ at the end, and look for debug symbols on the host as
  // well.
  if (file_name) {
    module_filename_abs = strip_proc_root(file_name);
  }

  // OK. Now that we know what we're doing.
  // Follow the algorithm outlined here to find debug data:
  // https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
  std::vector<DebuginfoCandiate> candidate_files_abs;

  // We start by trying to find by build ID only.
  if (build_id.size() > 2) {
    auto build_id_stem = build_id_hex.substr(0, 2);
    auto build_id_rest = build_id_hex.substr(2, build_id_hex.size() - 2);
    // Search in global debug directories
    for (auto &debug_dir : opts.global_debug_directories) {
      DebuginfoCandiate candidate = {};
      candidate.path = std::filesystem::path(debug_dir) / ".build-id" / build_id_stem /
                       (build_id_rest + ".debug");
      candidate.build_id = build_id;
      candidate_files_abs.push_back(candidate);
    }
  }

  // Then, search by debuglink.
  if (debuglink_file_name.has_value()) {
    // When we're looking for main info, we validate by crc32, but when looking
    // for alt info, we validate by build_id.
    auto set_validation = [looking_for_alt, debuglink,
                           debugaltlink](DebuginfoCandiate &candidate) -> void {
      if (looking_for_alt) {
        candidate.build_id = debugaltlink.value().build_id;
      } else {
        candidate.crc32 = debuglink.value().crc32;
      }
    };

    DebuginfoCandiate candidate;
    // First, see if it's absolute
    std::filesystem::path debuglink_file_name_path(debuglink_file_name.value());
    if (debuglink_file_name_path.is_absolute()) {
      candidate = {};
      candidate.path = debuglink_file_name_path;
      set_validation(candidate);
      candidate_files_abs.push_back(candidate);
    }

    // All of the non-absolute options require that we know the path of the
    // binary we're looking for debuginfo for.
    if (module_filename_abs.has_value()) {
      // Look in the directory of the executable file.
      candidate = {};
      candidate.path =
          module_filename_abs.value().parent_path() / debuglink_file_name_path.relative_path();
      set_validation(candidate);
      candidate_files_abs.push_back(candidate);

      // Look in a .debug directory
      candidate = {};
      candidate.path = module_filename_abs.value().parent_path() / ".debug" /
                       debuglink_file_name_path.relative_path();
      set_validation(candidate);
      candidate_files_abs.push_back(candidate);

      // And look in the global debug directories
      for (auto &debug_dir : opts.global_debug_directories) {
        candidate = {};
        candidate.path = std::filesystem::path(debug_dir) /
                         module_filename_abs.value().parent_path().relative_path() /
                         debuglink_file_name_path.relative_path();
        set_validation(candidate);
        candidate_files_abs.push_back(candidate);
      }
    }
  }

  // Duplicate the candidate paths, searching in /proc/pid/root first.
  std::vector<DebuginfoCandiate> candidate_files;
  if (opts.pid > 0) {
    for (auto &c : candidate_files_abs) {
      DebuginfoCandiate ccopy = c;
      ccopy.path = prepend_proc_root(opts.pid, c.path);
      candidate_files.push_back(ccopy);
    }
  }
  std::copy(candidate_files_abs.begin(), candidate_files_abs.end(),
            std::back_inserter(candidate_files));

  // Convert candidate_files to a std::string vector so we can log it :(
  std::vector<std::string> candidate_files_as_str;
  std::transform(candidate_files.begin(), candidate_files.end(),
                 std::back_inserter(candidate_files_as_str),
                 [](const DebuginfoCandiate &e) -> std::string { return e.path.string(); });

  BOOST_LOG_SEV(_logger, Sev::DEBUG)
      << "searching for " << (looking_for_alt ? "alt" : "main") << " debuginfo for module "
      << module_filename_abs.value_or(modname).string() << "; looking in "
      << boost::algorithm::join(candidate_files_as_str, ", ");

  // OK, let's get down to brass tax.
  // These are the resources we want to return.
  FDDestroyer fd;
  MallocUniquePtr<char> found_path;
  bool did_find = false;

  // Find the first matching file...

  for (auto &candidate : candidate_files) {
    fd = FDDestroyer(open(candidate.path.c_str(), O_RDONLY, 0));
    if (fd.fd == -1) {
      // presumably does not exist
      continue;
    }

    // OK, it exists. Is it the right file?
    if (candidate.build_id.size() > 0) {
      // validate by build ID
      ElfUniquePtr candidate_elf(elf_begin(fd.fd, ELF_C_READ, nullptr));
      if (!candidate_elf.get()) {
        continue;
      }
      auto candidate_build_id = DwarfUtil::build_id(candidate_elf.get());
      if (candidate_build_id != candidate.build_id) {
        continue;
      }
    }
    if (candidate.crc32.has_value()) {
      // validate by crc32
      uint32_t crc = file_crc32(fd.fd);
      lseek(fd.fd, 0, SEEK_SET);
      if (crc != candidate.crc32.value()) {
        continue;
      }
    }

    // If we got here, it's the good stuff
    std::string path_str = candidate.path.string();
    size_t path_str_len = path_str.length() + 1;
    found_path.reset(static_cast<char *>(malloc(path_str_len)));
    std::copy(path_str.c_str(), path_str.c_str() + path_str_len, found_path.get());
    did_find = true;
    break;
  }

  if (!did_find && opts.enable_debuginfod && build_id_hex.size() > 0) {
    // Try in debuginfod
    DebuginfodClientUniquePtr dbid(debuginfod_begin());
    char *debuginfod_found_path;
    int debuginfod_found_fd = debuginfod_find_debuginfo(
        dbid.get(), reinterpret_cast<const unsigned char *>(build_id_hex.c_str()), 0,
        &debuginfod_found_path);
    if (debuginfod_found_fd >= 0) {
      fd = FDDestroyer(debuginfod_found_fd);
      found_path.reset(debuginfod_found_path);
      did_find = true;
    }
  }

  if (!did_find) {
    BOOST_LOG_SEV(_logger, Sev::DEBUG)
        << "did not find debuginfo for " << module_filename_abs.value_or(modname).string();
    return -1;
  }

  *debuginfo_file_name = found_path.release();
  return fd.release();
}

} // namespace DebuginfoSearch