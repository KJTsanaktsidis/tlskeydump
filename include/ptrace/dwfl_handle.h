#ifndef __dwfl_handle_h
#define __dwfl_handle_h

#include "config.h"

#include <cstdint>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <gelf.h>
#include <libelf.h>
#include <optional>
#include <string>
#include <unistd.h>

#include "debuginfo_search/debuginfo_search.h"
#include "dwarf_util/dwarf_die_cache.h"
#include "log.h"

namespace Ptrace {

struct DwflError : public FormattedError {
  template <typename... Args>
  DwflError(std::string format, Args... args) : FormattedError(format, args...) {}
  DwflError(std::string format) : FormattedError(format) {}
};

class DwflHandle {
public:
  DwflHandle(pid_t pid, DebuginfoSearch::Options opts);
  DwflHandle(DwflHandle &&other);
  ~DwflHandle();
  DwflHandle &operator=(DwflHandle &&other);
  DwflHandle(const DwflHandle &other) = delete;
  DwflHandle &operator=(const DwflHandle &other) = delete;
  friend void swap(DwflHandle &first, DwflHandle &second);

  void reload_maps();
  uintptr_t elf_start_address();
  bool is_dynamic();
  std::optional<DwarfUtil::DieEntry> get_function(const std::string &fnname,
                                                  const std::string &soname);
  std::optional<DwarfUtil::DieEntry> get_type(const std::string &fnname, const std::string &soname);

private:
  Logger _logger;

  pid_t _pid;
  Dwfl *_dwfl;
  Dwfl_Callbacks _dwfl_cbs;
  DwarfUtil::DieCache _cache;
  DebuginfoSearch::Options _search_opts;

  static int find_debuginfo_thunk(Dwfl_Module *mod, void **userdata, const char *modname,
                                  Dwarf_Addr base, const char *file_name,
                                  const char *debuglink_file, GElf_Word debuglink_crc,
                                  char **debuginfo_file_name);
  static int find_elf_thunk(Dwfl_Module *mod, void **userdata, const char *modname, Dwarf_Addr base,
                            char **file_name, Elf **elfp);
};

} // namespace Ptrace

#endif
