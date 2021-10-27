#include "config.h"

#include <boost/algorithm/string/join.hpp>
#include <boost/assert.hpp>
#include <boost/format.hpp>
#include <elfutils/libdwfl.h>
#include <gelf.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "debuginfo_search/debuginfo_search.h"
#include "dwarf_util/dwarf_helpers.h"
#include "log.h"
#include "ptrace/dwfl_handle.h"

namespace Ptrace {

DwflHandle::DwflHandle(pid_t pid, DebuginfoSearch::Options opts) : _pid(pid), _search_opts(opts) {
  configure_logger_component(_logger, "DwflHandle");

  _dwfl_cbs.find_elf = &DwflHandle::find_elf_thunk;
  _dwfl_cbs.find_debuginfo = &DwflHandle::find_debuginfo_thunk;
  _dwfl_cbs.debuginfo_path = opts.global_debug_directories_cstr();
  _dwfl_cbs.section_address = nullptr;

  _dwfl = dwfl_begin(&_dwfl_cbs);
  if (_dwfl == nullptr) {
    throw DwflError("failed dwfl_begin: %s", dwfl_errmsg(-1));
  }

  reload_maps();
}

DwflHandle::~DwflHandle() { dwfl_end(_dwfl); }

DwflHandle::DwflHandle(DwflHandle &&other) {
  using std::swap;
  swap(other, *this);
}

DwflHandle &DwflHandle::operator=(DwflHandle &&other) {
  using std::swap;
  swap(other, *this);
  return *this;
}

void swap(DwflHandle &first, DwflHandle &second) {
  using std::swap;
  swap(first._pid, second._pid);
  swap(first._search_opts, second._search_opts);
  swap(first._dwfl, second._dwfl);
  swap(first._dwfl_cbs, second._dwfl_cbs);
  swap(first._cache, second._cache);
}

void DwflHandle::reload_maps() {
  dwfl_report_begin(_dwfl);

  int ret = dwfl_linux_proc_report(_dwfl, _pid);
  dwfl_report_end(_dwfl, nullptr, nullptr);
  if (ret != 0) {
    throw DwflError("dwfl_proc_attach failed: %s", dwfl_errmsg(-1));
  }

  std::vector<Dwfl_Module *> new_modules;
  auto callback = [&new_modules](Dwfl_Module *m) {
    new_modules.push_back(m);
    return int(DWARF_CB_OK);
  };
  auto callback_thunk = [](Dwfl_Module *m, void **, const char *name, Dwarf_Addr, void *arg) {
    return static_cast<decltype(&callback)>(arg)->operator()(m);
  };
  ret = dwfl_getmodules(_dwfl, callback_thunk, &callback, 0);
  if (ret == -1) {
    throw DwflError("dwfl_getmodules failed: %s", dwfl_errmsg(-1));
  }

  _cache = DwarfUtil::DieCache();
  for (auto &mod : new_modules) {
    void **userdata;
    dwfl_module_info(mod, &userdata, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    *userdata = this;

    _cache.load_module(mod);
  }
}

uintptr_t DwflHandle::elf_start_address() {
  auto mod = _cache.modules().at(0);
  auto maybe_addr = DwarfUtil::elf_start_addr(mod->elf, mod->elf_bias);
  if (!maybe_addr.has_value()) {
    throw DwflError("no _start addr in elf!");
  }
  return maybe_addr.value();
}

bool DwflHandle::is_dynamic() {
  auto mod = _cache.modules().at(0);
  return DwarfUtil::elf_is_dynamic(mod->elf);
}

std::optional<DwarfUtil::DieEntry> DwflHandle::get_function(const std::string &fnname,
                                                            const std::string &soname) {
  return _cache.get_function(fnname, soname);
}

std::optional<DwarfUtil::DieEntry> DwflHandle::get_type(const std::string &fnname,
                                                        const std::string &soname) {
  return _cache.get_type(fnname, soname);
}

int DwflHandle::find_debuginfo_thunk(Dwfl_Module *mod, void **userdata, const char *modname,
                                     Dwarf_Addr base, const char *file_name,
                                     const char *debuglink_file, GElf_Word debuglink_crc,
                                     char **debuginfo_file_name) {
  BOOST_ASSERT(userdata != nullptr && *userdata != nullptr);
  try {
    auto self = static_cast<DwflHandle *>(*userdata);
    auto fd = DebuginfoSearch::find_debuginfo_dwfl_cb(mod, modname, file_name, debuglink_file,
                                                      debuginfo_file_name, self->_search_opts);
    if (fd.has_value()) {
      return fd.value();
    }
  } catch (...) {
  }
  return dwfl_standard_find_debuginfo(mod, userdata, modname, base, file_name, debuglink_file,
                                      debuglink_crc, debuginfo_file_name);
}

int DwflHandle::find_elf_thunk(Dwfl_Module *mod, void **userdata, const char *modname,
                               Dwarf_Addr base, char **file_name, Elf **elfp) {
  BOOST_ASSERT(userdata != nullptr && *userdata != nullptr);
  try {
    auto self = static_cast<DwflHandle *>(*userdata);
    auto fd = DebuginfoSearch::find_elf_dwfl_cb(mod, modname, file_name, elfp, self->_search_opts);
    if (fd.has_value()) {
      return fd.value();
    }
  } catch (...) {
  }
  return dwfl_linux_proc_find_elf(mod, userdata, modname, base, file_name, elfp);
}

} // namespace Ptrace
