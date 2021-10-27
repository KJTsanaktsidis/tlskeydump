#ifndef __dwarf_die_cache_h
#define __dwarf_die_cache_h

#include "config.h"

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <functional>
#include <gelf.h>
#include <libelf.h>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "log.h"

namespace DwarfUtil {

struct ModuleEntry {
  Dwarf *dw = nullptr;
  Elf *elf = nullptr;
  Dwfl_Module *mod = nullptr;
  GElf_Addr elf_bias = 0;
  Dwarf_Addr dw_bias = 0;
  std::optional<std::string> soname;
  bool dwarf_loaded = false;
};

struct DieEntry {
  Dwarf_Die die = {};
  std::shared_ptr<ModuleEntry> module;
  std::optional<std::string> name;
};

class DieCache {
public:
  DieCache();

  void load_module(Dwfl_Module *dwfl);
  void load_module(Elf *elf, Dwarf *dw);

  std::optional<DieEntry> get_function(const std::string &fnname);
  std::optional<DieEntry> get_function(const std::string &fnname, const std::string &soname);
  std::optional<DieEntry> get_type(const std::string &fnname);
  std::optional<DieEntry> get_type(const std::string &fnname, const std::string &soname);
  const std::vector<std::shared_ptr<ModuleEntry>> modules();

private:
  Logger _logger;
  std::vector<std::shared_ptr<ModuleEntry>> _modules;
  std::vector<DieEntry> _dies;
  std::unordered_map<std::string, std::vector<DieEntry>> _dies_by_name;

  std::optional<DieEntry> lookup_die_by_name(const std::string &name,
                                             std::function<bool(DieEntry ent)> predicate);
  void load_module(std::shared_ptr<ModuleEntry> module_entry);
  void force_load_all_modules();
  void force_load_module_soname(const std::string &soname);
  void load_module_dwarf(std::shared_ptr<ModuleEntry> module_entry);
};

} // namespace DwarfUtil

#endif
