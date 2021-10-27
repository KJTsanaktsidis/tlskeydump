#include "config.h"

#include <algorithm>
#include <elfutils/libdw.h>
#include <memory>

#include "dwarf_util/dwarf_die_cache.h"
#include "dwarf_util/dwarf_helpers.h"
#include "dwarf_util/dwarf_iterators.h"

namespace DwarfUtil {

DieCache::DieCache() { configure_logger_component(_logger, "DieCache"); }

void DieCache::load_module(Elf *elf, Dwarf *dw) {
  // construct the module entry
  auto module_entry = std::make_shared<ModuleEntry>();
  module_entry->elf = elf;
  module_entry->dw = dw;
  module_entry->elf_bias = 0;
  module_entry->dw_bias = 0;
  module_entry->mod = nullptr;
  module_entry->soname = module_soname(module_entry->elf);
  module_entry->dwarf_loaded = true;
  load_module(module_entry);
}

void DieCache::load_module(Dwfl_Module *dwfl) {
  // construct the module entry.
  auto module_entry = std::make_shared<ModuleEntry>();
  module_entry->elf = dwfl_module_getelf(dwfl, &module_entry->elf_bias);
  if (!module_entry->elf) {
    // this module has no ELF (not sure if this is possible?)
    return;
  }
  module_entry->mod = dwfl;
  module_entry->soname = module_soname(module_entry->elf);
  module_entry->dwarf_loaded = false; // defer loading of DWARF data just now.
  load_module(module_entry);
}

void DieCache::load_module(std::shared_ptr<ModuleEntry> module_entry) {
  _modules.push_back(module_entry);
  if (module_entry->dw) {
    load_module_dwarf(module_entry);
  }
}

std::optional<DieEntry> DieCache::get_function(const std::string &fnname) {
  force_load_all_modules();
  auto rdie = lookup_die_by_name(
      fnname, [](DieEntry ent) -> bool { return die_is_function_impl(&ent.die); });
  if (!rdie.has_value()) {
    return std::nullopt;
  }
  return rdie.value();
}

std::optional<DieEntry> DieCache::get_function(const std::string &fnname,
                                               const std::string &soname) {
  force_load_module_soname(soname);
  auto rdie = lookup_die_by_name(fnname, [soname](DieEntry ent) -> bool {
    return die_is_function_impl(&ent.die) && ent.module->soname.has_value() &&
           ent.module->soname.value() == soname;
  });
  if (!rdie.has_value()) {
    return std::nullopt;
  }
  return rdie.value();
}

std::optional<DieEntry> DieCache::get_type(const std::string &fnname) {
  force_load_all_modules();
  auto rdie =
      lookup_die_by_name(fnname, [](DieEntry ent) -> bool { return die_is_type(&ent.die); });
  if (!rdie.has_value()) {
    return std::nullopt;
  }
  return rdie.value();
}

std::optional<DieEntry> DieCache::get_type(const std::string &fnname, const std::string &soname) {
  force_load_module_soname(soname);
  auto rdie = lookup_die_by_name(fnname, [soname](DieEntry ent) -> bool {
    return die_is_type(&ent.die) && ent.module->soname.has_value() &&
           ent.module->soname.value() == soname;
  });
  if (!rdie.has_value()) {
    return std::nullopt;
  }
  return rdie.value();
}

std::optional<DieEntry> DieCache::lookup_die_by_name(const std::string &name,
                                                     std::function<bool(DieEntry ent)> predicate) {
  if (!_dies_by_name.contains(name)) {
    return std::nullopt;
  }

  // Find the first die that is a function
  auto begin = _dies_by_name[name].begin();
  auto end = _dies_by_name[name].end();
  auto ix = std::find_if(begin, end, predicate);
  if (ix == end) {
    return std::nullopt;
  }
  return *ix;
}

const std::vector<std::shared_ptr<ModuleEntry>> DieCache::modules() { return _modules; }

void DieCache::force_load_all_modules() {
  for (auto &mod : _modules) {
    load_module_dwarf(mod);
  }
}

void DieCache::force_load_module_soname(const std::string &soname) {
  auto module_entry = std::find_if(
      _modules.begin(), _modules.end(),
      [soname](const std::shared_ptr<ModuleEntry> &ent) -> bool { return ent->soname == soname; });
  if (module_entry != _modules.end()) {
    load_module_dwarf(*module_entry);
  }
}

void DieCache::load_module_dwarf(std::shared_ptr<ModuleEntry> module_entry) {
  if (module_entry->dwarf_loaded) {
    return;
  }
  if (!module_entry->dw) {
    module_entry->dw = dwfl_module_getdwarf(module_entry->mod, &module_entry->dw_bias);
    module_entry->dwarf_loaded = true;
    if (!module_entry->dw) {
      return; // no debug symbols.
    }
  }
  for (auto die : AllDiesRange(module_entry->dw)) {
    DieEntry die_entry;
    die_entry.die = die;
    die_entry.module = module_entry;
    die_entry.name = die_name(&die_entry.die);

    // Copy everything into our giant backing vector
    _dies.push_back(die_entry);

    // Index by name
    if (die_entry.name.has_value()) {
      if (!_dies_by_name.contains(die_entry.name.value())) {
        _dies_by_name[die_entry.name.value()] = std::vector<DieEntry>();
      }
      _dies_by_name[die_entry.name.value()].push_back(die_entry);
    }
  }
}

} // namespace DwarfUtil
