#ifndef __dwarf_helpers_h
#define __dwarf_helpers_h

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <elfutils/libdw.h>
#include <gelf.h>
#include <libelf.h>
#include <optional>
#include <string>
#include <vector>

#include "dwarf_util/dwarf_iterators.h"
#include "log.h"

namespace DwarfUtil {

struct DwarfLogicalError : public FormattedError {
  template <typename... Args>
  DwarfLogicalError(std::string format, Args... args) : FormattedError(format, args...) {}
};

bool die_is_float(Dwarf_Die *die);
bool die_is_type(Dwarf_Die *die);
bool die_is_function_impl(Dwarf_Die *die);
std::optional<std::vector<Dwarf_Die>> die_function_args(Dwarf_Die *die);
std::vector<uintptr_t> die_function_entry(Dwarf_Die *die, Dwarf_Addr bias);
std::optional<std::string> die_name(Dwarf_Die *die);
std::optional<size_t> die_size(Dwarf_Die *die);
std::optional<Dwarf_Die> die_type(Dwarf_Die *die);
std::optional<Dwarf_Die> die_member(Dwarf_Die *die, const std::string &member_name);
std::optional<size_t> die_member_offset(Dwarf_Die *die);
std::optional<Dwarf_Die> die_dereference_type(Dwarf_Die *die);

struct MemberLocation {
  ptrdiff_t offset;
  size_t size;
};
std::optional<MemberLocation> die_member_location(Dwarf_Die *die);

std::optional<Dwarf_Die> module_type_die_by_name(Dwarf *dw, const std::string &type_name);
std::optional<Dwarf_Die> module_function_die_by_name(Dwarf *dw, const std::string &type_name);
std::optional<std::string> module_soname(Elf *elf);
std::optional<uintptr_t> elf_start_addr(Elf *elf, GElf_Addr bias);
bool elf_is_dynamic(Elf *elf);

struct DebuglinkData {
  std::string file;
  uint32_t crc32;
};

struct AltDebuglinkData {
  std::string file;
  std::vector<uint8_t> build_id;
};

std::optional<DebuglinkData> debuglink_data(Elf *elf);
std::vector<uint8_t> build_id(Elf *elf);
std::optional<AltDebuglinkData> alt_debuglink_data(Dwarf *dw);

} // namespace DwarfUtil

#endif
