#include "config.h"

#include <algorithm>
#include <boost/format.hpp>
#include <deque>
#include <dwarf.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>
#include <iterator>
#include <optional>
#include <sys/types.h>
#include <vector>

#include "cleanup_pointers.h"
#include "dwarf_util/dwarf_helpers.h"
#include "dwarf_util/dwarf_iterators.h"
#include "log.h"

namespace DwarfUtil {

static Logger _logger = new_logger("DwarfHelpers");

static constexpr int EncodingsFloat[] = {
    DW_ATE_float,
    DW_ATE_complex_float,
    DW_ATE_imaginary_float,
    DW_ATE_decimal_float,
};

static constexpr int TagsType[] = {
    DW_TAG_array_type,
    DW_TAG_class_type,
    DW_TAG_enumeration_type,
    DW_TAG_pointer_type,
    DW_TAG_reference_type,
    DW_TAG_string_type,
    DW_TAG_structure_type,
    DW_TAG_subroutine_type,
    DW_TAG_typedef,
    DW_TAG_union_type,
    DW_TAG_ptr_to_member_type,
    DW_TAG_set_type,
    DW_TAG_subrange_type,
    DW_TAG_base_type,
    DW_TAG_const_type,
    DW_TAG_file_type,
    DW_TAG_packed_type,
    DW_TAG_template_type_parameter,
    DW_TAG_thrown_type,
    DW_TAG_volatile_type,
    DW_TAG_restrict_type,
    DW_TAG_interface_type,
    DW_TAG_unspecified_type,
    DW_TAG_shared_type,
    DW_TAG_type_unit,
    DW_TAG_rvalue_reference_type,
    DW_TAG_coarray_type,
    DW_TAG_dynamic_type,
    DW_TAG_atomic_type,
    DW_TAG_immutable_type,
};

// ================ Private template impls ================
template <typename InputIterator>
static bool _die_has_encoding(Dwarf_Die *die, InputIterator start_iter, InputIterator end_iter) {
  Dwarf_Attribute encoding_attr_mem, *encoding_attr;
  Dwarf_Word encoding;
  encoding_attr = dwarf_attr_integrate(die, DW_AT_encoding, &encoding_attr_mem);
  if (!encoding_attr) {
    return false;
  }
  int r = dwarf_formudata(encoding_attr, &encoding);
  if (r != 0) {
    return false;
  }

  auto found = std::find(start_iter, end_iter, encoding);
  return found != end_iter;
}

template <typename InputIterator>
static bool _die_has_tag(Dwarf_Die *die, InputIterator start_iter, InputIterator end_iter) {
  int tag = dwarf_tag(die);
  auto found = std::find(start_iter, end_iter, tag);
  return found != end_iter;
}

template <typename InsertIterator>
std::optional<int> _die_function_args(Dwarf_Die *die, InsertIterator it) {
  if (dwarf_tag(die) != DW_TAG_subprogram) {
    return std::nullopt;
  }

  DieDirectChildrenRange direct_children(*die);
  int num_args = 0;
  for (auto child_die : direct_children) {
    if (dwarf_tag(&child_die) != DW_TAG_formal_parameter) {
      continue;
    }
    Dwarf_Die fn_arg_die;
    Dwarf_Attribute origin_attr_mem, *origin_attr;

    origin_attr = dwarf_attr_integrate(&child_die, DW_AT_abstract_origin, &origin_attr_mem);
    if (origin_attr != nullptr) {
      auto fn_arg_die_ptr = dwarf_formref_die(origin_attr, &fn_arg_die);
      if (fn_arg_die_ptr == nullptr) {
        throw DwarfLogicalError("error calling dwarf_formref_die in die_function_args: %s",
                                dwarf_errmsg(-1));
      }
    } else {
      fn_arg_die = child_die;
    }

    *(it++) = fn_arg_die;
    num_args++;
  }
  return num_args;
}

// ================ Public impls ================
bool die_is_float(Dwarf_Die *die) {
  return _die_has_encoding(die, std::begin(EncodingsFloat), std::end(EncodingsFloat));
}

bool die_is_type(Dwarf_Die *die) {
  return _die_has_tag(die, std::begin(TagsType), std::end(TagsType));
}

bool die_is_function_impl(Dwarf_Die *die) {
  if (dwarf_tag(die) != DW_TAG_subprogram) {
    return false;
  }
  Dwarf_Addr entrypc;
  int res = dwarf_entrypc(die, &entrypc);
  if (res == -1) {
    return false;
  }
  return true;
}

std::optional<std::vector<Dwarf_Die>> die_function_args(Dwarf_Die *die) {
  std::vector<Dwarf_Die> ret_vec;
  auto tmpl_ret = _die_function_args(die, std::back_inserter(ret_vec));
  if (tmpl_ret.has_value()) {
    return ret_vec;
  } else {
    return std::nullopt;
  }
}

std::vector<uintptr_t> die_function_entry(Dwarf_Die *die, Dwarf_Addr bias) {
  Dwarf_Addr *breakpoints;
  std::vector<uintptr_t> ret;
  int bp_count = dwarf_entry_breakpoints(die, &breakpoints);
  if (bp_count < 1) {
    return ret;
  }
  MallocUniquePtr<Dwarf_Addr> bp_free(breakpoints);

  for (int i = 0; i < bp_count; i++) {
    ret.push_back(breakpoints[i] + bias);
  }
  return ret;
}

std::optional<std::string> die_name(Dwarf_Die *die) {
  auto name = dwarf_diename(die);
  if (name == nullptr) {
    return std::nullopt;
  }
  return std::string(name);
}

std::optional<size_t> die_size(Dwarf_Die *die) {
  Dwarf_Die peeled_die_mem, *peeled_die;
  dwarf_peel_type(die, &peeled_die_mem);
  peeled_die = &peeled_die_mem;

  Dwarf_Word size = 0;
  int r = dwarf_aggregate_size(peeled_die, &size);
  if (r != -1) {
    return size;
  }

  // If the die is an array, and the enclosing CU does not specify
  // the language, dwarf_aggregate_size is not able to compute the size
  // (since it doesn't know if the language uses zero or one based indexing).
  // https://sourceware.org/pipermail/elfutils-devel/2021q3/004221.html
  // We however can probably safely assume that the libraries we're opening
  // here haven't been rewritten in FORTRAN.
  if (dwarf_tag(peeled_die) == DW_TAG_array_type) {
    auto element_type = die_type(peeled_die);
    if (!element_type.has_value()) {
      return std::nullopt;
    }
    Dwarf_Die child;
    r = dwarf_child(peeled_die, &child);
    if (r != 0) {
      return std::nullopt;
    }
    if (dwarf_tag(&child) != DW_TAG_subrange_type) {
      return std::nullopt;
    }
    Dwarf_Attribute upper_bound_attr_mem, *upper_bound_attr;
    upper_bound_attr = dwarf_attr_integrate(&child, DW_AT_upper_bound, &upper_bound_attr_mem);
    if (upper_bound_attr == nullptr) {
      return std::nullopt;
    }
    Dwarf_Sword upper_bound;
    bool is_signed = true;

    auto subrange_type = die_type(&child);
    if (subrange_type.has_value()) {
      Dwarf_Attribute encoding_attr;
      Dwarf_Word encoding;
      if (dwarf_attr_integrate(&subrange_type.value(), DW_AT_encoding, &encoding_attr) != nullptr) {
        r = dwarf_formudata(&encoding_attr, &encoding);
        if (r == 0) {
          is_signed = (encoding == DW_ATE_signed) || (encoding == DW_ATE_signed_char);
        }
      }
    }
    if (is_signed) {
      r = dwarf_formsdata(upper_bound_attr, &upper_bound);
      if (r == -1) {
        return std::nullopt;
      }
    } else {
      Dwarf_Word unsigned_upper_bound;
      r = dwarf_formudata(upper_bound_attr, &unsigned_upper_bound);
      if (r == -1) {
        return std::nullopt;
      }
      upper_bound = static_cast<Dwarf_Sword>(unsigned_upper_bound);
    }

    // Assume we're using zero based indexing.
    Dwarf_Word element_count = upper_bound + 1;
    auto element_size = die_size(&element_type.value());
    if (!element_size.value()) {
      return std::nullopt;
    }
    return element_count * element_size.value();
  }
  return std::nullopt;
}

std::optional<Dwarf_Die> die_type(Dwarf_Die *die) {
  Dwarf_Attribute typeattr_mem, *typeattr;
  typeattr = dwarf_attr_integrate(die, DW_AT_type, &typeattr_mem);
  if (typeattr == nullptr) {
    return std::nullopt;
  }

  Dwarf_Die refdie_mem, *refdie;
  refdie = dwarf_formref_die(typeattr, &refdie_mem);
  if (refdie != nullptr) {
    Dwarf_Die peeled_die;
    dwarf_peel_type(refdie, &peeled_die);
    return peeled_die;
  }
  return std::nullopt;
}

std::optional<Dwarf_Die> die_member(Dwarf_Die *die, const std::string &member_name) {
  if (!die_is_type(die)) {
    return std::nullopt;
  }
  Dwarf_Die peeled_die;
  dwarf_peel_type(die, &peeled_die);

  // Look for children of die that are of type member
  DieDirectChildrenRange direct_children(peeled_die);
  for (auto child : direct_children) {
    if (dwarf_tag(&child) == DW_TAG_member) {
      auto maybe_name = die_name(&child);
      if (maybe_name.has_value() && maybe_name.value() == member_name) {
        return child;
      }
    }
  }
  return std::nullopt;
}

std::optional<size_t> die_member_offset(Dwarf_Die *die) {
  Dwarf_Attribute offsetattr;
  Dwarf_Attribute *offsetattr_ptr =
      dwarf_attr_integrate(die, DW_AT_data_member_location, &offsetattr);
  if (offsetattr_ptr == nullptr) {
    return std::nullopt;
  }
  switch (offsetattr_ptr->form) {
  case DW_FORM_data1:
  case DW_FORM_data2:
  case DW_FORM_data4:
  case DW_FORM_data8:
  case DW_FORM_data16:
  case DW_FORM_udata: {
    Dwarf_Word ret = 0;
    dwarf_formudata(offsetattr_ptr, &ret);
    return ret;
  }
  default:
    return std::nullopt;
  }
}

std::optional<Dwarf_Die> die_dereference_type(Dwarf_Die *die) {
  if (!die_is_type(die)) {
    return std::nullopt;
  }
  Dwarf_Die peeled_die;
  dwarf_peel_type(die, &peeled_die);
  return die_type(&peeled_die);
}

std::optional<MemberLocation> die_member_location(Dwarf_Die *die) {
  MemberLocation r;
  auto offset = die_member_offset(die);
  if (!offset.has_value()) {
    return std::nullopt;
  }
  r.offset = offset.value();

  auto dtype = die_type(die);
  if (!dtype.has_value()) {
    return std::nullopt;
  }
  auto sz = die_size(&dtype.value());
  if (!sz.has_value()) {
    return std::nullopt;
  }
  r.size = sz.value();
  return r;
}

std::optional<Dwarf_Die> module_type_die_by_name(Dwarf *dw, const std::string &type_name) {
  AllDiesRange dies(dw);
  auto el = std::find_if(dies.begin(), dies.end(), [type_name](Dwarf_Die die) -> bool {
    return die_is_type(&die) && die_name(&die).value_or("") == type_name;
  });
  return el != dies.end() ? std::optional(*el) : std::nullopt;
}

std::optional<Dwarf_Die> module_function_die_by_name(Dwarf *dw, const std::string &type_name) {
  AllDiesRange dies(dw);
  auto el = std::find_if(dies.begin(), dies.end(), [type_name](Dwarf_Die die) -> bool {
    return die_is_function_impl(&die) && die_name(&die).value_or("") == type_name;
  });
  return el != dies.end() ? std::optional(*el) : std::nullopt;
}

std::optional<std::string> module_soname(Elf *elf) {
  // Find the sections we're looking for - .dynstr and .dynamic
  Elf_Scn *dynstr_scn = nullptr;
  Elf_Scn *dynamic_scn = nullptr;
  for (auto scn : ElfSectionsRange(elf)) {
    if (!scn.name.has_value()) {
      continue;
    }
    if (scn.name == ".dynstr") {
      dynstr_scn = scn.scn;
    } else if (scn.name == ".dynamic") {
      dynamic_scn = scn.scn;
    }
  }

  if (!dynamic_scn || !dynstr_scn) {
    // This module did not have what we were looking for
    return std::nullopt;
  }

  // Loop through the dynamic section looking for the SONAME entry.
  GElf_Shdr dynamic_section_header, *dynamic_section_header_ptr;
  dynamic_section_header_ptr = gelf_getshdr(dynamic_scn, &dynamic_section_header);
  if (dynamic_section_header_ptr == nullptr) {
    return std::nullopt;
  }
  Elf_Data *data_ptr;
  data_ptr = elf_getdata(dynamic_scn, nullptr);
  if (data_ptr == nullptr) {
    return std::nullopt;
  }

  int num_entries = dynamic_section_header.sh_size / dynamic_section_header.sh_entsize;
  GElf_Dyn soname_ent;
  bool found = false;
  for (int i = 0; i < num_entries; i++) {
    GElf_Dyn dyn, *dyn_ptr;
    dyn_ptr = gelf_getdyn(data_ptr, i, &dyn);
    if (dyn_ptr != nullptr && dyn.d_tag == DT_SONAME) {
      soname_ent = dyn;
      found = true;
      break;
    }
  }
  if (!found) {
    return std::nullopt;
  }

  // We definitely found a soname tag
  auto soname_data = elf_strptr(elf, elf_ndxscn(dynstr_scn), soname_ent.d_un.d_val);
  if (!soname_data) {
    return std::nullopt;
  }

  return std::string(soname_data);
}

std::optional<DebuglinkData> debuglink_data(Elf *elf) {
  // This is easy - we can just use the implementation of dwelf_elf_gnu_debuglink
  // to parse everything for us.
  GElf_Word crc32;
  const char *filename = dwelf_elf_gnu_debuglink(elf, &crc32);
  if (!filename) {
    // no debuglink
    return std::nullopt;
  }

  DebuglinkData data;
  data.file = std::string(filename);
  data.crc32 = crc32;
  return data;
}

std::vector<uint8_t> build_id(Elf *elf) {
  // Also return the build ID of this file if present.
  std::vector<uint8_t> vec;

  const void *build_id_void;
  ssize_t build_id_len = dwelf_elf_gnu_build_id(elf, &build_id_void);
  if (build_id_len > 0) {
    auto build_id = static_cast<const uint8_t *>(build_id_void);
    std::copy(build_id, build_id + build_id_len, std::back_inserter(vec));
  }
  return vec;
}

std::optional<AltDebuglinkData> alt_debuglink_data(Dwarf *dw) {
  // Although in theory this can be implemented without having a Dwarf*, calling
  // dwelf_dwarf_gnu_debugaltlink requires it because it uses the indexed section
  // data from the dwarf struct.
  // We can implement an overload of alt_debuglink_data that doesn't require it,
  // but we'd have to do a lot of parsing ourselves; I'll only write that if it
  // turns out to be needed.
  const char *filename;
  const void *build_id_void;
  ssize_t build_id_len = dwelf_dwarf_gnu_debugaltlink(dw, &filename, &build_id_void);
  if (build_id_len <= 0) {
    // no altlink
    return std::nullopt;
  }

  // The build ID is returned as a void*, but it's actually an array of bytes...
  auto build_id = static_cast<const uint8_t *>(build_id_void);

  AltDebuglinkData data;
  data.file = std::string(filename);
  std::copy(build_id, build_id + build_id_len, std::back_inserter(data.build_id));
  return data;
}

std::optional<uintptr_t> elf_start_addr(Elf *elf, GElf_Addr bias) {
  GElf_Ehdr header_mem, *header;
  header = gelf_getehdr(elf, &header_mem);
  if (header == nullptr) {
    return std::nullopt;
  }
  if (!header->e_entry) {
    return std::nullopt;
  }

  return header->e_entry + bias;
}

bool elf_is_dynamic(Elf *elf) {
  GElf_Ehdr header_mem, *header;
  header = gelf_getehdr(elf, &header_mem);
  if (header == nullptr) {
    return false;
  }
  for (int i = 0; i < header->e_phnum; i++) {
    GElf_Phdr phdr_mem, *phdr;
    phdr = gelf_getphdr(elf, i, &phdr_mem);
    if (phdr && phdr->p_type == PT_INTERP) {
      return true;
    }
  }
  return false;
}

} // namespace DwarfUtil
