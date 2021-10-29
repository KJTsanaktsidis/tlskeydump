// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <cstring>
#include <deque>
#include <elfutils/libdw.h>

#include "dwarf_util/dwarf_iterators.h"
#include "log.h"

namespace DwarfUtil {

static Logger _logger = new_logger("DwarfIterators");

// ==================== DieIterator impl ====================
DieIterator::DieIterator() {}
DieIterator::DieIterator(Dwarf_Die die) : _this_die(die), _descend_into_children(true) {}
DieIterator::DieIterator(Dwarf_Die die, bool descend)
    : _this_die(die), _descend_into_children(descend) {}
DieIterator::DieIterator(bool end) : _is_end(end) {}
DieIterator::reference DieIterator::operator*() const { return _this_die; }
DieIterator::pointer DieIterator::operator->() const { return &_this_die; }

DieIterator &DieIterator::operator++() {
  bool has_children = dwarf_haschildren(&_this_die);
  if (has_children && _descend_into_children) {
    Dwarf_Die child;
    int r = dwarf_child(&_this_die, &child);
    if (r == -1) {
      auto err = dwarf_errmsg(-1);
      auto dieoff = dwarf_dieoffset(&_this_die);
      throw IterationError("error iterating children of die %d: %s", dieoff, err);
    }
    _parent_chain.push_back(_this_die);
    _this_die = child;
    return *this;
  } else {
    // siblings?
    Dwarf_Die search_sibling_die = _this_die;
    while (true) {
      Dwarf_Die sibling;
      int r = dwarf_siblingof(&search_sibling_die, &sibling);
      if (r == -1) {
        auto err = dwarf_errmsg(-1);
        auto dieoff = dwarf_dieoffset(&_this_die);
        throw IterationError("error iterating siblings of die %d: %s", dieoff, err);
      } else if (r == 0) {
        // had siblings
        _this_die = sibling;
        return *this;
      } else if (_parent_chain.size() > 0) {
        // see if a parent had siblings
        search_sibling_die = _parent_chain.back();
        _parent_chain.pop_back();
      } else {
        // we're done
        _is_end = true;
        return *this;
      }
    };
  }
}

DieIterator DieIterator::operator++(int) {
  DieIterator tmp = *this;
  ++(*this);
  return tmp;
}

bool operator==(const DieIterator &a, const DieIterator &b) {
  if (a._is_end && b._is_end) {
    return true;
  }
  if (a._is_end != b._is_end) {
    return false;
  }
  // annoyingly, dwarf_dieoffset takes Dwarf_Die* not const Dwarf_Die*,
  // even though it does zero mutation.
  auto a_const_ptr = const_cast<Dwarf_Die *>(&a._this_die);
  auto b_const_ptr = const_cast<Dwarf_Die *>(&b._this_die);
  return dwarf_dieoffset(a_const_ptr) == dwarf_dieoffset(b_const_ptr);
}

bool operator!=(const DieIterator &a, const DieIterator &b) { return !(a == b); }

// ==================== DieSuccessorsRange impl ===================
DieSuccessorsRange::DieSuccessorsRange() {}
DieSuccessorsRange::DieSuccessorsRange(Dwarf_Die die) : _die(die) {}
DieIterator DieSuccessorsRange::begin() { return DieIterator(_die); }
DieIterator DieSuccessorsRange::end() { return DieIterator(true); }

// ==================== DieDirectChildrenRange impl ====================
DieDirectChildrenRange::DieDirectChildrenRange() {}
DieDirectChildrenRange::DieDirectChildrenRange(Dwarf_Die die) : _die(die) {}
DieIterator DieDirectChildrenRange::begin() {
  if (!dwarf_haschildren(&_die)) {
    return DieIterator(true);
  }
  Dwarf_Die child_die;
  dwarf_child(&_die, &child_die);
  return DieIterator(child_die, false);
}
DieIterator DieDirectChildrenRange::end() {
  // Just return an "end: true" iterator
  // when exhaustively iterating all direct children, we hit the _is_end = true
  // line in operator++
  return DieIterator(true);
}

// ==================== CUIterator impl =====================
CUIterator::CUIterator() {}
CUIterator::CUIterator(CUWithDie cu) : _this_cu(cu) {}
CUIterator::CUIterator(bool end) : _is_end(end) {}
CUIterator::reference CUIterator::operator*() const { return _this_cu; }
CUIterator::pointer CUIterator::operator->() const { return &_this_cu; }

CUIterator &CUIterator::operator++() {
  CUWithDie next = {};
  Dwarf *dw = dwarf_cu_getdwarf(_this_cu.cu);
  int r = dwarf_get_units(dw, _this_cu.cu, &next.cu, nullptr, nullptr, &next.cudie, nullptr);
  if (r == -1) {
    auto err = dwarf_errmsg(-1);
    throw IterationError("error getting next CU: %s", err);
  }
  _this_cu = next;
  if (_this_cu.cu == nullptr) {
    _is_end = true;
  }
  return *this;
}

CUIterator CUIterator::operator++(int) {
  CUIterator tmp = *this;
  ++(*this);
  return tmp;
}

bool operator==(const CUIterator &a, const CUIterator &b) {
  if (a._is_end && b._is_end) {
    return true;
  }
  if (a._is_end != b._is_end) {
    return false;
  }
  return a._this_cu.cu == b._this_cu.cu;
}

bool operator!=(const CUIterator &a, const CUIterator &b) { return !(a == b); }

// ==================== CURange impl ====================
CURange::CURange() {}
CURange::CURange(Dwarf *dw) : _dw(dw) {}

CUIterator CURange::begin() {
  CUWithDie first_cu = {};
  int r = dwarf_get_units(_dw, nullptr, &first_cu.cu, nullptr, nullptr, &first_cu.cudie, nullptr);
  if (r == -1) {
    auto err = dwarf_errmsg(-1);
    throw IterationError("error getting first CU: %s", err);
  }
  return CUIterator(first_cu);
}

CUIterator CURange::end() { return CUIterator(true); }

// ==================== AllDiesIterator impl ====================
AllDiesIterator::AllDiesIterator() {}
AllDiesIterator::AllDiesIterator(CURange cus) : _cus(cus) {
  _cu_it = cus.begin();
  _dies = DieSuccessorsRange(_cu_it->cudie);
  _die_it = _dies.begin();
}
AllDiesIterator::AllDiesIterator(bool is_end) : _is_end(is_end) {}
AllDiesIterator::reference AllDiesIterator::operator*() const { return *_die_it; }
AllDiesIterator::pointer AllDiesIterator::operator->() const { return _die_it.operator->(); }

AllDiesIterator &AllDiesIterator::operator++() {
  _die_it++;
  if (_die_it == _dies.end()) {
    _cu_it++;
    if (_cu_it == _cus.end()) {
      _is_end = true;
    } else {
      _dies = DieSuccessorsRange(_cu_it->cudie);
      _die_it = _dies.begin();
    }
  }
  return *this;
}

AllDiesIterator AllDiesIterator::operator++(int) {
  AllDiesIterator tmp = *this;
  ++(*this);
  return tmp;
}

bool operator==(const AllDiesIterator &a, const AllDiesIterator &b) {
  if (a._is_end && b._is_end) {
    return true;
  }
  if (a._is_end != b._is_end) {
    return false;
  }
  return (a._cu_it == b._cu_it) && (a._die_it == b._die_it);
}

bool operator!=(const AllDiesIterator &a, const AllDiesIterator &b) { return !(a == b); }

// ==================== AllDiesRange impl ====================
AllDiesRange::AllDiesRange(Dwarf *dw) : _dw(dw) {}
AllDiesIterator AllDiesRange::begin() { return AllDiesIterator(CURange(_dw)); }
AllDiesIterator AllDiesRange::end() { return AllDiesIterator(true); }

// ==================== ElfSectionIterator impl ====================
ElfSectionIterator::ElfSectionIterator() : _elf(nullptr) {}
ElfSectionIterator::ElfSectionIterator(Elf *elf, GElf_Section ix)
    : _elf(elf), _str_table(get_str_table()), _this_value(make_data_struct(ix)) {}

ElfSectionIterator::reference ElfSectionIterator::operator*() const { return _this_value; }
ElfSectionIterator::pointer ElfSectionIterator::operator->() const { return &_this_value; }

ElfSectionIterator &ElfSectionIterator::operator++() {
  GElf_Section next_ix = _this_value.index + 1;
  _this_value = make_data_struct(next_ix);
  return *this;
}
ElfSectionIterator ElfSectionIterator::operator++(int) {
  ElfSectionIterator tmp = *this;
  ++(*this);
  return tmp;
}

bool operator==(const ElfSectionIterator &a, const ElfSectionIterator &b) {
  return a._this_value.index == b._this_value.index;
}

bool operator!=(const ElfSectionIterator &a, const ElfSectionIterator &b) { return !(a == b); }

ElfSectionData ElfSectionIterator::make_data_struct(GElf_Section ix) {
  ElfSectionData data;
  // scn might be invalid if ix is past the end of the ELF - that's fine,
  // it's the value used in .end(). Just don't derefernece it.
  data.index = ix;
  data.scn = elf_getscn(_elf, data.index);
  GElf_Shdr *r = nullptr;
  if (data.scn) {
    r = gelf_getshdr(data.scn, &data.hdr);
  }
  if (r == nullptr) {
    // zero out the section if it's invalid
    std::memset(&data.hdr, 0, sizeof(data.hdr));
    data.header_ok = false;
  } else {
    data.header_ok = true;
  }

  char *scn_name = nullptr;
  if (data.header_ok) {
    scn_name = elf_strptr(_elf, _str_table, data.hdr.sh_name);
  }
  if (scn_name) {
    data.name = std::string(scn_name);
  } else {
    data.name = std::nullopt;
  }

  return data;
}

GElf_Section ElfSectionIterator::get_str_table() {
  GElf_Ehdr elf_header, *elf_header_ptr;
  elf_header_ptr = gelf_getehdr(_elf, &elf_header);
  if (!elf_header_ptr) {
    return -1;
  }
  return elf_header.e_shstrndx;
}

// ==================== ElfSectionsRange impl ====================
ElfSectionsRange::ElfSectionsRange(Elf *elf) : _elf(elf) {}

ElfSectionIterator ElfSectionsRange::begin() { return ElfSectionIterator(_elf, 0); }
ElfSectionIterator ElfSectionsRange::end() { return ElfSectionIterator(_elf, size()); }

size_t ElfSectionsRange::size() {
  size_t section_count;
  int r = elf_getshdrnum(_elf, &section_count);
  if (r == -1) {
    throw IterationError("could not get section header count of ELF file: %s", elf_errmsg(-1));
  }
  return section_count;
}

} // namespace DwarfUtil
