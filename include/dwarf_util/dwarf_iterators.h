// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __die_iterators_h
#define __die_iterators_h

#include "config.h"

#include <cstddef>
#include <deque>
#include <elf.h>
#include <elfutils/libdw.h>
#include <gelf.h>
#include <iterator>
#include <libelf.h>
#include <optional>
#include <string>

#include "log.h"

namespace DwarfUtil {

struct IterationError : public FormattedError {
  template <typename... Args>
  IterationError(std::string format, Args... args) : FormattedError(format, args...) {}
};

class DieIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using difference_type = std::ptrdiff_t;
  using value_type = Dwarf_Die;
  using pointer = const Dwarf_Die *;
  using reference = const Dwarf_Die &;

  DieIterator();
  DieIterator(Dwarf_Die die);
  DieIterator(Dwarf_Die die, bool descend);
  DieIterator(bool end);
  reference operator*() const;
  pointer operator->() const;
  DieIterator &operator++();
  DieIterator operator++(int);
  friend bool operator==(const DieIterator &a, const DieIterator &b);
  friend bool operator!=(const DieIterator &a, const DieIterator &b);

private:
  std::deque<Dwarf_Die> _parent_chain;
  Dwarf_Die _this_die;
  bool _is_end = false;
  bool _descend_into_children = true;
};

class DieSuccessorsRange {
public:
  DieSuccessorsRange();
  DieSuccessorsRange(Dwarf_Die die);
  DieIterator begin();
  DieIterator end();

private:
  Dwarf_Die _die;
};

class DieDirectChildrenRange {
public:
  DieDirectChildrenRange();
  DieDirectChildrenRange(Dwarf_Die die);
  DieIterator begin();
  DieIterator end();

private:
  Dwarf_Die _die;
};

struct CUWithDie {
  Dwarf_CU *cu;
  Dwarf_Die cudie;
};

class CUIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using difference_type = std::ptrdiff_t;
  using value_type = CUWithDie;
  using pointer = const CUWithDie *;
  using reference = const CUWithDie &;

  CUIterator();
  CUIterator(CUWithDie cu);
  CUIterator(bool end);
  reference operator*() const;
  pointer operator->() const;
  CUIterator &operator++();
  CUIterator operator++(int);
  friend bool operator==(const CUIterator &a, const CUIterator &b);
  friend bool operator!=(const CUIterator &a, const CUIterator &b);

private:
  CUWithDie _this_cu = {};
  bool _is_end = false;
};

class CURange {
public:
  CURange();
  CURange(Dwarf *dw);
  CUIterator begin();
  CUIterator end();

private:
  Dwarf *_dw;
};

class AllDiesIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using difference_type = std::ptrdiff_t;
  using value_type = Dwarf_Die;
  using pointer = const Dwarf_Die *;
  using reference = const Dwarf_Die &;

  AllDiesIterator();
  AllDiesIterator(CURange cus);
  AllDiesIterator(bool is_end);
  reference operator*() const;
  pointer operator->() const;
  AllDiesIterator &operator++();
  AllDiesIterator operator++(int);
  friend bool operator==(const AllDiesIterator &a, const AllDiesIterator &b);
  friend bool operator!=(const AllDiesIterator &a, const AllDiesIterator &b);

private:
  CURange _cus;
  CUIterator _cu_it;
  DieSuccessorsRange _dies;
  DieIterator _die_it;
  bool _is_end = false;
};

class AllDiesRange {
public:
  AllDiesRange(Dwarf *dw);
  AllDiesIterator begin();
  AllDiesIterator end();

private:
  Dwarf *_dw;
};

struct ElfSectionData {
  GElf_Section index;
  Elf_Scn *scn;
  GElf_Shdr hdr;
  bool header_ok;
  std::optional<std::string> name;
};

class ElfSectionIterator {
public:
  using iterator_category = std::input_iterator_tag;
  using difference_type = std::ptrdiff_t;
  using value_type = ElfSectionData;
  using pointer = const ElfSectionData *;
  using reference = const ElfSectionData &;

  ElfSectionIterator();
  ElfSectionIterator(Elf *elf, GElf_Section ix);
  reference operator*() const;
  pointer operator->() const;
  ElfSectionIterator &operator++();
  ElfSectionIterator operator++(int);
  friend bool operator==(const ElfSectionIterator &a, const ElfSectionIterator &b);
  friend bool operator!=(const ElfSectionIterator &a, const ElfSectionIterator &b);

private:
  Elf *_elf;
  GElf_Section _str_table;
  ElfSectionData _this_value;

  ElfSectionData make_data_struct(GElf_Section ix);
  GElf_Section get_str_table();
};

class ElfSectionsRange {
public:
  ElfSectionsRange(Elf *elf);
  ElfSectionIterator begin();
  ElfSectionIterator end();
  size_t size();

private:
  Elf *_elf;
};

} // namespace DwarfUtil

#endif
