# SPDX-License-Identifier: GPL-2.0-or-later

find_path(Libelf_INCLUDE_DIR "elf.h" "gelf.h" "libelf.h")
find_library(Libelf_LIBRARIES elf)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libelf DEFAULT_MSG Libelf_LIBRARIES Libelf_INCLUDE_DIR)
