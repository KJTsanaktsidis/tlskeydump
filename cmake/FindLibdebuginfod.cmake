# SPDX-License-Identifier: GPL-2.0-or-later

find_path(Libdebuginfod_INCLUDE_DIR "elfutils/debuginfod.h")
find_library(Libdebuginfod_LIBRARIES debuginfod)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libdebuginfod DEFAULT_MSG Libdebuginfod_LIBRARIES Libdebuginfod_INCLUDE_DIR)
