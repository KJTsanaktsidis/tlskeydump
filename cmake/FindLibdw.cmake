find_path(Libdw_INCLUDE_DIR "elfutils/libdw.h" "elfutils/libdwfl.h")
find_library(Libdw_LIBRARIES dw)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libdw DEFAULT_MSG Libdw_LIBRARIES Libdw_INCLUDE_DIR)
