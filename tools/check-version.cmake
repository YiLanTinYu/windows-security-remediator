cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED SOURCE_ROOT)
  get_filename_component(SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
endif()

file(STRINGS "${SOURCE_ROOT}/VERSION" version_lines)
foreach(line IN LISTS version_lines)
  if(line MATCHES "^([A-Z_]+)=([0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)$")
    set("VERSION_${CMAKE_MATCH_1}" "${CMAKE_MATCH_2}")
  elseif(NOT line STREQUAL "")
    message(FATAL_ERROR "VERSION contains an invalid line: ${line}")
  endif()
endforeach()

if(NOT DEFINED VERSION_SUITE)
  message(FATAL_ERROR "VERSION does not define SUITE")
endif()

file(READ "${SOURCE_ROOT}/README.md" readme)
if(NOT readme MATCHES "版本：${VERSION_SUITE}([\r\n]|$)")
  message(FATAL_ERROR "README.md does not declare suite version ${VERSION_SUITE}")
endif()

file(READ "${SOURCE_ROOT}/delivery/Windows版/VERSION_MANIFEST.txt" manifest)
if(NOT manifest MATCHES "套件版本：${VERSION_SUITE}([\r\n]|$)")
  message(FATAL_ERROR "VERSION_MANIFEST.txt does not declare suite version ${VERSION_SUITE}")
endif()

set(component_checks
  "ONSITE_INSPECTOR|文件版本"
  "FTP_INSPECTOR|文件版本"
  "RECORD_CLEANER|文件版本"
  "FTP_REPORT_PRUNER|文件版本"
  "REPORT_ISSUE_EXPORTER|文件版本")
foreach(check IN LISTS component_checks)
  string(REPLACE "|" ";" fields "${check}")
  list(GET fields 0 component)
  if(NOT DEFINED VERSION_${component})
    message(FATAL_ERROR "VERSION does not define ${component}")
  endif()
  if(NOT manifest MATCHES "${VERSION_${component}}")
    message(FATAL_ERROR "VERSION_MANIFEST.txt does not contain ${component} version ${VERSION_${component}}")
  endif()
endforeach()

set(resource_files
  remediator.rc inspector.rc ftp_inspector.rc remote_inspector.rc
  report_server.rc cleaner.rc ftp_report_pruner.rc report_issue_exporter.rc)
foreach(resource IN LISTS resource_files)
  file(READ "${SOURCE_ROOT}/src/${resource}" contents)
  if(contents MATCHES "(FILEVERSION|PRODUCTVERSION) +[0-9]")
    message(FATAL_ERROR "src/${resource} contains a hard-coded numeric version")
  endif()
  if(NOT contents MATCHES "#include \"version.h\"")
    message(FATAL_ERROR "src/${resource} does not include generated version.h")
  endif()
endforeach()

message(STATUS "Version metadata is consistent for suite ${VERSION_SUITE}")
