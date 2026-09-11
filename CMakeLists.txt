cmake_minimum_required(VERSION 3.20)
project(SecurityRemediator LANGUAGES C CXX)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(sqlite3 STATIC third_party/sqlite/sqlite3.c)
target_compile_definitions(sqlite3 PRIVATE _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN SQLITE_THREADSAFE=0 SQLITE_OMIT_LOAD_EXTENSION SQLITE_OMIT_DEPRECATED)
target_compile_options(sqlite3 PRIVATE /w)

add_library(audit-core STATIC src/audit_core.cpp)
target_compile_features(audit-core PRIVATE cxx_std_17)
target_compile_definitions(audit-core PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(audit-core PRIVATE /W4 /permissive- /utf-8)
target_include_directories(audit-core PUBLIC src PRIVATE third_party/sqlite)
target_link_libraries(audit-core PUBLIC sqlite3 ole32 oleaut32 advapi32 iphlpapi ws2_32)

add_library(system-remediation STATIC src/system_remediation.cpp src/firewall_remediation.cpp)
target_compile_features(system-remediation PRIVATE cxx_std_17)
target_compile_definitions(system-remediation PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(system-remediation PRIVATE /W4 /permissive- /utf-8)
target_include_directories(system-remediation PUBLIC src)
target_link_libraries(system-remediation PUBLIC advapi32 ole32 oleaut32 shell32)

add_library(workflow-report STATIC src/workflow_report.cpp)
target_compile_features(workflow-report PRIVATE cxx_std_17)
target_compile_definitions(workflow-report PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(workflow-report PRIVATE /W4 /permissive- /utf-8)
target_include_directories(workflow-report PUBLIC src)
target_link_libraries(workflow-report PUBLIC audit-core system-remediation)

add_executable(remediator WIN32 src/main.cpp src/remediator.rc)
target_compile_features(remediator PRIVATE cxx_std_17)
target_compile_definitions(remediator PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(remediator PRIVATE /W4 /permissive- /utf-8)
target_link_libraries(remediator PRIVATE ole32 oleaut32 advapi32 shell32 crypt32 iphlpapi)

add_executable(remediator-inspector src/inspector.cpp src/inspector.rc src/inspector.manifest)
target_compile_features(remediator-inspector PRIVATE cxx_std_17)
target_compile_definitions(remediator-inspector PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(remediator-inspector PRIVATE /W4 /permissive- /utf-8)
target_link_options(remediator-inspector PRIVATE /MANIFESTUAC:NO)
target_include_directories(remediator-inspector PRIVATE third_party/sqlite)
target_link_libraries(remediator-inspector PRIVATE shell32 audit-core sqlite3 system-remediation workflow-report)
set_target_properties(remediator-inspector PROPERTIES OUTPUT_NAME "onsite-check-repair")

set(SR_UPLOAD_KEY_HEX "" CACHE STRING "Hex-encoded upload-only HMAC key")
set(SR_SERVER_CERT_SHA256 "" CACHE STRING "Pinned server certificate SHA-256")
set(SR_DEFAULT_SERVER "127.0.0.1:8443" CACHE STRING "Default report server host:port")
add_executable(remote-inspector WIN32 src/remote_inspector.cpp src/remote_inspector.rc src/inspector.manifest)
target_compile_features(remote-inspector PRIVATE cxx_std_17)
target_compile_definitions(remote-inspector PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601 SR_UPLOAD_KEY_HEX="${SR_UPLOAD_KEY_HEX}" SR_SERVER_CERT_SHA256="${SR_SERVER_CERT_SHA256}" SR_DEFAULT_SERVER=L"${SR_DEFAULT_SERVER}")
target_compile_options(remote-inspector PRIVATE /W4 /permissive- /utf-8)
target_link_options(remote-inspector PRIVATE /MANIFESTUAC:NO)
target_link_libraries(remote-inspector PRIVATE audit-core winhttp bcrypt crypt32 shell32)

set(SR_FTP_DEFAULT_SERVER "127.0.0.1:12221" CACHE STRING "Default FTP server host:port")
set(SR_FTP_USER "" CACHE STRING "FTP upload user")
set(SR_FTP_PASSWORD "" CACHE STRING "FTP upload password")
add_executable(ftp-inspector WIN32 src/ftp_inspector.cpp src/ftp_inspector.rc src/inspector.manifest)
target_compile_features(ftp-inspector PRIVATE cxx_std_17)
target_compile_definitions(ftp-inspector PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601 SR_FTP_DEFAULT_SERVER=L"${SR_FTP_DEFAULT_SERVER}" SR_FTP_USER=L"${SR_FTP_USER}" SR_FTP_PASSWORD=L"${SR_FTP_PASSWORD}")
target_compile_options(ftp-inspector PRIVATE /W4 /permissive- /utf-8)
target_link_options(ftp-inspector PRIVATE /MANIFESTUAC:NO)
target_link_libraries(ftp-inspector PRIVATE audit-core system-remediation workflow-report wininet shell32 ole32 oleaut32)
set_target_properties(ftp-inspector PROPERTIES OUTPUT_NAME "ftp-check-repair")

add_executable(report-server src/report_server.cpp src/report_server.rc src/inspector.manifest)
target_compile_features(report-server PRIVATE cxx_std_17)
target_compile_definitions(report-server PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(report-server PRIVATE /W4 /permissive- /utf-8)
target_link_options(report-server PRIVATE /MANIFESTUAC:NO)
target_link_libraries(report-server PRIVATE httpapi bcrypt crypt32 advapi32 shell32 ole32 oleaut32 ws2_32)

add_executable(remediator-cleaner src/cleaner.cpp src/cleaner.rc src/inspector.manifest)
target_compile_features(remediator-cleaner PRIVATE cxx_std_17)
target_compile_definitions(remediator-cleaner PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(remediator-cleaner PRIVATE /W4 /utf-8)
target_link_options(remediator-cleaner PRIVATE /MANIFESTUAC:NO)
target_include_directories(remediator-cleaner PRIVATE third_party/sqlite)
target_link_libraries(remediator-cleaner PRIVATE sqlite3)
set_target_properties(remediator-cleaner PROPERTIES OUTPUT_NAME "record-cleaner")

add_executable(ftp-report-pruner src/ftp_report_pruner.cpp src/ftp_report_pruner.rc src/inspector.manifest)
target_compile_features(ftp-report-pruner PRIVATE cxx_std_17)
target_compile_definitions(ftp-report-pruner PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(ftp-report-pruner PRIVATE /W4 /permissive- /utf-8)
target_link_options(ftp-report-pruner PRIVATE /MANIFESTUAC:NO)

add_executable(report-issue-exporter src/report_issue_exporter.cpp src/report_issue_exporter.rc src/report_tool.manifest)
target_compile_features(report-issue-exporter PRIVATE cxx_std_17)
target_compile_definitions(report-issue-exporter PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(report-issue-exporter PRIVATE /W4 /permissive- /utf-8)
target_link_options(report-issue-exporter PRIVATE /MANIFESTUAC:NO)

add_executable(rule-signer tools/rule_signer.cpp)
target_compile_features(rule-signer PRIVATE cxx_std_17)
target_compile_definitions(rule-signer PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_compile_options(rule-signer PRIVATE /W4 /permissive- /utf-8)
target_link_libraries(rule-signer PRIVATE advapi32 crypt32)

include(CTest)
if(BUILD_TESTING)
  find_program(SR_TEST_POWERSHELL NAMES pwsh.exe powershell.exe REQUIRED)
  add_executable(workflow-report-test tests/workflow_report_test.cpp)
  target_compile_features(workflow-report-test PRIVATE cxx_std_17)
  target_compile_definitions(workflow-report-test PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
  target_compile_options(workflow-report-test PRIVATE /W4 /permissive- /utf-8)
  target_include_directories(workflow-report-test PRIVATE src)
  target_link_libraries(workflow-report-test PRIVATE workflow-report)
  add_test(NAME workflow-report COMMAND workflow-report-test)

  add_executable(netbios-backup-capture-test tests/netbios-backup-capture-test.cpp)
  target_compile_features(netbios-backup-capture-test PRIVATE cxx_std_17)
  target_compile_definitions(netbios-backup-capture-test PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
  target_compile_options(netbios-backup-capture-test PRIVATE /W4 /permissive- /utf-8)
  target_include_directories(netbios-backup-capture-test PRIVATE src)
  target_link_libraries(netbios-backup-capture-test PRIVATE system-remediation advapi32)
  add_test(NAME netbios-backup-capture COMMAND netbios-backup-capture-test)

  add_executable(usb-uasp-audit-test tests/usb_uasp_audit_test.cpp)
  target_compile_features(usb-uasp-audit-test PRIVATE cxx_std_17)
  target_compile_definitions(usb-uasp-audit-test PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
  target_compile_options(usb-uasp-audit-test PRIVATE /W4 /permissive- /utf-8)
  target_link_libraries(usb-uasp-audit-test PRIVATE audit-core advapi32)
  add_test(NAME usb-uasp-audit COMMAND usb-uasp-audit-test)
  if(MSVC)
    foreach(win7_target IN ITEMS remediator remediator-inspector remote-inspector ftp-inspector remediator-cleaner)
      add_test(
        NAME win7-import-${win7_target}
        COMMAND "${SR_TEST_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/win7-import-compat.ps1"
                -Dumpbin "${CMAKE_DUMPBIN}"
                -Path "$<TARGET_FILE:${win7_target}>"
      )
    endforeach()
    add_test(
      NAME ftp-report-pruner
      COMMAND "${SR_TEST_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
              -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/ftp-report-pruner.ps1"
              -ExePath "$<TARGET_FILE:ftp-report-pruner>"
    )
    add_test(
      NAME win7-import-ftp-report-pruner
      COMMAND "${SR_TEST_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
              -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/win7-import-compat.ps1"
              -Dumpbin "${CMAKE_DUMPBIN}"
              -Path "$<TARGET_FILE:ftp-report-pruner>"
    )
    add_test(
      NAME report-issue-exporter
      COMMAND "${SR_TEST_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
              -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/report-issue-exporter.ps1"
              -ExePath "$<TARGET_FILE:report-issue-exporter>"
    )
    add_test(
      NAME win7-import-report-issue-exporter
      COMMAND "${SR_TEST_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
              -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/win7-import-compat.ps1"
              -Dumpbin "${CMAKE_DUMPBIN}"
              -Path "$<TARGET_FILE:report-issue-exporter>"
    )
    add_test(
      NAME shared-audit-consistency
      COMMAND "${SR_TEST_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
              -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/shared-audit-consistency.ps1"
              -FieldInspector "$<TARGET_FILE:remediator-inspector>"
              -RemoteInspector "$<TARGET_FILE:ftp-inspector>"
    )
    add_test(
      NAME audit-report-quality
      COMMAND "${SR_TEST_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
              -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/audit-report-quality.ps1"
              -Inspector "$<TARGET_FILE:remediator-inspector>"
    )
  endif()
endif()
