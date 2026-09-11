#define _WIN32_WINNT 0x0601
#include "system_remediation.h"
#include <windows.h>
#include <iostream>

namespace {
const wchar_t *kFixture =
    L"Software\\SecurityRemediatorTests\\NetbiosBackupCapture";

bool CreateInterface(const std::wstring &path, bool withValue, DWORD value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0,
                      KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS)
    return false;
  bool ok = true;
  if (withValue)
    ok = RegSetValueExW(key, L"NetbiosOptions", 0, REG_DWORD,
                        reinterpret_cast<const BYTE *>(&value), sizeof(value)) ==
         ERROR_SUCCESS;
  RegCloseKey(key);
  return ok;
}
} // namespace

int wmain() {
  RegDeleteTreeW(HKEY_CURRENT_USER, kFixture);
  const std::wstring root = std::wstring(kFixture) +
      L"\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces";
  if (!CreateInterface(root + L"\\Tcpip_{11111111-1111-1111-1111-111111111111}",
                       true, 2) ||
      !CreateInterface(root + L"\\Tcpip_{22222222-2222-2222-2222-222222222222}",
                       false, 0)) {
    std::cerr << "FAIL: could not create NetBIOS registry fixture\n";
    return 2;
  }

  HKEY fixture = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kFixture, 0, KEY_READ, &fixture) !=
          ERROR_SUCCESS ||
      RegOverridePredefKey(HKEY_LOCAL_MACHINE, fixture) != ERROR_SUCCESS) {
    if (fixture) RegCloseKey(fixture);
    RegDeleteTreeW(HKEY_CURRENT_USER, kFixture);
    std::cerr << "FAIL: could not redirect HKLM\n";
    return 2;
  }

  std::vector<sr::NetbiosOptionSnapshot> states;
  const bool captured = sr::CaptureNetbiosOptionSnapshots(states);
  RegOverridePredefKey(HKEY_LOCAL_MACHINE, nullptr);
  RegCloseKey(fixture);
  RegDeleteTreeW(HKEY_CURRENT_USER, kFixture);

  if (!captured || states.size() != 2) {
    std::cerr << "FAIL: NetBIOS backup capture could not enumerate fixture\n";
    return 1;
  }
  size_t existing = 0, missing = 0;
  for (const auto &state : states) {
    if (state.exists && state.value == 2) ++existing;
    if (!state.exists) ++missing;
  }
  if (existing != 1 || missing != 1) {
    std::cerr << "FAIL: NetBIOS values and missing values were not preserved\n";
    return 1;
  }
  std::cout << "PASS: NetBIOS backup capture enumerated readable interfaces\n";
  return 0;
}
