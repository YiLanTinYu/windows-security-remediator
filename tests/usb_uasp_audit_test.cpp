#define _WIN32_WINNT 0x0601
#include "audit_core.h"
#include <windows.h>
#include <iostream>
#include <string>

namespace {
const wchar_t *kFixture =
    L"Software\\SecurityRemediatorTests\\UsbUaspAudit";

bool SetString(HKEY root, const std::wstring &path, const wchar_t *name,
               const wchar_t *value) {
  HKEY key = nullptr;
  DWORD disposition = 0;
  if (RegCreateKeyExW(root, path.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr,
                      &key, &disposition) != ERROR_SUCCESS)
    return false;
  const DWORD bytes =
      static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
  const bool ok = RegSetValueExW(key, name, 0, REG_SZ,
                                 reinterpret_cast<const BYTE *>(value),
                                 bytes) == ERROR_SUCCESS;
  RegCloseKey(key);
  return ok;
}

const sr::SummaryRow *FindSummary(const sr::AuditResult &result,
                                  const wchar_t *item) {
  for (const auto &row : result.summary)
    if (row.item == item)
      return &row;
  return nullptr;
}

const sr::DetailTable *FindDetails(const sr::AuditResult &result,
                                   const wchar_t *title) {
  for (const auto &table : result.details)
    if (table.title == title)
      return &table;
  return nullptr;
}
} // namespace

int wmain() {
  RegDeleteTreeW(HKEY_CURRENT_USER, kFixture);
  const std::wstring base = std::wstring(kFixture) +
                            L"\\SYSTEM\\CurrentControlSet\\Enum\\";
  const wchar_t *usbContainer = L"{90cae5b5-b014-5f9f-9837-840dfd392f85}";
  if (!SetString(HKEY_CURRENT_USER,
                 base + L"USB\\VID_1F75&PID_0917\\U391", L"ContainerID",
                 usbContainer) ||
      !SetString(HKEY_CURRENT_USER,
                 base + L"SCSI\\Disk&Ven_aigo&Prod_U391\\6&1", L"ContainerID",
                 usbContainer) ||
      !SetString(HKEY_CURRENT_USER,
                 base + L"SCSI\\Disk&Ven_aigo&Prod_U391\\6&1", L"FriendlyName",
                 L"aigo U391 SCSI Disk Device") ||
      !SetString(HKEY_CURRENT_USER,
                 base + L"SCSI\\Disk&Ven_NVMe&Prod_Internal\\0&0", L"ContainerID",
                 L"{11111111-1111-1111-1111-111111111111}") ||
      !SetString(HKEY_CURRENT_USER,
                 base + L"SCSI\\Disk&Ven_NVMe&Prod_Internal\\0&0", L"FriendlyName",
                 L"Internal Disk")) {
    std::wcerr << L"FAIL: 无法创建注册表测试夹具\n";
    return 2;
  }

  HKEY fixture = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kFixture, 0, KEY_READ, &fixture) !=
          ERROR_SUCCESS ||
      RegOverridePredefKey(HKEY_LOCAL_MACHINE, fixture) != ERROR_SUCCESS) {
    std::wcerr << L"FAIL: 无法重定向测试注册表\n";
    if (fixture)
      RegCloseKey(fixture);
    return 2;
  }

  const sr::AuditResult result = sr::RunAudit();
  RegOverridePredefKey(HKEY_LOCAL_MACHINE, nullptr);
  RegCloseKey(fixture);
  RegDeleteTreeW(HKEY_CURRENT_USER, kFixture);

  const sr::SummaryRow *summary = FindSummary(result, L"USB 存储设备记录");
  const sr::DetailTable *details =
      FindDetails(result, L"USB 存储设备注册表记录逐项明细");
  if (!summary || summary->verdict != sr::Verdict::Review ||
      summary->actual.find(L"1条") == std::wstring::npos || !details ||
      details->rows.size() != 1 || details->rows[0].size() < 3 ||
      details->rows[0][2] != L"aigo U391 SCSI Disk Device") {
    std::cerr << "FAIL: SCSI/UASP USB storage record was missed"
              << "; summary=" << (summary ? 1 : 0)
              << "; verdict="
              << (summary ? static_cast<int>(summary->verdict) : -1)
              << "; detailRows=" << (details ? details->rows.size() : 0)
              << "\n";
    return 1;
  }
  std::cout << "PASS: USB-backed SCSI/UASP storage detected; internal SCSI ignored\n";
  return 0;
}
