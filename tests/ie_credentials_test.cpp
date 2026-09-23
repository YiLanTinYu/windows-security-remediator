#include "ie_credentials.h"
#include <windows.h>
#include <iostream>
#include <string>

namespace {
bool Contains(const std::wstring &value, const std::wstring &part) {
  return value.find(part) != std::wstring::npos;
}

int Fail(const wchar_t *message) {
  std::wcerr << L"FAIL: " << message << L"\n";
  return 1;
}
} // namespace

int wmain() {
  const std::wstring vaultCmd =
      sr::ResolveWindowsCredentialToolPath(L"VaultCmd.exe");
  if (vaultCmd.empty() ||
      GetFileAttributesW(vaultCmd.c_str()) == INVALID_FILE_ATTRIBUTES)
    return Fail(L"VaultCmd could not be resolved for this process architecture");

  const std::wstring fixture =
      L"Credentials in vault: Web Credentials\r\n"
      L"Resource: https://intranet.example.test/login\r\n"
      L"Identity: test-user\r\n"
      L"Password: MUST-NOT-APPEAR\r\n";
  const sr::IECredentialScan parsed = sr::ParseIEVaultOutput(fixture);
  if (!parsed.available || parsed.credentials.size() != 1)
    return Fail(L"fixture was not recognized");
  if (parsed.credentials[0].website != L"https://intranet.example.test/login" ||
      parsed.credentials[0].account != L"test-user")
    return Fail(L"website or account metadata mismatch");
  if (Contains(parsed.credentials[0].website, L"MUST-NOT-APPEAR") ||
      Contains(parsed.credentials[0].account, L"MUST-NOT-APPEAR"))
    return Fail(L"password leaked into audit output");

  const std::wstring cmdKeyFixture =
      L"Target: LegacyGeneric:target=Microsoft_WinInet_https://legacy.example.test\r\n"
      L"Type: Generic\r\n"
      L"User: legacy-user\r\n"
      L"Password: MUST-NOT-APPEAR\r\n";
  const sr::IECredentialScan cmdKeyParsed =
      sr::ParseIECmdKeyOutput(cmdKeyFixture);
  if (!cmdKeyParsed.available || cmdKeyParsed.credentials.size() != 1 ||
      !Contains(cmdKeyParsed.credentials[0].website, L"Microsoft_WinInet_") ||
      cmdKeyParsed.credentials[0].account != L"legacy-user")
    return Fail(L"legacy WinInet credential was not recognized");
  if (Contains(cmdKeyParsed.credentials[0].website, L"MUST-NOT-APPEAR") ||
      Contains(cmdKeyParsed.credentials[0].account, L"MUST-NOT-APPEAR"))
    return Fail(L"legacy password leaked into audit output");

  const std::wstring mixedCmdKeyFixture =
      L"Target: LegacyGeneric:target=Microsoft_WinInet_https://ie.example.test\r\n"
      L"User: ie-user\r\n"
      L"Target: Domain:target=TERMSRV/remote.example.test\r\n"
      L"User: remote-user\r\n"
      L"Target: LegacyGeneric:target=unrelated-application\r\n"
      L"User: app-user\r\n"
      L"Target: LegacyGeneric:target=other_Microsoft_WinInet_decoy\r\n"
      L"User: decoy-user\r\n";
  const std::vector<std::wstring> cleanupTargets =
      sr::SelectWinInetCredentialTargets(mixedCmdKeyFixture);
  if (cleanupTargets.size() != 1 ||
      cleanupTargets[0] !=
          L"LegacyGeneric:target=Microsoft_WinInet_https://ie.example.test")
    return Fail(L"cleanup selection included an unrelated credential");

  const sr::IEAuditContribution userAudit =
      sr::EvaluateInternetExplorerAudit(true, false, parsed);
  if (userAudit.failed != 1 || userAudit.review != 0 ||
      userAudit.detailRows.size() != 2 || userAudit.accountRows.size() != 1)
    return Fail(L"current-user credential was not reported as abnormal");
  if (userAudit.detailRows.back().size() != 7 ||
      !Contains(userAudit.detailRows.back()[4], L"1") ||
      userAudit.detailRows.back()[5] != L"异常")
    return Fail(L"current-user conclusion or count mismatch");

  const sr::IEAuditContribution systemAudit =
      sr::EvaluateInternetExplorerAudit(true, true, parsed);
  if (systemAudit.failed != 0 || systemAudit.review != 1 ||
      systemAudit.detailRows.size() != 2 ||
      systemAudit.detailRows.back().size() != 7 ||
      systemAudit.detailRows.back()[5] != L"需复核")
    return Fail(L"SYSTEM identity was not reported for review");
  if (!Contains(systemAudit.detailRows.back()[4], L"SYSTEM"))
    return Fail(L"SYSTEM limitation missing from report");

  std::wcout << L"PASS: IE Web 凭据元数据检测和 SYSTEM 需复核语义正确\n";
  return 0;
}
