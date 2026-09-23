#pragma once

#include <string>
#include <vector>

namespace sr {

struct IECredential {
  std::wstring website;
  std::wstring account;
};

struct IECredentialScan {
  bool available = true;
  std::wstring error;
  std::vector<IECredential> credentials;
};

struct IEAuditContribution {
  int passed = 0;
  int failed = 0;
  int review = 0;
  std::vector<std::vector<std::wstring>> detailRows;
  std::vector<std::vector<std::wstring>> accountRows;
};

struct IECredentialCleanupResult {
  bool available = true;
  int before = 0;
  int removed = 0;
  int after = 0;
  std::wstring error;
};

IECredentialScan ParseIEVaultOutput(const std::wstring &output);
IECredentialScan ParseIECmdKeyOutput(const std::wstring &output);
std::vector<std::wstring>
SelectWinInetCredentialTargets(const std::wstring &cmdKeyOutput);
std::wstring ResolveWindowsCredentialToolPath(const wchar_t *fileName);
IECredentialScan ReadCurrentUserLegacyIEStorage();
IECredentialScan ReadCurrentUserWinInetCredentials();
IECredentialScan ReadCurrentUserIEWebCredentials();
IECredentialScan ReadCurrentUserIECredentials();
IECredentialCleanupResult CleanCurrentUserLegacyIEStorage(bool apply);
IECredentialCleanupResult CleanCurrentUserWinInetCredentials(bool apply);
IEAuditContribution EvaluateInternetExplorerAudit(
    bool installed, bool runningAsSystem, const IECredentialScan &scan);

} // namespace sr
