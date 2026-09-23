#define _WIN32_WINNT 0x0601
#include "ie_credentials.h"

#include <windows.h>
#include <algorithm>
#include <cwctype>
#include <set>
#include <sstream>

namespace sr {
namespace {
constexpr wchar_t kWebVaultGuid[] =
    L"4BF4C442-9B8A-41A0-B380-DD4A704DDB28";

std::wstring Trim(const std::wstring &value) {
  const auto first = std::find_if_not(value.begin(), value.end(), iswspace);
  if (first == value.end())
    return {};
  const auto last = std::find_if_not(value.rbegin(), value.rend(), iswspace);
  return std::wstring(first, last.base());
}

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), towlower);
  return value;
}

bool StartsWith(const std::wstring &value, const std::wstring &prefix) {
  return value.size() >= prefix.size() &&
         std::equal(prefix.begin(), prefix.end(), value.begin());
}

std::wstring ValueAfterLabel(const std::wstring &line,
                             const std::vector<std::wstring> &labels) {
  const std::wstring lower = Lower(line);
  for (const auto &label : labels) {
    if (StartsWith(lower, Lower(label)))
      return Trim(line.substr(label.size()));
  }
  return {};
}

std::wstring DecodeOutput(const std::vector<unsigned char> &bytes) {
  if (bytes.empty())
    return {};
  if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) {
    const size_t count = (bytes.size() - 2) / sizeof(wchar_t);
    return std::wstring(
        reinterpret_cast<const wchar_t *>(bytes.data() + 2), count);
  }
  const int size = MultiByteToWideChar(
      CP_OEMCP, 0, reinterpret_cast<const char *>(bytes.data()),
      static_cast<int>(bytes.size()), nullptr, 0);
  if (size <= 0)
    return {};
  std::wstring output(static_cast<size_t>(size), L'\0');
  MultiByteToWideChar(CP_OEMCP, 0,
                      reinterpret_cast<const char *>(bytes.data()),
                      static_cast<int>(bytes.size()), output.data(), size);
  return output;
}

bool Capture(const std::wstring &application, const std::wstring &arguments,
             std::wstring &output, std::wstring &error) {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE readPipe = nullptr;
  HANDLE writePipe = nullptr;
  if (!CreatePipe(&readPipe, &writePipe, &security, 0)) {
    error = L"无法创建凭据检查管道";
    return false;
  }
  SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  startup.hStdOutput = writePipe;
  startup.hStdError = writePipe;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION process{};
  std::wstring command = L"\"" + application + L"\" " + arguments;
  std::vector<wchar_t> mutableCommand(command.begin(), command.end());
  mutableCommand.push_back(L'\0');
  const BOOL started = CreateProcessW(
      application.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  CloseHandle(writePipe);
  if (!started) {
    CloseHandle(readPipe);
    error = L"无法启动 Windows 凭据检查工具，错误码 " +
            std::to_wstring(GetLastError());
    return false;
  }

  std::vector<unsigned char> bytes;
  unsigned char buffer[4096];
  DWORD read = 0;
  while (ReadFile(readPipe, buffer, sizeof(buffer), &read, nullptr) && read)
    bytes.insert(bytes.end(), buffer, buffer + read);
  CloseHandle(readPipe);
  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exitCode = 0;
  GetExitCodeProcess(process.hProcess, &exitCode);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  output = DecodeOutput(bytes);
  if (exitCode != 0) {
    error = L"Windows 凭据检查工具执行失败，退出码 " +
            std::to_wstring(exitCode);
    return false;
  }
  return true;
}

void AddUnique(std::vector<IECredential> &credentials, std::wstring website,
               std::wstring account) {
  if (website.empty())
    website = L"未记录网站地址";
  if (account.empty())
    account = L"未记录账号";
  const auto duplicate = std::find_if(
      credentials.begin(), credentials.end(), [&](const IECredential &item) {
        return item.website == website && item.account == account;
      });
  if (duplicate == credentials.end())
    credentials.push_back({std::move(website), std::move(account)});
}

bool ReadLegacyStorage(std::vector<IECredential> &credentials,
                       std::wstring &error) {
  HKEY key = nullptr;
  const LONG opened = RegOpenKeyExW(
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2", 0,
      KEY_QUERY_VALUE, &key);
  if (opened == ERROR_FILE_NOT_FOUND)
    return true;
  if (opened != ERROR_SUCCESS) {
    error = L"无法读取当前用户 IE Storage2，错误码 " +
            std::to_wstring(opened);
    return false;
  }
  DWORD valueCount = 0;
  const LONG queried = RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr,
                                       nullptr, nullptr, &valueCount, nullptr,
                                       nullptr, nullptr, nullptr);
  RegCloseKey(key);
  if (queried != ERROR_SUCCESS) {
    error = L"无法统计当前用户 IE Storage2，错误码 " +
            std::to_wstring(queried);
    return false;
  }
  for (DWORD i = 0; i < valueCount; ++i)
    credentials.push_back(
        {L"旧版 IE 保存密码索引 " + std::to_wstring(i + 1),
         L"请在凭据管理器中查看"});
  return true;
}

std::vector<std::wstring> ReadLegacyStorageValueNames(LONG &status) {
  std::vector<std::wstring> names;
  HKEY key = nullptr;
  status = RegOpenKeyExW(
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2", 0,
      KEY_QUERY_VALUE, &key);
  if (status == ERROR_FILE_NOT_FOUND) {
    status = ERROR_SUCCESS;
    return names;
  }
  if (status != ERROR_SUCCESS)
    return names;

  DWORD maxNameLength = 0;
  status = RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr,
                            nullptr, nullptr, &maxNameLength, nullptr, nullptr,
                            nullptr);
  if (status != ERROR_SUCCESS) {
    RegCloseKey(key);
    return names;
  }
  std::vector<wchar_t> name(static_cast<size_t>(maxNameLength) + 2, L'\0');
  for (DWORD index = 0;; ++index) {
    DWORD length = static_cast<DWORD>(name.size());
    const LONG enumerated =
        RegEnumValueW(key, index, name.data(), &length, nullptr, nullptr,
                      nullptr, nullptr);
    if (enumerated == ERROR_NO_MORE_ITEMS)
      break;
    if (enumerated != ERROR_SUCCESS) {
      status = enumerated;
      names.clear();
      break;
    }
    names.emplace_back(name.data(), length);
  }
  RegCloseKey(key);
  return names;
}

bool IsSafeWinInetTarget(const std::wstring &target) {
  const std::wstring lower = Lower(target);
  return (StartsWith(lower, L"microsoft_wininet_") ||
          StartsWith(lower,
                     L"legacygeneric:target=microsoft_wininet_")) &&
         target.find_first_of(L"\"\r\n") == std::wstring::npos;
}
} // namespace

std::wstring ResolveWindowsCredentialToolPath(const wchar_t *fileName) {
  if (!fileName || !*fileName)
    return {};

  wchar_t systemDirectory[MAX_PATH]{};
  if (GetSystemDirectoryW(systemDirectory, MAX_PATH)) {
    const std::wstring candidate =
        std::wstring(systemDirectory) + L"\\" + fileName;
    if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
      return candidate;
  }

  // A 32-bit process on 64-bit Windows is redirected from System32 to
  // SysWOW64. VaultCmd.exe is not present in SysWOW64 on every supported
  // system, so use the documented Sysnative alias as the fallback.
  wchar_t windowsDirectory[MAX_PATH]{};
  if (GetWindowsDirectoryW(windowsDirectory, MAX_PATH)) {
    const std::wstring candidate =
        std::wstring(windowsDirectory) + L"\\Sysnative\\" + fileName;
    if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
      return candidate;
  }
  return {};
}

IECredentialScan ParseIEVaultOutput(const std::wstring &output) {
  IECredentialScan result;
  std::wistringstream input(output);
  std::wstring line;
  std::wstring website;
  std::wstring account;
  const std::vector<std::wstring> resourceLabels = {L"resource:", L"资源:",
                                                     L"资源："};
  const std::vector<std::wstring> identityLabels = {
      L"identity:", L"标识:", L"标识：", L"用户名:", L"用户名："};
  while (std::getline(input, line)) {
    line = Trim(line);
    const std::wstring resource = ValueAfterLabel(line, resourceLabels);
    if (!resource.empty()) {
      if (!website.empty())
        AddUnique(result.credentials, website, account);
      website = resource;
      account.clear();
      continue;
    }
    const std::wstring identity = ValueAfterLabel(line, identityLabels);
    if (!identity.empty() && !website.empty())
      account = identity;
  }
  if (!website.empty())
    AddUnique(result.credentials, website, account);
  return result;
}

IECredentialScan ParseIECmdKeyOutput(const std::wstring &output) {
  IECredentialScan result;
  std::wistringstream input(output);
  std::wstring line;
  std::wstring target;
  std::wstring account;
  const std::vector<std::wstring> targetLabels = {L"target:", L"目标:",
                                                   L"目标："};
  const std::vector<std::wstring> userLabels = {L"user:", L"用户:",
                                                 L"用户："};
  while (std::getline(input, line)) {
    line = Trim(line);
    const std::wstring nextTarget = ValueAfterLabel(line, targetLabels);
    if (!nextTarget.empty()) {
      if (!target.empty())
        AddUnique(result.credentials, target, account);
      target = IsSafeWinInetTarget(nextTarget) ? nextTarget : L"";
      account.clear();
      continue;
    }
    const std::wstring user = ValueAfterLabel(line, userLabels);
    if (!user.empty() && !target.empty())
      account = user;
  }
  if (!target.empty())
    AddUnique(result.credentials, target, account);
  return result;
}

std::vector<std::wstring>
SelectWinInetCredentialTargets(const std::wstring &cmdKeyOutput) {
  std::vector<std::wstring> targets;
  const IECredentialScan parsed = ParseIECmdKeyOutput(cmdKeyOutput);
  for (const auto &credential : parsed.credentials) {
    if (IsSafeWinInetTarget(credential.website))
      targets.push_back(credential.website);
  }
  return targets;
}

IECredentialScan ReadCurrentUserLegacyIEStorage() {
  IECredentialScan result;
  if (!ReadLegacyStorage(result.credentials, result.error))
    result.available = false;
  return result;
}

IECredentialScan ReadCurrentUserWinInetCredentials() {
  IECredentialScan result;
  const std::wstring cmdKey = ResolveWindowsCredentialToolPath(L"cmdkey.exe");
  std::wstring output;
  if (cmdKey.empty() || !Capture(cmdKey, L"/list", output, result.error)) {
    result.available = false;
    if (result.error.empty())
      result.error = L"系统中没有 cmdkey.exe，无法检查旧版 IE/WinInet 凭据";
    return result;
  }
  result = ParseIECmdKeyOutput(output);
  return result;
}

IECredentialScan ReadCurrentUserIEWebCredentials() {
  IECredentialScan result;
  const std::wstring vaultCmd = ResolveWindowsCredentialToolPath(L"VaultCmd.exe");
  if (vaultCmd.empty()) {
    result.available = false;
    result.error = L"系统中没有 VaultCmd.exe，无法检查 IE Web 凭据";
    return result;
  }
  std::wstring vaultList;
  if (!Capture(vaultCmd, L"/list", vaultList, result.error)) {
    result.available = false;
    return result;
  }
  if (Lower(vaultList).find(Lower(kWebVaultGuid)) == std::wstring::npos)
    return result;

  std::wstring credentialList;
  if (!Capture(vaultCmd,
               std::wstring(L"/listcreds:") + kWebVaultGuid + L" /all",
               credentialList, result.error)) {
    result.available = false;
    return result;
  }
  return ParseIEVaultOutput(credentialList);
}

IECredentialScan ReadCurrentUserIECredentials() {
  IECredentialScan result;
  for (const auto &source : {ReadCurrentUserLegacyIEStorage(),
                             ReadCurrentUserWinInetCredentials(),
                             ReadCurrentUserIEWebCredentials()}) {
    if (!source.available) {
      result.available = false;
      result.error = source.error;
      return result;
    }
    for (const auto &credential : source.credentials)
      AddUnique(result.credentials, credential.website, credential.account);
  }
  return result;
}

IECredentialCleanupResult CleanCurrentUserLegacyIEStorage(bool apply) {
  IECredentialCleanupResult result;
  LONG status = ERROR_SUCCESS;
  const std::vector<std::wstring> names = ReadLegacyStorageValueNames(status);
  if (status != ERROR_SUCCESS) {
    result.available = false;
    result.error = L"无法读取当前用户 IE Storage2，错误码 " +
                   std::to_wstring(status);
    return result;
  }
  result.before = static_cast<int>(names.size());
  if (apply && !names.empty()) {
    HKEY key = nullptr;
    status = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2", 0,
        KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (status != ERROR_SUCCESS) {
      result.available = false;
      result.error = L"无法打开当前用户 IE Storage2 进行清理，错误码 " +
                     std::to_wstring(status);
      return result;
    }
    for (const auto &name : names) {
      if (RegDeleteValueW(key, name.c_str()) == ERROR_SUCCESS)
        ++result.removed;
    }
    RegCloseKey(key);
  }
  const std::vector<std::wstring> remaining =
      ReadLegacyStorageValueNames(status);
  if (status != ERROR_SUCCESS) {
    result.available = false;
    result.error = L"清理后无法复读当前用户 IE Storage2，错误码 " +
                   std::to_wstring(status);
    return result;
  }
  result.after = static_cast<int>(remaining.size());
  return result;
}

IECredentialCleanupResult CleanCurrentUserWinInetCredentials(bool apply) {
  IECredentialCleanupResult result;
  const IECredentialScan before = ReadCurrentUserWinInetCredentials();
  if (!before.available) {
    result.available = false;
    result.error = before.error;
    return result;
  }
  result.before = static_cast<int>(before.credentials.size());
  if (apply) {
    const std::wstring cmdKey = ResolveWindowsCredentialToolPath(L"cmdkey.exe");
    for (const auto &credential : before.credentials) {
      if (!IsSafeWinInetTarget(credential.website))
        continue;
      std::wstring ignored;
      std::wstring error;
      if (Capture(cmdKey, L"/delete:\"" + credential.website + L"\"",
                  ignored, error))
        ++result.removed;
      else if (result.error.empty())
        result.error = error;
    }
  }
  const IECredentialScan after = ReadCurrentUserWinInetCredentials();
  if (!after.available) {
    result.available = false;
    result.error = after.error;
    return result;
  }
  result.after = static_cast<int>(after.credentials.size());
  if (!result.error.empty())
    result.available = false;
  return result;
}

IEAuditContribution EvaluateInternetExplorerAudit(
    bool installed, bool runningAsSystem, const IECredentialScan &scan) {
  IEAuditContribution result;
  result.detailRows.push_back(
      {L"本机", L"Internet Explorer", L"安装状态", L"仅记录",
       installed ? L"已安装" : L"未安装",
       installed ? L"已识别" : L"不适用",
       installed ? L"发现程序文件" : L"未发现程序文件"});
  if (!installed)
    return result;

  if (runningAsSystem) {
    result.detailRows.push_back(
        {L"登录用户", L"Internet Explorer", L"已保存密码",
         L"没有保存密码", L"SYSTEM 无法检查登录用户凭据", L"需复核",
         L"请由用户本人运行现场检查版"});
    result.review = 1;
    return result;
  }
  if (!scan.available) {
    result.detailRows.push_back(
        {L"当前用户", L"Internet Explorer", L"已保存密码",
         L"没有保存密码", L"读取失败", L"需复核",
         scan.error.empty() ? L"凭据存储无法读取" : scan.error});
    result.review = 1;
    return result;
  }
  if (scan.credentials.empty()) {
    result.detailRows.push_back(
        {L"当前用户", L"Internet Explorer", L"已保存密码",
         L"没有保存密码", L"未发现保存密码（0条）", L"通过",
         L"只读取网站和账号元数据，不读取或解密密码"});
    result.passed = 1;
    return result;
  }

  for (const auto &credential : scan.credentials)
    result.accountRows.push_back(
        {L"当前用户", L"Internet Explorer", L"Web 凭据",
         credential.website.empty() ? L"未记录网站地址" : credential.website,
         credential.account.empty() ? L"未记录账号" : credential.account});
  result.detailRows.push_back(
      {L"当前用户", L"Internet Explorer", L"已保存密码",
       L"没有保存密码",
       L"发现保存密码（" + std::to_wstring(scan.credentials.size()) + L"条）",
       L"异常", L"网站和账号见下方明细；未读取或解密密码"});
  result.failed = 1;
  return result;
}

} // namespace sr
