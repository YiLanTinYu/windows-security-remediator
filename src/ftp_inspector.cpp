#define _WIN32_WINNT 0x0601
#include "audit_core.h"
#include "system_remediation.h"
#include "workflow_report.h"
#include "win7_fs.h"
#include <windows.h>
#include <shellapi.h>
#include <wininet.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#ifndef SR_FTP_DEFAULT_SERVER
#define SR_FTP_DEFAULT_SERVER L"127.0.0.1:12221"
#endif
#ifndef SR_FTP_USER
#define SR_FTP_USER L""
#endif
#ifndef SR_FTP_PASSWORD
#define SR_FTP_PASSWORD L""
#endif

namespace {
struct Server {
  std::wstring host;
  INTERNET_PORT port = 0;
};

std::wstring ExePath() {
  std::vector<wchar_t> value(32768);
  DWORD size = GetModuleFileNameW(
      nullptr, value.data(), static_cast<DWORD>(value.size()));
  return std::wstring(value.data(), size);
}

std::wstring ExeDir() {
  return sr::win7fs::Parent(ExePath());
}

std::string Utf8(const std::wstring &value) {
  if (value.empty())
    return {};
  int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                 static_cast<int>(value.size()), nullptr, 0,
                                 nullptr, nullptr);
  std::string result(size, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(),
                      static_cast<int>(value.size()), result.data(), size,
                      nullptr, nullptr);
  return result;
}

std::wstring Utf16(const std::string &value) {
  if (value.empty())
    return {};
  int size = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                 static_cast<int>(value.size()), nullptr, 0);
  std::wstring result(size, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(),
                      static_cast<int>(value.size()), result.data(), size);
  return result;
}

std::wstring JsonQuote(const std::wstring &value) {
  std::wostringstream output;
  output << L'\"';
  for (wchar_t character : value) {
    if (character == L'\"')
      output << L"\\\"";
    else if (character == L'\\')
      output << L"\\\\";
    else if (character == L'\n')
      output << L"\\n";
    else if (character == L'\r')
      output << L"\\r";
    else if (character == L'\t')
      output << L"\\t";
    else if (character < 32)
      output << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0')
             << static_cast<int>(character) << std::dec;
    else
      output << character;
  }
  return output.str() + L"\"";
}

bool ParseServer(const std::wstring &value, Server &server) {
  const size_t colon = value.rfind(L':');
  if (colon == std::wstring::npos || colon == 0)
    return false;
  server.host = value.substr(0, colon);
  wchar_t *end = nullptr;
  long port = wcstol(value.c_str() + colon + 1, &end, 10);
  if (!end || *end || port < 1 || port > 65535 ||
      server.host.find_first_of(L"/\\?#") != std::wstring::npos)
    return false;
  server.port = static_cast<INTERNET_PORT>(port);
  return true;
}

void WriteStatus(const std::wstring &directory, const std::wstring &content) {
  const std::wstring path =
      sr::win7fs::Join(directory, L"upload-status.json");
  std::ofstream output(path.c_str(), std::ios::binary);
  const std::string bytes = Utf8(content);
  output.write("\xEF\xBB\xBF", 3);
  output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

bool PutReportFiles(const Server &server, const sr::ReportFiles &reports,
                    std::wstring &stage, DWORD &error) {
  HINTERNET internet = InternetOpenW(
      L"SecurityInspectionFtpReporter/1.0", INTERNET_OPEN_TYPE_DIRECT, nullptr,
      nullptr, 0);
  HINTERNET connection = nullptr;
  bool success = false;
  auto fail = [&](const wchar_t *value) {
    stage = value;
    error = GetLastError();
  };
  if (!internet) {
    fail(L"open-session");
    return false;
  }
  DWORD timeout = 15000;
  InternetSetOptionW(internet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout,
                     sizeof(timeout));
  InternetSetOptionW(internet, INTERNET_OPTION_SEND_TIMEOUT, &timeout,
                     sizeof(timeout));
  InternetSetOptionW(internet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout,
                     sizeof(timeout));
  connection = InternetConnectW(internet, server.host.c_str(), server.port,
                                SR_FTP_USER, SR_FTP_PASSWORD,
                                INTERNET_SERVICE_FTP,
                                INTERNET_FLAG_PASSIVE, 0);
  if (!connection) {
    fail(L"connect-or-login");
    goto done;
  }
  {
    const std::wstring htmlName = sr::win7fs::Filename(reports.htmlPath);
    const std::wstring jsonName = sr::win7fs::Filename(reports.jsonPath);
    if (!FtpPutFileW(connection, reports.htmlPath.c_str(), htmlName.c_str(),
                     FTP_TRANSFER_TYPE_BINARY, 0)) {
      fail(L"upload-html");
      goto done;
    }
    if (!FtpPutFileW(connection, reports.jsonPath.c_str(), jsonName.c_str(),
                     FTP_TRANSFER_TYPE_BINARY, 0)) {
      fail(L"upload-json");
      goto done;
    }
  }
  success = true;
done:
  if (connection)
    InternetCloseHandle(connection);
  InternetCloseHandle(internet);
  return success;
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
  int argc = 0;
  LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  std::wstring serverValue = SR_FTP_DEFAULT_SERVER;
  bool localOnly = false;
  bool auditOnly = false;
  for (int index = 1; index < argc; ++index) {
    const std::wstring argument = argv[index];
    if (argument.rfind(L"/server=", 0) == 0)
      serverValue = argument.substr(8);
    else if (argument == L"/local-only")
      localOnly = true;
    else if (argument == L"/audit-only")
      auditOnly = true;
    else {
      LocalFree(argv);
      return 2;
    }
  }
  LocalFree(argv);

  Server server;
  if ((!localOnly && (!ParseServer(serverValue, server) || !*SR_FTP_USER ||
      !*SR_FTP_PASSWORD)))
    return 2;
  try {
    const sr::AuditResult before = sr::RunAudit();
    sr::RemediationResult remediation;
    sr::AuditResult result = before;
    sr::ReportFiles reports;
    int operationExit = before.failed ? 5 : 0;
    if (auditOnly) {
      reports = sr::WriteReports(before, ExeDir());
    } else {
      remediation = sr::ApplySystemRemediation();
      result = sr::RunAudit();
      reports = sr::WriteWorkflowReports(before, remediation, result, ExeDir());
      if (!remediation.authorized) operationExit = 3;
      else operationExit = remediation.success && sr::RemediationScopeCompliant(result) ? 0 : 1;
    }
    if (localOnly) {
      WriteStatus(ExeDir(),
                  L"{\"uploaded\":false,\"transport\":\"FTP\","
                  L"\"reason\":\"local-only\",\"auditOnly\":" +
                  std::wstring(auditOnly ? L"true" : L"false") +
                  L",\"operationExit\":" + std::to_wstring(operationExit) + L"}");
      return operationExit;
    }

    bool uploaded = false;
    std::wstring failureStage;
    DWORD failureCode = 0;
    for (int attempt = 0; attempt < 3 && !uploaded; ++attempt) {
      uploaded = PutReportFiles(server, reports, failureStage, failureCode);
      if (!uploaded && attempt < 2)
        Sleep(static_cast<DWORD>((attempt + 1) * 2000));
    }
    if (uploaded) {
      WriteStatus(ExeDir(),
                  L"{\"uploaded\":true,\"transport\":\"FTP\","
                  L"\"server\":" +
                      JsonQuote(serverValue) +
                      L",\"files\":2,\"auditOnly\":" +
                      std::wstring(auditOnly ? L"true" : L"false") +
                      L",\"repairSuccess\":" +
                      std::wstring(remediation.success ? L"true" : L"false") +
                      L",\"repairChanged\":" +
                      std::wstring(remediation.changed ? L"true" : L"false") +
                      L",\"operationExit\":" + std::to_wstring(operationExit) + L"}");
      return operationExit;
    }
    WriteStatus(
        ExeDir(),
        L"{\"uploaded\":false,\"transport\":\"FTP\",\"server\":" +
            JsonQuote(serverValue) +
            L",\"reason\":\"FTP上传失败；本地报告已保留\",\"stage\":" +
            JsonQuote(failureStage) + L",\"win32\":" +
            std::to_wstring(failureCode) + L",\"auditOnly\":" +
            std::wstring(auditOnly ? L"true" : L"false") +
            L",\"repairSuccess\":" +
            std::wstring(remediation.success ? L"true" : L"false") +
            L",\"repairChanged\":" +
            std::wstring(remediation.changed ? L"true" : L"false") +
            L",\"operationExit\":" + std::to_wstring(operationExit) + L"}");
    return operationExit == 0 ? 6 : 7;
  } catch (const std::exception &error) {
    WriteStatus(ExeDir(),
                L"{\"uploaded\":false,\"transport\":\"FTP\","
                L"\"reason\":" +
                    JsonQuote(Utf16(error.what())) + L"}");
    return 1;
  }
}
