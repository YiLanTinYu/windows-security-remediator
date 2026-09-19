#define _WIN32_WINNT 0x0601
#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <cwctype>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {
struct ReportFile {
  std::wstring name;
  std::wstring path;
  std::wstring group;
  std::wstring timestamp;
  bool html = false;
};

struct ReportBatch {
  bool html = false;
  bool json = false;
};

std::wstring Join(const std::wstring &left, const std::wstring &right) {
  if (left.empty() || left.back() == L'\\')
    return left + right;
  return left + L"\\" + right;
}

std::wstring ExeDirectory() {
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                          static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size())
    return L".";
  std::wstring path(buffer.data(), length);
  const size_t slash = path.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"." : path.substr(0, slash);
}

bool EqualsNoCase(const std::wstring &a, const wchar_t *b) {
  const size_t length = wcslen(b);
  if (a.size() != length)
    return false;
  for (size_t i = 0; i < length; ++i)
    if (towlower(a[i]) != towlower(b[i]))
      return false;
  return true;
}

bool ValidTimestamp(const std::wstring &value) {
  if (value.size() != 19 || value[8] != L'-' || value[15] != L'-')
    return false;
  for (size_t i = 0; i < value.size(); ++i)
    if (i != 8 && i != 15 && !iswdigit(value[i]))
      return false;
  return true;
}

bool ParseReportName(const std::wstring &name, ReportFile &report) {
  const size_t dot = name.find_last_of(L'.');
  if (dot == std::wstring::npos)
    return false;
  const std::wstring extension = name.substr(dot + 1);
  if (!EqualsNoCase(extension, L"html") && !EqualsNoCase(extension, L"json"))
    return false;

  const std::wstring stem = name.substr(0, dot);
  const std::wstring windowsPrefix = L"verification-report_";
  const std::wstring legacyKylinPrefix = L"kylin-report_";
  size_t prefixLength = 0;
  if (stem.compare(0, windowsPrefix.size(), windowsPrefix) == 0)
    prefixLength = windowsPrefix.size();
  else if (stem.compare(0, legacyKylinPrefix.size(), legacyKylinPrefix) == 0)
    prefixLength = legacyKylinPrefix.size();
  else
    return false;
  const size_t separator = stem.find_last_of(L'_');
  if (separator == std::wstring::npos || separator <= prefixLength)
    return false;
  const std::wstring timestamp = stem.substr(separator + 1);
  if (!ValidTimestamp(timestamp))
    return false;

  report.name = name;
  report.group = stem.substr(0, separator);
  report.timestamp = timestamp;
  report.html = EqualsNoCase(extension, L"html");
  return true;
}

std::vector<ReportFile> FindReports(const std::wstring &directory) {
  std::vector<ReportFile> reports;
  WIN32_FIND_DATAW data{};
  HANDLE find = FindFirstFileW(Join(directory, L"*").c_str(), &data);
  if (find == INVALID_HANDLE_VALUE)
    return reports;
  do {
    if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
      continue;
    ReportFile report;
    if (ParseReportName(data.cFileName, report)) {
      report.path = Join(directory, report.name);
      reports.push_back(report);
    }
  } while (FindNextFileW(find, &data));
  FindClose(find);
  return reports;
}

std::string Utf8(const std::wstring &value) {
  if (value.empty())
    return {};
  const int length = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr,
                                         0, nullptr, nullptr);
  std::string output(static_cast<size_t>(length), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      &output[0], length, nullptr, nullptr);
  return output;
}

bool WriteLog(const std::wstring &directory, const std::wstring &content) {
  const std::wstring path = Join(directory, L"report-cleanup.log");
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE)
    return false;
  const std::string utf8 = Utf8(content);
  const BYTE bom[] = {0xEF, 0xBB, 0xBF};
  DWORD written = 0;
  bool ok = WriteFile(file, bom, sizeof(bom), &written, nullptr) != FALSE;
  if (ok && !utf8.empty())
    ok = WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written,
                   nullptr) != FALSE;
  CloseHandle(file);
  return ok;
}

std::wstring Now() {
  SYSTEMTIME time{};
  GetLocalTime(&time);
  wchar_t value[64]{};
  swprintf_s(value, L"%04u-%02u-%02u %02u:%02u:%02u", time.wYear,
             time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
  return value;
}
} // namespace

int wmain(int argc, wchar_t **argv) {
  _setmode(_fileno(stdout), _O_U16TEXT);
  _setmode(_fileno(stderr), _O_U16TEXT);

  bool preview = false;
  if (argc == 2 && EqualsNoCase(argv[1], L"/preview"))
    preview = true;
  else if (argc != 1) {
    std::wcerr << L"参数错误。直接运行执行清理，/preview 仅预览。\n";
    return 2;
  }

  const std::wstring directory = ExeDirectory();
  std::vector<ReportFile> reports = FindReports(directory);
  std::map<std::wstring, ReportBatch> batches;
  for (const auto &report : reports) {
    auto &batch = batches[report.group + L"|" + report.timestamp];
    if (report.html)
      batch.html = true;
    else
      batch.json = true;
  }
  std::map<std::wstring, std::wstring> newest;
  for (const auto &report : reports) {
    const ReportBatch &batch = batches[report.group + L"|" + report.timestamp];
    if (!batch.html || !batch.json)
      continue;
    auto &stamp = newest[report.group];
    if (stamp.empty() || report.timestamp > stamp)
      stamp = report.timestamp;
  }

  std::vector<const ReportFile *> kept;
  std::vector<const ReportFile *> incomplete;
  std::vector<const ReportFile *> obsolete;
  for (const auto &report : reports) {
    const ReportBatch &batch = batches[report.group + L"|" + report.timestamp];
    if (!batch.html || !batch.json)
      incomplete.push_back(&report);
    else if (report.timestamp == newest[report.group])
      kept.push_back(&report);
    else
      obsolete.push_back(&report);
  }
  const auto byName = [](const ReportFile *a, const ReportFile *b) {
    return a->name < b->name;
  };
  std::sort(kept.begin(), kept.end(), byName);
  std::sort(incomplete.begin(), incomplete.end(), byName);
  std::sort(obsolete.begin(), obsolete.end(), byName);

  std::wcout << L"FTP 报告整理工具\n"
             << L"处理目录：" << directory << L"\n"
             << L"识别终端：" << newest.size() << L" 个\n"
             << L"保留文件：" << kept.size() << L" 个\n"
             << L"保留不完整报告文件：" << incomplete.size() << L" 个\n"
             << L"待删除旧文件：" << obsolete.size() << L" 个\n\n";
  std::wcout << L"【保留的最新报告】\n";
  for (const auto *report : kept)
    std::wcout << L"保留  " << report->name << L"\n";
  for (const auto *report : incomplete)
    std::wcout << L"保留（不完整报告）  " << report->name << L"\n";
  std::wcout << L"\n【准备删除的旧报告】\n";
  for (const auto *report : obsolete)
    std::wcout << L"删除  " << report->name << L"\n";
  if (obsolete.empty())
    std::wcout << L"没有需要删除的重复报告。\n";

  std::wstring log = L"FTP 报告整理日志\r\n整理时间：" + Now() +
                     L"\r\n处理目录：" + directory + L"\r\n识别终端：" +
                     std::to_wstring(newest.size()) + L" 个\r\n保留文件：" +
                     std::to_wstring(kept.size()) + L" 个\r\n待删除旧文件：" +
                     std::to_wstring(obsolete.size()) + L" 个\r\n\r\n";
  for (const auto *report : kept)
    log += L"保留：" + report->name + L"\r\n";
  for (const auto *report : incomplete)
    log += L"保留（不完整报告，不参与去重）：" + report->name + L"\r\n";
  for (const auto *report : obsolete)
    log += L"待删除：" + report->name + L"\r\n";

  if (preview) {
    log += L"\r\n结果：仅预览，没有删除文件。\r\n";
    WriteLog(directory, log);
    return 0;
  }
  if (obsolete.empty()) {
    log += L"\r\n结果：没有重复报告，无需清理。\r\n";
    WriteLog(directory, log);
    return 0;
  }

  std::wcout << L"\n确认删除以上旧报告请输入 yes：";
  std::string confirmation;
  std::getline(std::cin, confirmation);
  if (confirmation != "yes") {
    std::wcout << L"已取消，没有删除文件。\n";
    log += L"\r\n结果：用户取消，没有删除文件。\r\n";
    WriteLog(directory, log);
    return 0;
  }

  size_t deleted = 0;
  size_t failed = 0;
  log += L"\r\n【执行结果】\r\n";
  for (const auto *report : obsolete) {
    if (DeleteFileW(report->path.c_str())) {
      ++deleted;
      log += L"已删除：" + report->name + L"\r\n";
    } else {
      ++failed;
      log += L"删除失败：" + report->name + L"，错误码 " +
             std::to_wstring(GetLastError()) + L"\r\n";
    }
  }
  log += L"删除成功：" + std::to_wstring(deleted) + L" 个；删除失败：" +
         std::to_wstring(failed) + L" 个。\r\n";
  const bool logged = WriteLog(directory, log);
  std::wcout << L"\n整理完成：成功删除 " << deleted << L" 个，失败 " << failed
             << L" 个。\n日志：" << Join(directory, L"report-cleanup.log")
             << L"\n";
  if (!logged)
    std::wcerr << L"警告：无法写入清理日志。\n";
  return failed == 0 && logged ? 0 : 1;
}
