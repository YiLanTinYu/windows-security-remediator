#define _WIN32_WINNT 0x0601
#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {
struct Json {
  enum class Type { Null, String, Object, Array, Other } type = Type::Null;
  std::wstring text;
  std::map<std::wstring, Json> object;
  std::vector<Json> array;
};

class JsonParser {
public:
  explicit JsonParser(const std::wstring &input) : input_(input) {}
  bool Parse(Json &value) {
    Skip();
    if (!Value(value)) return false;
    Skip();
    return pos_ == input_.size();
  }

private:
  const std::wstring &input_;
  size_t pos_ = 0;

  void Skip() {
    while (pos_ < input_.size() && iswspace(input_[pos_])) ++pos_;
  }
  bool Take(wchar_t c) {
    Skip();
    if (pos_ >= input_.size() || input_[pos_] != c) return false;
    ++pos_;
    return true;
  }
  bool Hex4(uint32_t &value) {
    value = 0;
    for (int i = 0; i < 4; ++i) {
      if (pos_ >= input_.size()) return false;
      const wchar_t c = input_[pos_++];
      value <<= 4;
      if (c >= L'0' && c <= L'9') value += c - L'0';
      else if (c >= L'a' && c <= L'f') value += c - L'a' + 10;
      else if (c >= L'A' && c <= L'F') value += c - L'A' + 10;
      else return false;
    }
    return true;
  }
  bool String(std::wstring &value) {
    Skip();
    if (pos_ >= input_.size() || input_[pos_++] != L'"') return false;
    value.clear();
    while (pos_ < input_.size()) {
      wchar_t c = input_[pos_++];
      if (c == L'"') return true;
      if (c != L'\\') { value += c; continue; }
      if (pos_ >= input_.size()) return false;
      c = input_[pos_++];
      switch (c) {
      case L'"': value += L'"'; break;
      case L'\\': value += L'\\'; break;
      case L'/': value += L'/'; break;
      case L'b': value += L'\b'; break;
      case L'f': value += L'\f'; break;
      case L'n': value += L'\n'; break;
      case L'r': value += L'\r'; break;
      case L't': value += L'\t'; break;
      case L'u': {
        uint32_t code = 0;
        if (!Hex4(code)) return false;
        value += static_cast<wchar_t>(code);
        break;
      }
      default: return false;
      }
    }
    return false;
  }
  bool Value(Json &value) {
    Skip();
    if (pos_ >= input_.size()) return false;
    if (input_[pos_] == L'"') {
      value.type = Json::Type::String;
      return String(value.text);
    }
    if (input_[pos_] == L'{') return Object(value);
    if (input_[pos_] == L'[') return Array(value);
    const size_t start = pos_;
    while (pos_ < input_.size() && input_[pos_] != L',' &&
           input_[pos_] != L'}' && input_[pos_] != L']' &&
           !iswspace(input_[pos_])) ++pos_;
    if (pos_ == start) return false;
    value.type = Json::Type::Other;
    value.text = input_.substr(start, pos_ - start);
    return true;
  }
  bool Object(Json &value) {
    if (!Take(L'{')) return false;
    value.type = Json::Type::Object;
    Skip();
    if (Take(L'}')) return true;
    for (;;) {
      std::wstring key;
      Json child;
      if (!String(key) || !Take(L':') || !Value(child)) return false;
      value.object[key] = std::move(child);
      Skip();
      if (Take(L'}')) return true;
      if (!Take(L',')) return false;
    }
  }
  bool Array(Json &value) {
    if (!Take(L'[')) return false;
    value.type = Json::Type::Array;
    Skip();
    if (Take(L']')) return true;
    for (;;) {
      Json child;
      if (!Value(child)) return false;
      value.array.push_back(std::move(child));
      Skip();
      if (Take(L']')) return true;
      if (!Take(L',')) return false;
    }
  }
};

struct Report {
  std::wstring source;
  std::wstring stamp;
  std::wstring ip;
  std::wstring mac;
  std::wstring computer;
  std::wstring finished;
  std::vector<std::wstring> issues;
  std::vector<std::wstring> issueItems;
  std::vector<std::wstring> reviews;
};

std::wstring Join(const std::wstring &a, const std::wstring &b) {
  return a.empty() || a.back() == L'\\' ? a + b : a + L"\\" + b;
}
std::wstring ExeDir() {
  std::vector<wchar_t> path(32768);
  DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (!n || n >= path.size()) return L".";
  std::wstring value(path.data(), n);
  const size_t slash = value.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"." : value.substr(0, slash);
}
std::string Utf8(const std::wstring &value) {
  if (value.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), &out[0], n, nullptr, nullptr);
  return out;
}
bool ReadUtf8(const std::wstring &path, std::wstring &value) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 64 * 1024 * 1024) {
    CloseHandle(file); return false;
  }
  std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
  DWORD read = 0;
  bool ok = bytes.empty() || ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &read, nullptr);
  CloseHandle(file);
  if (!ok || read != bytes.size()) return false;
  size_t offset = bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xEF &&
                  static_cast<unsigned char>(bytes[1]) == 0xBB && static_cast<unsigned char>(bytes[2]) == 0xBF ? 3 : 0;
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data() + offset,
                              static_cast<int>(bytes.size() - offset), nullptr, 0);
  if (!n && bytes.size() != offset) return false;
  value.assign(static_cast<size_t>(n), L'\0');
  if (n) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data() + offset,
                             static_cast<int>(bytes.size() - offset), &value[0], n);
  return true;
}
const Json *Field(const Json &object, const wchar_t *name) {
  auto it = object.object.find(name);
  return it == object.object.end() ? nullptr : &it->second;
}
std::wstring Text(const Json &object, const wchar_t *name) {
  const Json *value = Field(object, name);
  return value && value->type == Json::Type::String ? value->text : L"";
}
bool ValidStamp(const std::wstring &stamp) {
  if (stamp.size() != 19 || stamp[8] != L'-' || stamp[15] != L'-') return false;
  for (size_t i = 0; i < stamp.size(); ++i)
    if (i != 8 && i != 15 && !iswdigit(stamp[i])) return false;
  return true;
}
bool ReportFilename(const std::wstring &name, std::wstring &stamp) {
  const std::wstring prefix = L"verification-report_", suffix = L".json";
  if (name.size() <= prefix.size() + suffix.size() || name.compare(0, prefix.size(), prefix) != 0 ||
      _wcsicmp(name.substr(name.size() - suffix.size()).c_str(), suffix.c_str()) != 0) return false;
  std::wstring stem = name.substr(0, name.size() - suffix.size());
  size_t split = stem.find_last_of(L'_');
  if (split == std::wstring::npos) return false;
  stamp = stem.substr(split + 1);
  return ValidStamp(stamp);
}
std::wstring ProblemText(size_t number, const Json &row) {
  std::wstring item = Text(row, L"item"), actual = Text(row, L"actual"), expected = Text(row, L"expected");
  std::wstring line = std::to_wstring(number) + L". " + (item.empty() ? L"未命名项目" : item);
  if (!actual.empty()) line += L"：" + actual;
  if (!expected.empty()) line += L"（预期：" + expected + L"）";
  return line;
}
bool LoadReport(const std::wstring &path, const std::wstring &name, const std::wstring &stamp, Report &report) {
  std::wstring content;
  Json root;
  if (!ReadUtf8(path, content) || !JsonParser(content).Parse(root) || root.type != Json::Type::Object) return false;
  report.ip = Text(root, L"ip");
  report.mac = Text(root, L"mac");
  report.computer = Text(root, L"computer");
  report.finished = Text(root, L"finished");
  report.source = name;
  report.stamp = stamp;
  const Json *summary = Field(root, L"summary");
  if (report.ip.empty() || !summary || summary->type != Json::Type::Array) return false;
  for (const Json &row : summary->array) {
    if (row.type != Json::Type::Object) continue;
    std::wstring conclusion = Text(row, L"conclusion");
    std::transform(conclusion.begin(), conclusion.end(), conclusion.begin(), towlower);
    if (conclusion == L"异常" || conclusion == L"fail") {
      report.issues.push_back(ProblemText(report.issues.size() + 1, row));
      std::wstring item = Text(row, L"item");
      report.issueItems.push_back(item.empty() ? L"未命名项目" : item);
    } else if (conclusion == L"需复核" || conclusion == L"review")
      report.reviews.push_back(ProblemText(report.reviews.size() + 1, row));
  }
  return true;
}
std::vector<Report> LatestReports(const std::wstring &directory, size_t &invalid) {
  std::map<std::wstring, Report> latest;
  invalid = 0;
  WIN32_FIND_DATAW data{};
  HANDLE find = FindFirstFileW(Join(directory, L"verification-report_*.json").c_str(), &data);
  if (find == INVALID_HANDLE_VALUE) return {};
  do {
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    std::wstring stamp;
    if (!ReportFilename(data.cFileName, stamp)) { ++invalid; continue; }
    Report report;
    if (!LoadReport(Join(directory, data.cFileName), data.cFileName, stamp, report)) { ++invalid; continue; }
    auto it = latest.find(report.ip);
    if (it == latest.end() || report.stamp > it->second.stamp) latest[report.ip] = std::move(report);
  } while (FindNextFileW(find, &data));
  FindClose(find);
  std::vector<Report> reports;
  for (auto &entry : latest) reports.push_back(std::move(entry.second));
  return reports;
}

std::string Xml(const std::wstring &value) {
  std::string text = Utf8(value), out;
  for (char c : text) {
    switch (c) {
    case '&': out += "&amp;"; break;
    case '<': out += "&lt;"; break;
    case '>': out += "&gt;"; break;
    case '"': out += "&quot;"; break;
    default: out += c;
    }
  }
  return out;
}
std::wstring Lines(const std::vector<std::wstring> &items) {
  if (items.empty()) return L"无";
  std::wstring value;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i) value += L"\n";
    value += items[i];
  }
  return value;
}
std::string Cell(const char *ref, const std::wstring &value, int style) {
  return "<c r=\"" + std::string(ref) + "\" s=\"" + std::to_string(style) +
         "\" t=\"inlineStr\"><is><t xml:space=\"preserve\">" + Xml(value) + "</t></is></c>";
}
std::string NumberCell(const char *ref, size_t value, int style) {
  return "<c r=\"" + std::string(ref) + "\" s=\"" + std::to_string(style) +
         "\"><v>" + std::to_string(value) + "</v></c>";
}
bool IsHighRiskItem(const std::wstring &item) {
  return item == L"Server 文件共享服务" || item == L"远程桌面服务" ||
         item == L"远程桌面连接策略" || item == L"Windows 防火墙配置文件" ||
         item == L"NetBIOS 配置汇总" || item.compare(0, 6, L"防火墙规则 ") == 0;
}
std::string SheetXml(const std::vector<Report> &reports, size_t invalid) {
  std::string x = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
    "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
    "<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"4\" topLeftCell=\"A5\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>"
    "<sheetFormatPr defaultRowHeight=\"18\"/>"
    "<cols><col min=\"1\" max=\"1\" width=\"16\" customWidth=\"1\"/><col min=\"2\" max=\"2\" width=\"20\" customWidth=\"1\"/>"
    "<col min=\"3\" max=\"3\" width=\"32\" customWidth=\"1\"/><col min=\"4\" max=\"4\" width=\"21\" customWidth=\"1\"/>"
    "<col min=\"5\" max=\"7\" width=\"12\" customWidth=\"1\"/><col min=\"8\" max=\"9\" width=\"55\" customWidth=\"1\"/>"
    "<col min=\"10\" max=\"10\" width=\"48\" customWidth=\"1\"/></cols><sheetData>";
  x += "<row r=\"1\" ht=\"26\" customHeight=\"1\">" + Cell("A1", L"终端安全问题汇总", 1) + "</row>";
  std::wstring note = L"每个 IP 仅保留最新报告；异常和需复核项目分别汇总。读取失败文件：" + std::to_wstring(invalid) + L" 个。";
  x += "<row r=\"2\" ht=\"20\" customHeight=\"1\">" + Cell("A2", note, 2) + "</row><row r=\"3\"/>";
  const wchar_t *headers[] = {L"IP地址", L"MAC地址", L"计算机名", L"检查时间", L"状态", L"异常数量", L"需复核数量", L"异常问题", L"需复核项目", L"原始JSON报告"};
  x += "<row r=\"4\" ht=\"24\" customHeight=\"1\">";
  for (int i = 0; i < 10; ++i) { char ref[8]{}; sprintf_s(ref, "%c4", 'A' + i); x += Cell(ref, headers[i], 3); }
  x += "</row>";
  for (size_t i = 0; i < reports.size(); ++i) {
    const Report &r = reports[i];
    size_t row = i + 5;
    size_t lineCount = std::max<size_t>(1, std::max(r.issues.size(), r.reviews.size()));
    size_t height = std::min<size_t>(120, std::max<size_t>(28, lineCount * 22));
    std::wstring status = !r.issues.empty() ? L"异常" : !r.reviews.empty() ? L"需复核" : L"通过";
    int statusStyle = !r.issues.empty() ? 7 : !r.reviews.empty() ? 8 : 9;
    x += "<row r=\"" + std::to_string(row) + "\" ht=\"" + std::to_string(height) + "\" customHeight=\"1\">";
    for (int col = 0; col < 10; ++col) {
      char ref[16]{}; sprintf_s(ref, "%c%zu", 'A' + col, row);
      if (col == 0) x += Cell(ref, r.ip, 4);
      else if (col == 1) x += Cell(ref, r.mac, 4);
      else if (col == 2) x += Cell(ref, r.computer, 4);
      else if (col == 3) x += Cell(ref, r.finished, 4);
      else if (col == 4) x += Cell(ref, status, statusStyle);
      else if (col == 5) x += NumberCell(ref, r.issues.size(), 6);
      else if (col == 6) x += NumberCell(ref, r.reviews.size(), 6);
      else if (col == 7) x += Cell(ref, Lines(r.issues), 5);
      else if (col == 8) x += Cell(ref, Lines(r.reviews), 5);
      else x += Cell(ref, r.source, 5);
    }
    x += "</row>";
  }
  size_t last = std::max<size_t>(4, reports.size() + 4);
  size_t abnormalIps = 0, reviewIps = 0, browserPasswordIps = 0, highRiskIps = 0;
  std::map<std::wstring, size_t> itemCounts;
  for (const Report &r : reports) {
    if (!r.issues.empty()) ++abnormalIps;
    if (!r.reviews.empty()) ++reviewIps;
    std::set<std::wstring> uniqueItems(r.issueItems.begin(), r.issueItems.end());
    bool browserPassword = false, highRisk = false;
    for (const std::wstring &item : uniqueItems) {
      ++itemCounts[item];
      if (item == L"浏览器已保存密码") browserPassword = true;
      if (IsHighRiskItem(item)) highRisk = true;
    }
    if (browserPassword) ++browserPasswordIps;
    if (highRisk) ++highRiskIps;
  }

  char ref[16]{};
  size_t summaryTitle = last + 2, summaryHeader = summaryTitle + 1;
  x += "<row r=\"" + std::to_string(summaryTitle) + "\" ht=\"26\" customHeight=\"1\">";
  sprintf_s(ref, "A%zu", summaryTitle);
  x += Cell(ref, L"终端问题统计", 1) + "</row>";
  x += "<row r=\"" + std::to_string(summaryHeader) + "\" ht=\"24\" customHeight=\"1\">";
  const wchar_t *summaryHeaders[] = {L"统计项目", L"终端数量", L"统计口径"};
  for (int col = 0; col < 3; ++col) {
    sprintf_s(ref, "%c%zu", 'A' + col, summaryHeader);
    x += Cell(ref, summaryHeaders[col], 3);
  }
  x += "</row>";
  struct SummaryRow { const wchar_t *label; size_t count; const wchar_t *basis; };
  const SummaryRow summaryRows[] = {
      {L"全部终端", reports.size(), L"按 IP 地址去重"},
      {L"存在异常的终端", abnormalIps, L"至少有一项检查结论为异常"},
      {L"需要人工复核的终端", reviewIps, L"至少有一项检查结论为需复核"},
      {L"浏览器保存密码的终端", browserPasswordIps, L"“浏览器已保存密码”检查结论为异常"},
      {L"高危漏洞未修复的终端", highRiskIps, L"端口防火墙、Server、远程桌面或 NetBIOS 任一项异常"}};
  for (size_t i = 0; i < std::size(summaryRows); ++i) {
    size_t row = summaryHeader + 1 + i;
    x += "<row r=\"" + std::to_string(row) + "\" ht=\"36\" customHeight=\"1\">";
    sprintf_s(ref, "A%zu", row); x += Cell(ref, summaryRows[i].label, 4);
    sprintf_s(ref, "B%zu", row); x += NumberCell(ref, summaryRows[i].count, 6);
    sprintf_s(ref, "C%zu", row); x += Cell(ref, summaryRows[i].basis, 5);
    x += "</row>";
  }

  size_t itemTitle = summaryHeader + std::size(summaryRows) + 2;
  x += "<row r=\"" + std::to_string(itemTitle) + "\" ht=\"24\" customHeight=\"1\">";
  sprintf_s(ref, "A%zu", itemTitle);
  x += Cell(ref, L"具体异常项目统计", 1) + "</row>";
  size_t itemHeader = itemTitle + 1;
  x += "<row r=\"" + std::to_string(itemHeader) + "\" ht=\"24\" customHeight=\"1\">";
  const wchar_t *itemHeaders[] = {L"异常检查项目", L"受影响终端数量", L"统计口径"};
  for (int col = 0; col < 3; ++col) {
    sprintf_s(ref, "%c%zu", 'A' + col, itemHeader);
    x += Cell(ref, itemHeaders[col], 3);
  }
  x += "</row>";
  size_t itemRow = itemHeader + 1;
  for (const auto &entry : itemCounts) {
    x += "<row r=\"" + std::to_string(itemRow) + "\" ht=\"24\" customHeight=\"1\">";
    sprintf_s(ref, "A%zu", itemRow); x += Cell(ref, entry.first, 4);
    sprintf_s(ref, "B%zu", itemRow); x += NumberCell(ref, entry.second, 6);
    sprintf_s(ref, "C%zu", itemRow); x += Cell(ref, L"同一 IP 的同一项目只计一次", 5);
    x += "</row>";
    ++itemRow;
  }
  x += "</sheetData><autoFilter ref=\"A4:J" + std::to_string(last) + "\"/>"
       "<pageMargins left=\"0.3\" right=\"0.3\" top=\"0.5\" bottom=\"0.5\" header=\"0.2\" footer=\"0.2\"/>"
       "</worksheet>";
  return x;
}

uint32_t Crc32(const std::string &data) {
  uint32_t crc = 0xFFFFFFFFu;
  for (unsigned char byte : data) {
    crc ^= byte;
    for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
  }
  return ~crc;
}
void U16(std::vector<unsigned char> &out, uint16_t v) { out.push_back(v & 255); out.push_back((v >> 8) & 255); }
void U32(std::vector<unsigned char> &out, uint32_t v) { U16(out, v & 0xFFFF); U16(out, (v >> 16) & 0xFFFF); }
struct ZipEntry { std::string name, data; uint32_t crc = 0, offset = 0; };
bool SaveXlsx(const std::wstring &path, std::vector<ZipEntry> entries) {
  std::vector<unsigned char> out;
  for (auto &e : entries) {
    e.offset = static_cast<uint32_t>(out.size()); e.crc = Crc32(e.data);
    U32(out, 0x04034B50); U16(out, 20); U16(out, 0x0800); U16(out, 0); U16(out, 0); U16(out, 0);
    U32(out, e.crc); U32(out, static_cast<uint32_t>(e.data.size())); U32(out, static_cast<uint32_t>(e.data.size()));
    U16(out, static_cast<uint16_t>(e.name.size())); U16(out, 0);
    out.insert(out.end(), e.name.begin(), e.name.end()); out.insert(out.end(), e.data.begin(), e.data.end());
  }
  uint32_t central = static_cast<uint32_t>(out.size());
  for (const auto &e : entries) {
    U32(out, 0x02014B50); U16(out, 20); U16(out, 20); U16(out, 0x0800); U16(out, 0); U16(out, 0); U16(out, 0);
    U32(out, e.crc); U32(out, static_cast<uint32_t>(e.data.size())); U32(out, static_cast<uint32_t>(e.data.size()));
    U16(out, static_cast<uint16_t>(e.name.size())); U16(out, 0); U16(out, 0); U16(out, 0); U16(out, 0); U32(out, 0); U32(out, e.offset);
    out.insert(out.end(), e.name.begin(), e.name.end());
  }
  uint32_t centralSize = static_cast<uint32_t>(out.size()) - central;
  U32(out, 0x06054B50); U16(out, 0); U16(out, 0); U16(out, static_cast<uint16_t>(entries.size())); U16(out, static_cast<uint16_t>(entries.size()));
  U32(out, centralSize); U32(out, central); U16(out, 0);
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0; bool ok = WriteFile(file, out.data(), static_cast<DWORD>(out.size()), &written, nullptr) && written == out.size();
  CloseHandle(file); return ok;
}
bool WriteLog(const std::wstring &path, const std::wstring &text) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  std::string bytes = "\xEF\xBB\xBF" + Utf8(text); DWORD written = 0;
  bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
  CloseHandle(file); return ok;
}
} // namespace

int wmain() {
  _setmode(_fileno(stdout), _O_U16TEXT);
  _setmode(_fileno(stderr), _O_U16TEXT);
  const std::wstring directory = ExeDir();
  size_t invalid = 0;
  std::vector<Report> reports = LatestReports(directory, invalid);
  if (reports.empty()) {
    std::wcerr << L"没有找到可读取的 verification-report_*.json 报告。\n";
    WriteLog(Join(directory, L"issue-summary.log"), L"未生成 Excel：没有找到可读取的 JSON 报告。\r\n");
    return 1;
  }
  const std::string contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/></Types>";
  const std::string rootRels = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
  const std::string workbook = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"问题汇总\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>";
  const std::string workbookRels = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>";
  const std::string styles = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><fonts count=\"4\"><font><sz val=\"11\"/><name val=\"Arial\"/></font><font><b/><sz val=\"16\"/><name val=\"Arial\"/></font><font><i/><color rgb=\"FF666666\"/><sz val=\"10\"/><name val=\"Arial\"/></font><font><b/><color rgb=\"FFFFFFFF\"/><sz val=\"11\"/><name val=\"Arial\"/></font></fonts><fills count=\"6\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill><fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF1F4E78\"/><bgColor indexed=\"64\"/></patternFill></fill><fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFFFE5E5\"/><bgColor indexed=\"64\"/></patternFill></fill><fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFFFF2CC\"/><bgColor indexed=\"64\"/></patternFill></fill><fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFE2F0D9\"/><bgColor indexed=\"64\"/></patternFill></fill></fills><borders count=\"2\"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style=\"thin\"><color rgb=\"FFD9E0E6\"/></left><right style=\"thin\"><color rgb=\"FFD9E0E6\"/></right><top style=\"thin\"><color rgb=\"FFD9E0E6\"/></top><bottom style=\"thin\"><color rgb=\"FFD9E0E6\"/></bottom><diagonal/></border></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"10\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"0\" fontId=\"1\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"0\" fontId=\"2\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"0\" fontId=\"3\" fillId=\"2\" borderId=\"1\" xfId=\"0\"><alignment horizontal=\"center\" vertical=\"center\"/></xf><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\"><alignment vertical=\"top\"/></xf><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\"><alignment vertical=\"top\" wrapText=\"1\"/></xf><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\"><alignment horizontal=\"center\" vertical=\"top\"/></xf><xf numFmtId=\"0\" fontId=\"0\" fillId=\"3\" borderId=\"1\" xfId=\"0\"><alignment horizontal=\"center\" vertical=\"center\"/></xf><xf numFmtId=\"0\" fontId=\"0\" fillId=\"4\" borderId=\"1\" xfId=\"0\"><alignment horizontal=\"center\" vertical=\"center\"/></xf><xf numFmtId=\"0\" fontId=\"0\" fillId=\"5\" borderId=\"1\" xfId=\"0\"><alignment horizontal=\"center\" vertical=\"center\"/></xf></cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>";
  std::vector<ZipEntry> entries = {{"[Content_Types].xml", contentTypes}, {"_rels/.rels", rootRels}, {"xl/workbook.xml", workbook}, {"xl/_rels/workbook.xml.rels", workbookRels}, {"xl/styles.xml", styles}, {"xl/worksheets/sheet1.xml", SheetXml(reports, invalid)}};
  const std::wstring output = Join(directory, L"security-issues-summary.xlsx");
  if (!SaveXlsx(output, std::move(entries))) {
    std::wcerr << L"无法写入 Excel，请关闭已打开的同名文件并检查目录权限。\n";
    WriteLog(Join(directory, L"issue-summary.log"), L"生成失败：无法写入 security-issues-summary.xlsx。\r\n");
    return 1;
  }
  size_t issueIps = 0, reviewIps = 0;
  for (const auto &r : reports) { if (!r.issues.empty()) ++issueIps; if (!r.reviews.empty()) ++reviewIps; }
  std::wstring log = L"终端安全问题汇总完成。\r\nIP数量：" + std::to_wstring(reports.size()) + L"\r\n存在异常的IP：" + std::to_wstring(issueIps) + L"\r\n存在需复核项的IP：" + std::to_wstring(reviewIps) + L"\r\n读取失败文件：" + std::to_wstring(invalid) + L"\r\n输出：security-issues-summary.xlsx\r\n";
  bool logged = WriteLog(Join(directory, L"issue-summary.log"), log);
  std::wcout << L"汇总完成。每个 IP 一行，共 " << reports.size() << L" 个 IP。\n"
             << L"Excel：" << output << L"\n读取失败文件：" << invalid << L" 个。\n";
  return logged ? 0 : 1;
}
