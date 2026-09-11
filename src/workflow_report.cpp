#include "workflow_report.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace sr {
namespace {
std::wstring EscapeJson(const std::wstring &value) {
  std::wostringstream output;
  output << L'"';
  for (wchar_t c : value) {
    if (c == L'"') output << L"\\\"";
    else if (c == L'\\') output << L"\\\\";
    else if (c == L'\n') output << L"\\n";
    else if (c == L'\r') output << L"\\r";
    else if (c == L'\t') output << L"\\t";
    else output << c;
  }
  return output.str() + L'"';
}

std::wstring EscapeHtml(const std::wstring &value) {
  std::wstring output;
  for (wchar_t c : value) {
    if (c == L'&') output += L"&amp;";
    else if (c == L'<') output += L"&lt;";
    else if (c == L'>') output += L"&gt;";
    else if (c == L'"') output += L"&quot;";
    else output += c;
  }
  return output;
}

std::string Utf8(const std::wstring &value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                      static_cast<int>(value.size()), nullptr,
                                      0, nullptr, nullptr);
  std::string output(static_cast<size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(),
                      static_cast<int>(value.size()), output.data(), size,
                      nullptr, nullptr);
  return output;
}

std::wstring VerdictText(Verdict verdict) {
  switch (verdict) {
  case Verdict::Pass: return L"通过";
  case Verdict::Fail: return L"异常";
  case Verdict::Review: return L"需复核";
  case Verdict::NotApplicable: return L"不适用";
  case Verdict::Info: return L"信息";
  }
  return L"需复核";
}

const wchar_t *VerdictClass(Verdict verdict) {
  switch (verdict) {
  case Verdict::Pass: return L"pass";
  case Verdict::Fail: return L"fail";
  case Verdict::Review: return L"review";
  case Verdict::NotApplicable: return L"na";
  case Verdict::Info: return L"info";
  }
  return L"review";
}

std::wstring SummaryTable(const AuditResult &result) {
  std::wostringstream output;
  output << L"<table><tr><th>序号</th><th>检查项目</th><th>预期结果</th>"
            L"<th>实际结果</th><th>结论</th></tr>";
  for (size_t i = 0; i < result.summary.size(); ++i) {
    const auto &row = result.summary[i];
    output << L"<tr><td>" << i + 1 << L"</td><td>" << EscapeHtml(row.item)
           << L"</td><td>" << EscapeHtml(row.expected) << L"</td><td>"
           << EscapeHtml(row.actual) << L"</td><td class="
           << VerdictClass(row.verdict) << L">"
           << EscapeHtml(VerdictText(row.verdict)) << L"</td></tr>";
  }
  return output.str() + L"</table>";
}
}

std::wstring ToWorkflowJson(const AuditResult &before,
                            const RemediationResult &remediation,
                            const AuditResult &after) {
  std::wstring finalJson = ToJson(after);
  if (!finalJson.empty() && finalJson.back() == L'}') finalJson.pop_back();
  std::wostringstream output;
  output << finalJson << L",\"workflowSchema\":1,\"before\":" << ToJson(before)
         << L",\"remediation\":{\"authorized\":"
         << (remediation.authorized ? L"true" : L"false")
         << L",\"success\":" << (remediation.success ? L"true" : L"false")
         << L",\"changed\":" << (remediation.changed ? L"true" : L"false")
         << L",\"restartRequired\":"
         << (remediation.restartRequired ? L"true" : L"false")
         << L",\"actions\":[";
  for (size_t i = 0; i < remediation.actions.size(); ++i) {
    if (i) output << L',';
    const auto &action = remediation.actions[i];
    output << L"{\"item\":" << EscapeJson(action.item)
           << L",\"action\":" << EscapeJson(action.action)
           << L",\"result\":" << EscapeJson(action.result)
           << L",\"success\":" << (action.success ? L"true" : L"false")
           << L",\"changed\":" << (action.changed ? L"true" : L"false")
           << L'}';
  }
  return output.str() + L"]}}";
}

std::wstring ToWorkflowHtml(const AuditResult &before,
                            const RemediationResult &remediation,
                            const AuditResult &after) {
  std::wstring html = ToHtml(after);
  const std::wstring marker = L"<div class=card><h2>一、检查结果汇总</h2>";
  const size_t position = html.find(marker);
  if (position == std::wstring::npos) return html;
  std::wostringstream phases;
  phases << L"<div class=card><h2>一、修复前检查</h2><p>通过 "
         << before.passed << L" 项　异常 " << before.failed << L" 项　需复核 "
         << before.review << L" 项</p>" << SummaryTable(before) << L"</div>"
         << L"<div class=card><h2>二、修复动作</h2><table><tr><th>序号</th>"
            L"<th>项目</th><th>执行动作</th><th>执行结果</th><th>是否改变</th></tr>";
  for (size_t i = 0; i < remediation.actions.size(); ++i) {
    const auto &action = remediation.actions[i];
    phases << L"<tr><td>" << i + 1 << L"</td><td>"
           << EscapeHtml(action.item) << L"</td><td>"
           << EscapeHtml(action.action) << L"</td><td>"
           << EscapeHtml(action.result) << L"</td><td>"
           << (action.changed ? L"是" : L"否") << L"</td></tr>";
  }
  phases << L"</table><p>总体结果："
         << (remediation.success ? L"修复动作执行完成" : L"存在修复失败项")
         << L"；不自动重启。</p></div>";
  html.replace(position, marker.size(),
               phases.str() + L"<div class=card><h2>三、修复后复检</h2>");
  return html;
}

ReportFiles WriteWorkflowReports(const AuditResult &before,
                                 const RemediationResult &remediation,
                                 const AuditResult &after,
                                 const std::wstring &directory) {
  ReportFiles files = WriteReports(after, directory);
  files.html = ToWorkflowHtml(before, remediation, after);
  files.json = ToWorkflowJson(before, remediation, after);
  std::ofstream html(files.htmlPath.c_str(), std::ios::binary | std::ios::trunc);
  std::ofstream json(files.jsonPath.c_str(), std::ios::binary | std::ios::trunc);
  const std::string htmlBytes = Utf8(files.html);
  const std::string jsonBytes = Utf8(files.json);
  html.write("\xEF\xBB\xBF", 3);
  html.write(htmlBytes.data(), static_cast<std::streamsize>(htmlBytes.size()));
  json.write("\xEF\xBB\xBF", 3);
  json.write(jsonBytes.data(), static_cast<std::streamsize>(jsonBytes.size()));
  if (!html || !json) throw std::runtime_error("write workflow report failed");
  return files;
}

bool RemediationScopeCompliant(const AuditResult &result) {
  bool server = false, terminal = false, rdp = false, profiles = false,
       netbios = false;
  int firewallRules = 0;
  for (const auto &row : result.summary) {
    const bool pass = row.verdict == Verdict::Pass;
    if (row.item == L"Server 文件共享服务") server = pass;
    else if (row.item == L"远程桌面服务") terminal = pass;
    else if (row.item == L"远程桌面连接策略") rdp = pass;
    else if (row.item == L"Windows 防火墙配置文件") profiles = pass;
    else if (row.item == L"NetBIOS 配置汇总") netbios = pass;
    else if (row.item.rfind(L"防火墙规则 ", 0) == 0 && pass) ++firewallRules;
  }
  return server && terminal && rdp && profiles && netbios && firewallRules == 10;
}
}
