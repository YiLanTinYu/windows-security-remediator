#include "workflow_report.h"
#include <iostream>

namespace {
bool Contains(const std::wstring &text, const wchar_t *expected) {
  return text.find(expected) != std::wstring::npos;
}
}

int wmain() {
  sr::AuditResult before;
  before.ip = L"192.0.2.10";
  before.mac = L"00-11-22-33-44-55";
  before.failed = 1;
  before.summary.push_back(
      {L"Server 文件共享服务", L"已停止、已禁用", L"正在运行", sr::Verdict::Fail});
  before.summary.push_back(
      {L"远程桌面连接策略", L"禁止连接", L"已禁止连接", sr::Verdict::Pass});
  before.summary.push_back(
      {L"端口外部连通性", L"外部不可连接", L"需要外部验证", sr::Verdict::Review});
  before.summary.push_back(
      {L"无线网卡", L"全部禁用", L"未识别到无线网卡", sr::Verdict::NotApplicable});

  sr::AuditResult after = before;
  after.failed = 0;
  after.passed = 1;
  after.summary[0].actual = L"状态=已停止，启动类型=已禁用";
  after.summary[0].verdict = sr::Verdict::Pass;

  sr::RemediationResult remediation;
  remediation.success = true;
  remediation.changed = true;
  remediation.actions.push_back(
      {L"Server 文件共享服务", L"停止并禁用", L"已完成", true, true});

  const std::wstring json = sr::ToWorkflowJson(before, remediation, after);
  const std::wstring html = sr::ToWorkflowHtml(before, remediation, after);

  if (!Contains(json, L"\"before\"") ||
      !Contains(json, L"\"remediation\"") ||
      !Contains(json, L"\"summary\"") ||
      !Contains(json, L"状态=已停止，启动类型=已禁用")) {
    std::wcerr << L"workflow JSON did not preserve before/actions/final summary\n";
    return 1;
  }
  if (!Contains(html, L"修复前检查") || !Contains(html, L"修复动作") ||
      !Contains(html, L"修复后复检")) {
    std::wcerr << L"workflow HTML did not label all three phases\n";
    return 1;
  }
  if (!Contains(html, L"<td class=fail>异常</td>") ||
      !Contains(html, L"<td class=pass>通过</td>") ||
      !Contains(html, L"<td class=review>需复核</td>") ||
      !Contains(html, L"<td class=na>不适用</td>")) {
    std::wcerr << L"before-remediation verdicts did not use report status colors\n";
    return 1;
  }
  sr::AuditResult compliant;
  for (const wchar_t *item : {L"Server 文件共享服务", L"远程桌面服务",
                              L"远程桌面连接策略", L"Windows 防火墙配置文件",
                              L"NetBIOS 配置汇总"})
    compliant.summary.push_back({item, L"", L"", sr::Verdict::Pass});
  for (const wchar_t *rule : {L"TCP-22", L"TCP-135", L"UDP-137",
                              L"UDP-138", L"TCP-139", L"TCP-445",
                              L"TCP-3389", L"UDP-3389"})
    compliant.summary.push_back(
        {std::wstring(L"防火墙规则 ") + rule, L"", L"", sr::Verdict::Pass});
  compliant.summary.push_back(
      {L"浏览器已保存密码", L"0条", L"2条", sr::Verdict::Fail});
  if (!sr::RemediationScopeCompliant(compliant)) {
    std::wcerr << L"non-remediated findings incorrectly failed remediation scope\n";
    return 1;
  }
  compliant.summary[0].verdict = sr::Verdict::Fail;
  if (sr::RemediationScopeCompliant(compliant)) {
    std::wcerr << L"remediated finding failure was not detected\n";
    return 1;
  }
  compliant.summary[0].verdict = sr::Verdict::Pass;
  for (auto &row : compliant.summary)
    if (row.item == L"Windows 防火墙配置文件")
      row.verdict = sr::Verdict::Fail;
  compliant.summary.push_back(
      {L"扫描接收兼容性", L"",
       L"检测到FTP接收服务，但控制端口、被动端口范围、允许来源或规则配置文件不完整",
       sr::Verdict::Review});
  if (!sr::RemediationScopeCompliant(compliant)) {
    std::wcerr << L"accepted FTP preservation policy incorrectly failed remediation scope\n";
    return 1;
  }
  return 0;
}
