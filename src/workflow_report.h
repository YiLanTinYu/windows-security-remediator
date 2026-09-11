#pragma once
#include "audit_core.h"
#include "system_remediation.h"

namespace sr {
std::wstring ToWorkflowJson(const AuditResult &before,
                            const RemediationResult &remediation,
                            const AuditResult &after);
std::wstring ToWorkflowHtml(const AuditResult &before,
                            const RemediationResult &remediation,
                            const AuditResult &after);
ReportFiles WriteWorkflowReports(const AuditResult &before,
                                 const RemediationResult &remediation,
                                 const AuditResult &after,
                                 const std::wstring &directory);
bool RemediationScopeCompliant(const AuditResult &result);
}
