#pragma once
#include <string>
#include <vector>

namespace sr {
enum class Verdict { Pass, Fail, Review, NotApplicable, Info };
struct SummaryRow { std::wstring item, expected, actual; Verdict verdict = Verdict::Review; };
struct DetailTable { std::wstring title; std::vector<std::wstring> columns; std::vector<std::vector<std::wstring>> rows; };
struct AuditResult {
    std::wstring computer, executionIdentity, ip, mac, adapter, finished;
    int passed = 0, failed = 0, review = 0;
    std::vector<SummaryRow> summary;
    std::vector<DetailTable> details;
};
struct ReportFiles { std::wstring htmlPath, jsonPath, html, json; };

AuditResult RunAudit();
ReportFiles WriteReports(const AuditResult& result, const std::wstring& directory, const std::wstring& prefix = L"verification-report");
std::wstring ToJson(const AuditResult& result);
std::wstring ToHtml(const AuditResult& result);
}
