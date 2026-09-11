#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <shellapi.h>
#include <sqlite3.h>
#include "audit_core.h"
#include "system_remediation.h"
#include "workflow_report.h"
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

namespace {
std::wstring ExePath(){wchar_t path[MAX_PATH]{};DWORD size=GetModuleFileNameW(nullptr,path,MAX_PATH);return std::wstring(path,size);}
std::wstring ExeDir(){std::wstring value=ExePath();size_t slash=value.find_last_of(L"\\/");return slash==std::wstring::npos?L".":value.substr(0,slash);}
bool HasArg(int argc,wchar_t** argv,const wchar_t* expected){for(int i=1;i<argc;i++)if(_wcsicmp(argv[i],expected)==0)return true;return false;}
void Print(const std::wstring& text){HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);DWORD written=0;if(output&&output!=INVALID_HANDLE_VALUE)WriteConsoleW(output,text.c_str(),static_cast<DWORD>(text.size()),&written,nullptr);}
void PrintAscii(const std::string& text){HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);DWORD written=0;if(output&&output!=INVALID_HANDLE_VALUE)WriteFile(output,text.data(),static_cast<DWORD>(text.size()),&written,nullptr);}
std::string Utf8(const std::wstring& value){if(value.empty())return {};int size=WideCharToMultiByte(CP_UTF8,0,value.c_str(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);std::string result(static_cast<size_t>(size),'\0');WideCharToMultiByte(CP_UTF8,0,value.c_str(),static_cast<int>(value.size()),result.data(),size,nullptr,nullptr);return result;}
int CountChromiumLogins(const std::wstring& path){
    sqlite3* database=nullptr;
    if(sqlite3_open_v2(Utf8(path).c_str(),&database,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,nullptr)!=SQLITE_OK){if(database)sqlite3_close(database);return 6;}
    sqlite3_busy_timeout(database,1500);
    sqlite3_stmt* statement=nullptr;
    constexpr const char* query="SELECT COUNT(*) FROM logins WHERE password_value IS NOT NULL AND length(password_value)>0";
    if(sqlite3_prepare_v2(database,query,-1,&statement,nullptr)!=SQLITE_OK){sqlite3_close(database);return 6;}
    const int step=sqlite3_step(statement);
    if(step!=SQLITE_ROW){sqlite3_finalize(statement);sqlite3_close(database);return 6;}
    const sqlite3_int64 count=sqlite3_column_int64(statement,0);
    sqlite3_finalize(statement);sqlite3_close(database);
    char result[32]{};std::snprintf(result,sizeof(result),"%lld\n",static_cast<long long>(count));PrintAscii(result);return 0;
}
std::string JsonString(const unsigned char* value){
    std::string result="\"";if(value)for(const unsigned char* p=value;*p;++p){
        if(*p=='"'||*p=='\\'){result+='\\';result+=static_cast<char>(*p);}
        else if(*p<32){char escaped[7]{};std::snprintf(escaped,sizeof(escaped),"\\u%04x",*p);result+=escaped;}
        else result+=static_cast<char>(*p);
    }return result+"\"";
}
int ListChromiumLogins(const std::wstring& path){
    sqlite3* database=nullptr;
    if(sqlite3_open_v2(Utf8(path).c_str(),&database,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,nullptr)!=SQLITE_OK){if(database)sqlite3_close(database);return 6;}
    sqlite3_busy_timeout(database,1500);sqlite3_stmt* statement=nullptr;
    const char* query="SELECT origin_url, username_value FROM logins WHERE password_value IS NOT NULL AND length(password_value)>0";
    if(sqlite3_prepare_v2(database,query,-1,&statement,nullptr)!=SQLITE_OK){sqlite3_close(database);return 6;}
    std::string output="[";int step=0;bool first=true;
    while((step=sqlite3_step(statement))==SQLITE_ROW){if(!first)output+=",";first=false;output+="{\"website\":"+JsonString(sqlite3_column_text(statement,0))+",\"account\":"+JsonString(sqlite3_column_text(statement,1))+"}";}
    sqlite3_finalize(statement);sqlite3_close(database);if(step!=SQLITE_DONE)return 6;
    PrintAscii(output+"]\n");return 0;
}
}

int wmain(int argc,wchar_t** argv){
    if(argc==3&&_wcsicmp(argv[1],L"/count-chromium-logins")==0)return CountChromiumLogins(argv[2]);
    if(argc==3&&_wcsicmp(argv[1],L"/list-chromium-logins")==0)return ListChromiumLogins(argv[2]);
    const bool auditOnly=HasArg(argc,argv,L"/audit-only");
    const bool rollback=HasArg(argc,argv,L"/rollback");
    SetConsoleTitleW(L"终端安全现场检查修复工具");
    Print(L"============================================================\r\n");
    Print(L"  终端安全现场检查修复工具 2.0.1\r\n");
    Print(L"  作者：倚栏听雨\r\n");
    Print(L"============================================================\r\n");
    Print(L"本程序先检查；只有输入小写 yes 后才修复系统安全配置。\r\n");
    Print(L"报告列出保存密码的网站和账号；不会解密或输出密码及 Cookie。\r\n\r\n");

    Print(L"开始修复前检查，请稍候……\r\n\r\n");
    const std::wstring directory=ExeDir();std::wstring report;DWORD exitCode=1;
    try{
      const auto before=sr::RunAudit();
      Print(L"修复前结果：通过 "+std::to_wstring(before.passed)+L" 项，异常 "+
            std::to_wstring(before.failed)+L" 项，需复核 "+
            std::to_wstring(before.review)+L" 项。\r\n");
      if(auditOnly){
        const auto files=sr::WriteReports(before,directory);report=files.htmlPath;
        exitCode=before.failed?5:0;
      }else{
        Print(rollback?L"输入小写 yes 确认恢复首次修复前状态："
                      :L"输入小写 yes 确认修复系统安全配置；其他输入只保存检查报告：");
        std::wstring answer;std::getline(std::wcin,answer);
        if(answer!=L"yes"){
          const auto files=sr::WriteReports(before,directory);report=files.htmlPath;
          exitCode=before.failed?5:0;
          Print(L"未确认修复，系统没有被修改。\r\n");
        }else if(!sr::IsRemediationAuthorized()){
          const auto files=sr::WriteReports(before,directory);report=files.htmlPath;
          exitCode=3;Print(L"权限不足：请右键选择“以管理员身份运行”。\r\n");
        }else{
          const auto remediation=rollback?sr::RollbackSystemRemediation()
                                         :sr::ApplySystemRemediation();
          Print(L"开始修复后复检，请稍候……\r\n");
          const auto after=sr::RunAudit();
          const auto files=sr::WriteWorkflowReports(before,remediation,after,directory);
          report=files.htmlPath;
          exitCode=(remediation.success && (rollback || sr::RemediationScopeCompliant(after)))?0:1;
        }
      }
    }
    catch(...){Print(L"错误：原生检查或报告生成失败。\r\n");}

    Print(L"\r\n程序已经运行完毕。\r\n");
    if(exitCode==0)Print(L"结论：本次操作完成；请查看报告中的最终结果和“需复核”项目。\r\n");
    else if(exitCode==5)Print(L"结论：检查发现异常，但未执行修复。\r\n");
    else if(exitCode==3)Print(L"结论：权限不足，未执行修复。\r\n");
    else Print(L"结论：检查未完整完成，请查看原始检查信息。\r\n");
    if(report.empty())Print(L"报告位置：未找到生成的 HTML 报告。\r\n");else Print(L"报告位置："+report+L"\r\n");

    if(!HasArg(argc,argv,L"/no-open")&&!report.empty()&&GetFileAttributesW(report.c_str())!=INVALID_FILE_ATTRIBUTES)ShellExecuteW(nullptr,L"open",report.c_str(),nullptr,directory.c_str(),SW_SHOWNORMAL);
    DWORD ids[2]{};DWORD consoleProcesses=GetConsoleProcessList(ids,2);
    if(!HasArg(argc,argv,L"/no-pause")&&consoleProcesses<=1){Print(L"\r\n按 Enter 键关闭此窗口……");wchar_t input[4]{};DWORD read=0;ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE),input,4,&read,nullptr);}
    return static_cast<int>(exitCode);
}
