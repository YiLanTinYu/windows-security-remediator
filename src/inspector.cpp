#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <shellapi.h>
#include <sqlite3.h>
#include <cstdio>
#include <string>
#include <vector>

namespace {
std::wstring Join(const std::wstring& left,const std::wstring& right){return left+(left.empty()||left.back()==L'\\'?L"":L"\\")+right;}
std::wstring ExePath(){wchar_t path[MAX_PATH]{};DWORD size=GetModuleFileNameW(nullptr,path,MAX_PATH);return std::wstring(path,size);}
std::wstring ExeDir(){std::wstring value=ExePath();size_t slash=value.find_last_of(L"\\/");return slash==std::wstring::npos?L".":value.substr(0,slash);}
std::wstring Quote(const std::wstring& value){return L"\""+value+L"\"";}
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
std::wstring FindLatestReport(const std::wstring& directory){
    WIN32_FIND_DATAW data{};HANDLE search=FindFirstFileW(Join(directory,L"verification-report_*.html").c_str(),&data);std::wstring result;FILETIME latest{};
    if(search!=INVALID_HANDLE_VALUE){do{if((data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==0&&(result.empty()||CompareFileTime(&data.ftLastWriteTime,&latest)>0)){result=Join(directory,data.cFileName);latest=data.ftLastWriteTime;}}while(FindNextFileW(search,&data));FindClose(search);}
    if(result.empty()){const std::wstring legacy=Join(directory,L"verification-report.html");if(GetFileAttributesW(legacy.c_str())!=INVALID_FILE_ATTRIBUTES)result=legacy;}
    return result;
}
}

int wmain(int argc,wchar_t** argv){
    if(argc==3&&_wcsicmp(argv[1],L"/count-chromium-logins")==0)return CountChromiumLogins(argv[2]);
    SetConsoleTitleW(L"Security Remediator 现场安全检查");
    Print(L"============================================================\r\n");
    Print(L"  Security Remediator 现场安全检查 1.2.4\r\n");
    Print(L"  作者：倚栏听雨\r\n");
    Print(L"============================================================\r\n");
    Print(L"本程序只读取系统状态和已保存密码条目数量，不执行修复。\r\n");
    Print(L"不会解密、显示或导出密码、账号、网站或 Cookie。\r\n\r\n");

    const std::wstring directory=ExeDir();
    const std::wstring verifier=Join(directory,L"verify-remediator.ps1");
    if(GetFileAttributesW(verifier.c_str())==INVALID_FILE_ATTRIBUTES){Print(L"错误：同目录缺少 verify-remediator.ps1。\r\n");return 2;}

    wchar_t system[MAX_PATH]{};GetSystemDirectoryW(system,MAX_PATH);
    const std::wstring powershell=Join(system,L"WindowsPowerShell\\v1.0\\powershell.exe");
    std::wstring command=Quote(powershell)+L" -NoProfile -ExecutionPolicy Bypass -File "+Quote(verifier)+L" -Interactive -ExitWithStatus -InspectorPath "+Quote(ExePath());
    std::vector<wchar_t> buffer(command.begin(),command.end());buffer.push_back(L'\0');
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    Print(L"开始检查，请稍候……\r\n\r\n");
    if(!CreateProcessW(powershell.c_str(),buffer.data(),nullptr,nullptr,TRUE,0,nullptr,directory.c_str(),&startup,&process)){
        Print(L"错误：无法启动 Windows PowerShell 验证脚本。\r\n");return 1;
    }
    WaitForSingleObject(process.hProcess,INFINITE);DWORD exitCode=1;GetExitCodeProcess(process.hProcess,&exitCode);CloseHandle(process.hThread);CloseHandle(process.hProcess);
    const std::wstring report=FindLatestReport(directory);

    Print(L"\r\n检查已经运行完毕。\r\n");
    if(exitCode==0)Print(L"结论：未发现明确异常，请查看报告中的“需复核”项目。\r\n");
    else if(exitCode==5)Print(L"结论：发现异常项目，请查看 HTML 报告。\r\n");
    else Print(L"结论：检查未完整完成，请查看原始检查信息。\r\n");
    if(report.empty())Print(L"报告位置：未找到生成的 HTML 报告。\r\n");else Print(L"报告位置："+report+L"\r\n");

    if(!HasArg(argc,argv,L"/no-open")&&!report.empty()&&GetFileAttributesW(report.c_str())!=INVALID_FILE_ATTRIBUTES)ShellExecuteW(nullptr,L"open",report.c_str(),nullptr,directory.c_str(),SW_SHOWNORMAL);
    DWORD ids[2]{};DWORD consoleProcesses=GetConsoleProcessList(ids,2);
    if(!HasArg(argc,argv,L"/no-pause")&&consoleProcesses<=1){Print(L"\r\n按 Enter 键关闭此窗口……");wchar_t input[4]{};DWORD read=0;ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE),input,4,&read,nullptr);}
    return static_cast<int>(exitCode);
}
