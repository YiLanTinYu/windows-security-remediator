#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

namespace {
std::wstring Join(const std::wstring& left,const std::wstring& right){return left+(left.empty()||left.back()==L'\\'?L"":L"\\")+right;}
std::wstring ExeDir(){wchar_t path[MAX_PATH]{};DWORD size=GetModuleFileNameW(nullptr,path,MAX_PATH);std::wstring value(path,size);size_t slash=value.find_last_of(L"\\/");return slash==std::wstring::npos?L".":value.substr(0,slash);}
std::wstring Quote(const std::wstring& value){return L"\""+value+L"\"";}
bool HasArg(int argc,wchar_t** argv,const wchar_t* expected){for(int i=1;i<argc;i++)if(_wcsicmp(argv[i],expected)==0)return true;return false;}
void Print(const std::wstring& text){HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);DWORD written=0;if(output&&output!=INVALID_HANDLE_VALUE)WriteConsoleW(output,text.c_str(),static_cast<DWORD>(text.size()),&written,nullptr);}
}

int wmain(int argc,wchar_t** argv){
    SetConsoleTitleW(L"Security Remediator 现场安全检查");
    Print(L"============================================================\r\n");
    Print(L"  Security Remediator 现场安全检查 1.2.1\r\n");
    Print(L"  作者：倚栏听雨\r\n");
    Print(L"============================================================\r\n");
    Print(L"本程序只读取系统和浏览器设置，不执行修复。\r\n");
    Print(L"不会读取、显示或导出任何已保存密码、账号或 Cookie。\r\n\r\n");

    const std::wstring directory=ExeDir();
    const std::wstring verifier=Join(directory,L"verify-remediator.ps1");
    const std::wstring report=Join(directory,L"verification-report.html");
    if(GetFileAttributesW(verifier.c_str())==INVALID_FILE_ATTRIBUTES){Print(L"错误：同目录缺少 verify-remediator.ps1。\r\n");return 2;}

    wchar_t system[MAX_PATH]{};GetSystemDirectoryW(system,MAX_PATH);
    const std::wstring powershell=Join(system,L"WindowsPowerShell\\v1.0\\powershell.exe");
    std::wstring command=Quote(powershell)+L" -NoProfile -ExecutionPolicy Bypass -File "+Quote(verifier)+L" -Interactive -ExitWithStatus";
    std::vector<wchar_t> buffer(command.begin(),command.end());buffer.push_back(L'\0');
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    Print(L"开始检查，请稍候……\r\n\r\n");
    if(!CreateProcessW(powershell.c_str(),buffer.data(),nullptr,nullptr,TRUE,0,nullptr,directory.c_str(),&startup,&process)){
        Print(L"错误：无法启动 Windows PowerShell 验证脚本。\r\n");return 1;
    }
    WaitForSingleObject(process.hProcess,INFINITE);DWORD exitCode=1;GetExitCodeProcess(process.hProcess,&exitCode);CloseHandle(process.hThread);CloseHandle(process.hProcess);

    Print(L"\r\n检查已经运行完毕。\r\n");
    if(exitCode==0)Print(L"结论：未发现明确异常，请查看报告中的“需复核”项目。\r\n");
    else if(exitCode==5)Print(L"结论：发现异常项目，请查看 HTML 报告。\r\n");
    else Print(L"结论：检查未完整完成，请查看原始检查信息。\r\n");
    Print(L"报告位置："+report+L"\r\n");

    if(!HasArg(argc,argv,L"/no-open")&&GetFileAttributesW(report.c_str())!=INVALID_FILE_ATTRIBUTES)ShellExecuteW(nullptr,L"open",report.c_str(),nullptr,directory.c_str(),SW_SHOWNORMAL);
    DWORD ids[2]{};DWORD consoleProcesses=GetConsoleProcessList(ids,2);
    if(!HasArg(argc,argv,L"/no-pause")&&consoleProcesses<=1){Print(L"\r\n按 Enter 键关闭此窗口……");wchar_t input[4]{};DWORD read=0;ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE),input,4,&read,nullptr);}
    return static_cast<int>(exitCode);
}
