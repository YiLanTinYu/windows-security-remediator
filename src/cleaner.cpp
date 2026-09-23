#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <sqlite3.h>
#include "ie_credentials.h"
#include <string>
#include <vector>
#include <cstdio>
#pragma comment(lib,"setupapi.lib")

// Only remove a disconnected USBSTOR device through the Windows device installer.
// Never take ownership of Enum registry keys or remove a driver package.
int RemoveUsbHistory(const wchar_t* id,bool probe){
    if(_wcsnicmp(id,L"USBSTOR\\",8)!=0||wcsstr(id,L"..")||wcschr(id,L'/'))return ERROR_INVALID_PARAMETER;
    HDEVINFO present=SetupDiGetClassDevsW(nullptr,L"USBSTOR",nullptr,DIGCF_ALLCLASSES|DIGCF_PRESENT);
    if(present==INVALID_HANDLE_VALUE)return GetLastError();
    for(DWORD i=0;;++i){SP_DEVINFO_DATA device{};device.cbSize=sizeof(device);
        if(!SetupDiEnumDeviceInfo(present,i,&device)){DWORD error=GetLastError();SetupDiDestroyDeviceInfoList(present);if(error!=ERROR_NO_MORE_ITEMS)return error;break;}
        wchar_t candidate[MAX_DEVICE_ID_LEN]{};
        if(!SetupDiGetDeviceInstanceIdW(present,&device,candidate,MAX_DEVICE_ID_LEN,nullptr)){DWORD error=GetLastError();SetupDiDestroyDeviceInfoList(present);return error;}
        if(_wcsicmp(candidate,id)==0){SetupDiDestroyDeviceInfoList(present);return ERROR_BUSY;}
    }
    HDEVINFO devices=SetupDiCreateDeviceInfoList(nullptr,nullptr);if(devices==INVALID_HANDLE_VALUE)return GetLastError();
    SP_DEVINFO_DATA device{};device.cbSize=sizeof(device);
    if(!SetupDiOpenDeviceInfoW(devices,id,nullptr,0,&device)){DWORD error=GetLastError();SetupDiDestroyDeviceInfoList(devices);return error;}
    if(probe){SetupDiDestroyDeviceInfoList(devices);return ERROR_SUCCESS;}
    SP_DEVINSTALL_PARAMS_W install{};install.cbSize=sizeof(install);
    if(!SetupDiGetDeviceInstallParamsW(devices,&device,&install)){DWORD error=GetLastError();SetupDiDestroyDeviceInfoList(devices);return error;}
    install.Flags|=DI_QUIETINSTALL;
    if(!SetupDiSetDeviceInstallParamsW(devices,&device,&install)){DWORD error=GetLastError();SetupDiDestroyDeviceInfoList(devices);return error;}
    SP_REMOVEDEVICE_PARAMS removal{};removal.ClassInstallHeader.cbSize=sizeof(SP_CLASSINSTALL_HEADER);removal.ClassInstallHeader.InstallFunction=DIF_REMOVE;removal.Scope=DI_REMOVEDEVICE_GLOBAL;
    if(!SetupDiSetClassInstallParamsW(devices,&device,&removal.ClassInstallHeader,sizeof(removal))||!SetupDiCallClassInstaller(DIF_REMOVE,devices,&device)){DWORD error=GetLastError();SetupDiDestroyDeviceInfoList(devices);return error;}
    bool reboot=SetupDiGetDeviceInstallParamsW(devices,&device,&install)&&(install.Flags&(DI_NEEDREBOOT|DI_NEEDRESTART));
    SetupDiDestroyDeviceInfoList(devices);return reboot?ERROR_SUCCESS_REBOOT_REQUIRED:ERROR_SUCCESS;
}

std::string Utf8(const wchar_t* value){int n=WideCharToMultiByte(CP_UTF8,0,value,-1,nullptr,0,nullptr,nullptr);std::string s(n,'\0');WideCharToMultiByte(CP_UTF8,0,value,-1,&s[0],n,nullptr,nullptr);return s;}
int CountChromiumLogins(const wchar_t* path){
    sqlite3* db=nullptr;if(sqlite3_open_v2(Utf8(path).c_str(),&db,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,nullptr)!=SQLITE_OK){if(db)sqlite3_close(db);return 6;}
    sqlite3_busy_timeout(db,1500);sqlite3_stmt* statement=nullptr;
    const char* query="SELECT count(*) FROM logins WHERE password_value IS NOT NULL AND length(password_value)>0";
    if(sqlite3_prepare_v2(db,query,-1,&statement,nullptr)!=SQLITE_OK){sqlite3_close(db);return 6;}
    const int step=sqlite3_step(statement);if(step!=SQLITE_ROW){sqlite3_finalize(statement);sqlite3_close(db);return 6;}
    const sqlite3_int64 count=sqlite3_column_int64(statement,0);sqlite3_finalize(statement);sqlite3_close(db);
    std::printf("%lld\n",static_cast<long long>(count));return 0;
}
int ClearDatabase(const wchar_t* path){
    sqlite3* db=nullptr;if(sqlite3_open_v2(Utf8(path).c_str(),&db,SQLITE_OPEN_READWRITE,nullptr)!=SQLITE_OK){if(db)sqlite3_close(db);return 1;}
    sqlite3_busy_timeout(db,1500);
    if(sqlite3_exec(db,"BEGIN EXCLUSIVE",nullptr,nullptr,nullptr)!=SQLITE_OK){sqlite3_close(db);return 1;}
    const char* query="DELETE FROM logins WHERE password_value IS NOT NULL AND length(password_value)>0";
    if(sqlite3_exec(db,query,nullptr,nullptr,nullptr)!=SQLITE_OK){sqlite3_exec(db,"ROLLBACK",nullptr,nullptr,nullptr);sqlite3_close(db);return 1;}
    int removed=sqlite3_changes(db);
    if(sqlite3_exec(db,"COMMIT",nullptr,nullptr,nullptr)!=SQLITE_OK){sqlite3_exec(db,"ROLLBACK",nullptr,nullptr,nullptr);sqlite3_close(db);return 1;}
    sqlite3_close(db);std::printf("%d\n",removed);return 0;
}
int PrintIECleanupResult(const sr::IECredentialCleanupResult& result){
    if(!result.available){std::fwprintf(stderr,L"%ls\n",result.error.c_str());return 6;}
    std::printf("%d %d %d\n",result.before,result.removed,result.after);return 0;
}
int CountIEWebCredentials(){
    const sr::IECredentialScan scan=sr::ReadCurrentUserIEWebCredentials();
    if(!scan.available){std::fwprintf(stderr,L"%ls\n",scan.error.c_str());return 6;}
    std::printf("%zu\n",scan.credentials.size());return 0;
}
int wmain(int argc,wchar_t** argv){
    if(argc==3&&wcscmp(argv[1],L"/remove-usb-history")==0)return RemoveUsbHistory(argv[2],false);
    if(argc==3&&wcscmp(argv[1],L"/probe-usb-history")==0)return RemoveUsbHistory(argv[2],true);
    if(argc==3&&wcscmp(argv[1],L"/clear-chromium")==0)return ClearDatabase(argv[2]);
    if(argc==3&&wcscmp(argv[1],L"/count-chromium-logins")==0)return CountChromiumLogins(argv[2]);
    if(argc==2&&wcscmp(argv[1],L"/inspect-ie-storage2")==0)return PrintIECleanupResult(sr::CleanCurrentUserLegacyIEStorage(false));
    if(argc==2&&wcscmp(argv[1],L"/clear-ie-storage2")==0)return PrintIECleanupResult(sr::CleanCurrentUserLegacyIEStorage(true));
    if(argc==2&&wcscmp(argv[1],L"/inspect-ie-wininet")==0)return PrintIECleanupResult(sr::CleanCurrentUserWinInetCredentials(false));
    if(argc==2&&wcscmp(argv[1],L"/clear-ie-wininet")==0)return PrintIECleanupResult(sr::CleanCurrentUserWinInetCredentials(true));
    if(argc==2&&wcscmp(argv[1],L"/count-ie-web-credentials")==0)return CountIEWebCredentials();
    if(argc!=1)return 2;
    wchar_t path[MAX_PATH]{},system[MAX_PATH]{};GetModuleFileNameW(nullptr,path,MAX_PATH);GetSystemDirectoryW(system,MAX_PATH);
    std::wstring exe=path,dir=exe.substr(0,exe.find_last_of(L"\\/")),ps=std::wstring(system)+L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::wstring command=L"\""+ps+L"\" -NoProfile -ExecutionPolicy Bypass -File \""+dir+L"\\cleanup-remediator.ps1\" -CleanerPath \""+exe+L"\"";
    std::vector<wchar_t> buffer(command.begin(),command.end());buffer.push_back(0);STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
    if(!CreateProcessW(ps.c_str(),buffer.data(),nullptr,nullptr,TRUE,0,nullptr,dir.c_str(),&si,&pi))return 1;
    WaitForSingleObject(pi.hProcess,INFINITE);DWORD code=1;GetExitCodeProcess(pi.hProcess,&code);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return code;
}
