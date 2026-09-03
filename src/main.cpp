#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <netfw.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <locale>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {
int FixedRuntimeLogName(wchar_t* buffer,const wchar_t*,...){return wcscpy_s(buffer,64,L"remediator.log");}
#define swprintf_s FixedRuntimeLogName
const wchar_t* kProduct=L"SecurityRemediator";
const wchar_t* kRulePrefix=L"SecurityRemediator - Block ";
std::wstring logDir, backupPath;
std::wofstream logFile;
int failures=0; bool changed=false; bool rebootNeeded=false;
int finalExitCode=-1; std::wstring finalMode=L"请查看 last-result.json";
struct LocaleBootstrap { LocaleBootstrap(){ try { std::locale::global(std::locale("")); } catch(...) {} } } localeBootstrap;

std::wstring Err(DWORD e=GetLastError()) { wchar_t b[32]; _snwprintf_s(b,_countof(b),_TRUNCATE,L"0x%08X",e); return b; }
std::wstring Join(const std::wstring&a,const std::wstring&b);
void Log(const std::wstring& s) { if(logFile.is_open()) { if(s==L"completed") { logFile << L"结果：执行成功，系统配置已按规则处理。\n"; std::wofstream r(Join(logDir,L"result.txt"),std::ios::trunc); r<<L"执行成功\n退出码："<<finalExitCode<<L"\n模式："<<finalMode<<L"\n修改内容："<<(changed?L"有":L"无")<<L"\n"; } else if(s==L"incomplete") { logFile << L"结果：执行未完成，请查看退出码和失败项。\n"; std::wofstream r(Join(logDir,L"result.txt"),std::ios::trunc); r<<L"执行未完成\n退出码："<<finalExitCode<<L"\n模式："<<finalMode<<L"\n请检查权限和日志中的失败项。\n"; } else logFile << s << L"\n"; } }
void (*const WriteLogFn)(const std::wstring&)=Log;
void DispatchLog(const std::wstring& s){if(s==L"completed")finalExitCode=0;else if(s==L"incomplete")finalExitCode=1;if(s==L"SecurityRemediator started")WriteLogFn(L"SecurityRemediator version 1.2.1, author: YiLanTingYu, started");else WriteLogFn(s);}
#define Log(s) DispatchLog(s)
std::wstring Join(const std::wstring&a,const std::wstring&b){return a+(a.empty()||a.back()==L'\\'?L"":L"\\")+b;}
std::wstring ExeDir(){wchar_t b[MAX_PATH]{};DWORD n=GetModuleFileNameW(nullptr,b,_countof(b));std::wstring p(b,n);size_t i=p.find_last_of(L"\\/");return i==std::wstring::npos?L".":p.substr(0,i);}
struct DefaultLogPath { DefaultLogPath(){logDir=ExeDir();} } defaultLogPath;
struct DirectoryBootstrap { DirectoryBootstrap(){ wchar_t p[MAX_PATH]{}; if(SUCCEEDED(SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,p))) { std::wstring d=Join(p,kProduct); SHCreateDirectoryExW(nullptr,d.c_str(),nullptr); } } } directoryBootstrap;
bool IsSystem(){HANDLE t=nullptr; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t)) return false; DWORD n=0; GetTokenInformation(t,TokenUser,nullptr,0,&n); std::vector<BYTE> b(n); bool ok=false; if(GetTokenInformation(t,TokenUser,b.data(),n,&n)){PSID s=((TOKEN_USER*)b.data())->User.Sid; PSID sys=nullptr; ConvertStringSidToSidW(L"S-1-5-18",&sys); ok=EqualSid(s,sys); LocalFree(sys);} CloseHandle(t); return ok;}
bool IsElevatedAdministrator(){HANDLE t=nullptr; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t)) return false; TOKEN_ELEVATION e{}; DWORD n=0; bool elevated=GetTokenInformation(t,TokenElevation,&e,sizeof(e),&n)&&e.TokenIsElevated!=0; CloseHandle(t); return elevated;}
bool IsAuthorized(){return IsSystem()||IsElevatedAdministrator();}
bool RegDword(HKEY root,const std::wstring&sub,const wchar_t* name,DWORD&v,bool&exists){HKEY h; exists=false; if(RegOpenKeyExW(root,sub.c_str(),0,KEY_QUERY_VALUE,&h)!=ERROR_SUCCESS)return true; DWORD t=0,n=sizeof(v); LONG e=RegQueryValueExW(h,name,nullptr,&t,(BYTE*)&v,&n); RegCloseKey(h); exists=e==ERROR_SUCCESS&&t==REG_DWORD; return e==ERROR_SUCCESS||e==ERROR_FILE_NOT_FOUND;}
bool SetDword(HKEY root,const std::wstring&sub,const wchar_t* name,DWORD v){HKEY h; if(RegCreateKeyExW(root,sub.c_str(),0,nullptr,0,KEY_SET_VALUE,nullptr,&h,nullptr)!=ERROR_SUCCESS)return false; LONG e=RegSetValueExW(h,name,0,REG_DWORD,(BYTE*)&v,sizeof(v)); RegCloseKey(h); return e==ERROR_SUCCESS;}
bool DeleteDword(HKEY root,const std::wstring&sub,const wchar_t* name){HKEY h; if(RegOpenKeyExW(root,sub.c_str(),0,KEY_SET_VALUE,&h)!=ERROR_SUCCESS)return true; LONG e=RegDeleteValueW(h,name); RegCloseKey(h); return e==ERROR_SUCCESS||e==ERROR_FILE_NOT_FOUND;}

struct SvcState { std::wstring name; DWORD start=0; bool running=false; };
bool GetSvc(const wchar_t* name,SvcState& s){s.name=name; SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT); if(!scm)return false; SC_HANDLE h=OpenServiceW(scm,name,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS); if(!h){CloseServiceHandle(scm);return false;} DWORD n=0; QueryServiceConfigW(h,nullptr,0,&n); std::vector<BYTE>b(n); QUERY_SERVICE_CONFIGW*q=(QUERY_SERVICE_CONFIGW*)b.data(); bool ok=QueryServiceConfigW(h,q,n,&n); if(ok)s.start=q->dwStartType; SERVICE_STATUS st{}; if(QueryServiceStatus(h,&st))s.running=st.dwCurrentState==SERVICE_RUNNING; CloseServiceHandle(h);CloseServiceHandle(scm);return ok;}
bool SetSvc(const wchar_t* name,DWORD start,bool run){SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm)return false;SC_HANDLE h=OpenServiceW(scm,name,SERVICE_CHANGE_CONFIG|SERVICE_START|SERVICE_STOP|SERVICE_QUERY_STATUS);if(!h){CloseServiceHandle(scm);return false;}bool ok=ChangeServiceConfigW(h,SERVICE_NO_CHANGE,start,SERVICE_NO_CHANGE,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)!=FALSE;SERVICE_STATUS st{};if(run){if(QueryServiceStatus(h,&st)&&st.dwCurrentState!=SERVICE_RUNNING)ok=StartServiceW(h,0,nullptr)||GetLastError()==ERROR_SERVICE_ALREADY_RUNNING;}else if(QueryServiceStatus(h,&st)&&st.dwCurrentState==SERVICE_RUNNING)ok=ControlService(h,SERVICE_CONTROL_STOP,&st)!=FALSE||GetLastError()==ERROR_SERVICE_NOT_ACTIVE;CloseServiceHandle(h);CloseServiceHandle(scm);return ok;}

struct ComInit { HRESULT hr; ComInit():hr(CoInitializeEx(nullptr,COINIT_MULTITHREADED)){} ~ComInit(){if(SUCCEEDED(hr))CoUninitialize();} };
struct FirewallRuleSpec { int port; long protocol; const wchar_t* tag; };
const FirewallRuleSpec kFirewallRules[]={{22,NET_FW_IP_PROTOCOL_TCP,L"TCP-22"},{135,NET_FW_IP_PROTOCOL_TCP,L"TCP-135"},{136,NET_FW_IP_PROTOCOL_TCP,L"TCP-136"},{136,NET_FW_IP_PROTOCOL_UDP,L"UDP-136"},{137,NET_FW_IP_PROTOCOL_UDP,L"UDP-137"},{138,NET_FW_IP_PROTOCOL_UDP,L"UDP-138"},{139,NET_FW_IP_PROTOCOL_TCP,L"TCP-139"},{445,NET_FW_IP_PROTOCOL_TCP,L"TCP-445"},{3389,NET_FW_IP_PROTOCOL_TCP,L"TCP-3389"},{3389,NET_FW_IP_PROTOCOL_UDP,L"UDP-3389"}};

bool FindNamedRules(INetFwRules* rules,const std::wstring& name,DWORD& count,INetFwRule** first){
  count=0; if(first)*first=nullptr; IUnknown* unknown=nullptr;
  if(FAILED(rules->get__NewEnum(&unknown))||!unknown)return false;
  IEnumVARIANT* enumerator=nullptr; HRESULT hr=unknown->QueryInterface(IID_IEnumVARIANT,reinterpret_cast<void**>(&enumerator)); unknown->Release();
  if(FAILED(hr)||!enumerator)return false;
  VARIANT item; VariantInit(&item); ULONG fetched=0; bool ok=true;
  while((hr=enumerator->Next(1,&item,&fetched))==S_OK){
    if(item.vt==VT_DISPATCH&&item.pdispVal){
      INetFwRule* rule=nullptr;
      if(SUCCEEDED(item.pdispVal->QueryInterface(__uuidof(INetFwRule),reinterpret_cast<void**>(&rule)))&&rule){
        BSTR ruleName=nullptr;
        if(SUCCEEDED(rule->get_Name(&ruleName))&&ruleName&&name==ruleName){++count;if(first&&!*first)*first=rule;else rule->Release();}
        else rule->Release();
        SysFreeString(ruleName);
      }
    }
    VariantClear(&item); VariantInit(&item);
  }
  if(hr!=S_FALSE)ok=false; VariantClear(&item); enumerator->Release(); return ok;
}
bool RuleMatches(INetFwRule* rule,const FirewallRuleSpec& spec,long profiles){
  long protocol=0,actualProfiles=0; NET_FW_RULE_DIRECTION direction=NET_FW_RULE_DIR_MAX; NET_FW_ACTION action=NET_FW_ACTION_MAX; VARIANT_BOOL enabled=VARIANT_FALSE; BSTR ports=nullptr;
  bool ok=SUCCEEDED(rule->get_Protocol(&protocol))&&SUCCEEDED(rule->get_LocalPorts(&ports))&&SUCCEEDED(rule->get_Direction(&direction))&&SUCCEEDED(rule->get_Action(&action))&&SUCCEEDED(rule->get_Enabled(&enabled))&&SUCCEEDED(rule->get_Profiles(&actualProfiles));
  std::wstring expected=std::to_wstring(spec.port); ok=ok&&ports&&expected==ports&&protocol==spec.protocol&&direction==NET_FW_RULE_DIR_IN&&action==NET_FW_ACTION_BLOCK&&enabled==VARIANT_TRUE&&actualProfiles==profiles; SysFreeString(ports); return ok;
}
bool ConfigureRule(INetFwRule* rule,const std::wstring& name,const FirewallRuleSpec& spec,long profiles){
  BSTR ruleName=SysAllocString(name.c_str()),description=SysAllocString(L"Inbound hardening rule; managed by SecurityRemediator."),ports=SysAllocString(std::to_wstring(spec.port).c_str());
  if(!ruleName||!description||!ports){SysFreeString(ruleName);SysFreeString(description);SysFreeString(ports);return false;}
  bool ok=true; if(FAILED(rule->put_Name(ruleName)))ok=false; if(FAILED(rule->put_Description(description)))ok=false; if(FAILED(rule->put_Protocol(spec.protocol)))ok=false; if(FAILED(rule->put_LocalPorts(ports)))ok=false; if(FAILED(rule->put_Direction(NET_FW_RULE_DIR_IN)))ok=false; if(FAILED(rule->put_Action(NET_FW_ACTION_BLOCK)))ok=false; if(FAILED(rule->put_Enabled(VARIANT_TRUE)))ok=false; if(FAILED(rule->put_Profiles(profiles)))ok=false;
  SysFreeString(ruleName);SysFreeString(description);SysFreeString(ports);return ok;
}
bool RemoveAllNamedRules(INetFwRules* rules,const std::wstring& name){
  DWORD count=0; if(!FindNamedRules(rules,name,count,nullptr))return false;
  while(count>0){BSTR ruleName=SysAllocString(name.c_str());if(!ruleName)return false;HRESULT hr=rules->Remove(ruleName);SysFreeString(ruleName);if(FAILED(hr))return false;DWORD remaining=0;if(!FindNamedRules(rules,name,remaining,nullptr)||remaining>=count)return false;count=remaining;}
  return true;
}
bool EnsureRule(INetFwRules* rules,const FirewallRuleSpec& spec,long profiles){
  std::wstring name=kRulePrefix;name+=spec.tag; DWORD count=0;INetFwRule* existing=nullptr;if(!FindNamedRules(rules,name,count,&existing))return false;
  if(count==1&&existing){bool ok=RuleMatches(existing,spec,profiles)||(ConfigureRule(existing,name,spec,profiles)&&RuleMatches(existing,spec,profiles));existing->Release();return ok;}
  if(existing)existing->Release(); if(count>1){Log(L"清理重复防火墙规则: "+name+L"，原数量="+std::to_wstring(count));if(!RemoveAllNamedRules(rules,name))return false;}
  INetFwRule* rule=nullptr;if(FAILED(CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwRule),reinterpret_cast<void**>(&rule)))||!rule)return false;
  bool ok=ConfigureRule(rule,name,spec,profiles)&&SUCCEEDED(rules->Add(rule));rule->Release();if(!ok)return false;DWORD finalCount=0;return FindNamedRules(rules,name,finalCount,nullptr)&&finalCount==1;
}
bool Firewall(bool apply){ ComInit ci; if(FAILED(ci.hr)&&ci.hr!=RPC_E_CHANGED_MODE)return false; INetFwPolicy2*p=nullptr; HRESULT hr=CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),(void**)&p); if(FAILED(hr))return false; long profiles=NET_FW_PROFILE2_DOMAIN|NET_FW_PROFILE2_PRIVATE|NET_FW_PROFILE2_PUBLIC; bool ok=true; if(!apply){p->Release();return true;} VARIANT_BOOL en=VARIANT_TRUE; for(NET_FW_PROFILE_TYPE2 bit: {(NET_FW_PROFILE_TYPE2)NET_FW_PROFILE2_DOMAIN,(NET_FW_PROFILE_TYPE2)NET_FW_PROFILE2_PRIVATE,(NET_FW_PROFILE_TYPE2)NET_FW_PROFILE2_PUBLIC}) if(FAILED(p->put_FirewallEnabled(bit,en)))ok=false;
  INetFwRules*rs=nullptr;if(SUCCEEDED(p->get_Rules(&rs))&&rs){for(const auto& rule:kFirewallRules)if(!EnsureRule(rs,rule,profiles))ok=false;rs->Release();}else ok=false;p->Release();return ok; }
bool RemoveRules(){ComInit ci;INetFwPolicy2*p=nullptr;if(FAILED(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),(void**)&p)))return false;INetFwRules*rs=nullptr;bool ok=SUCCEEDED(p->get_Rules(&rs))&&rs;if(ok){for(const auto& rule:kFirewallRules){std::wstring name=kRulePrefix;name+=rule.tag;if(!RemoveAllNamedRules(rs,name))ok=false;}rs->Release();}p->Release();return ok;}

std::wstring StateFile(){wchar_t p[MAX_PATH];SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,p);std::wstring d=Join(p,kProduct);CreateDirectoryW(d.c_str(),nullptr);return Join(d,L"backup.state");}
bool StateNumber(const std::wstring& value){return !value.empty()&&std::all_of(value.begin(),value.end(),[](wchar_t c){return c>=L'0'&&c<=L'9';});}
bool ValidStateFile(const std::wstring& path){std::wifstream f(path);if(!f)return false;bool server=false,term=false,rdp=false;std::wstring line;while(std::getline(f,line)){std::wistringstream s(line);std::wstring kind,a,b,c;std::getline(s,kind,L'|');if(kind==L"SVC"){std::getline(s,a,L'|');std::getline(s,b,L'|');std::getline(s,c,L'|');if(!StateNumber(b)||(c!=L"0"&&c!=L"1"))return false;if(a==L"LanmanServer")server=true;else if(a==L"TermService")term=true;else return false;}else if(kind==L"RDP"){std::getline(s,a,L'|');std::getline(s,b,L'|');if((a!=L"0"&&a!=L"1")||!StateNumber(b))return false;rdp=true;}else if(kind==L"NBT"){std::getline(s,a,L'|');std::getline(s,b,L'|');std::getline(s,c,L'|');if(a.empty()||(b!=L"0"&&b!=L"1")||!StateNumber(c))return false;}else return false;}return server&&term&&rdp;}
void SaveState(){backupPath=StateFile();if(ValidStateFile(backupPath)){Log(L"保留已有初始备份，不重复覆盖");return;}std::wofstream f(backupPath,std::ios::trunc);SvcState a,b;GetSvc(L"LanmanServer",a);GetSvc(L"TermService",b);DWORD r=0;bool re=false;RegDword(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",L"fDenyTSConnections",r,re);f<<L"SVC|LanmanServer|"<<a.start<<L"|"<<a.running<<L"\nSVC|TermService|"<<b.start<<L"|"<<b.running<<L"\nRDP|"<<re<<L"|"<<r<<L"\n";HKEY h=nullptr; if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces",0,KEY_READ,&h)==ERROR_SUCCESS){DWORD i=0;wchar_t n[256];DWORD ns=_countof(n);while(RegEnumKeyExW(h,i++,n,&ns,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS){std::wstring sub=L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\"+std::wstring(n);DWORD v=0;bool ex=false;RegDword(HKEY_LOCAL_MACHINE,sub,L"NetbiosOptions",v,ex);f<<L"NBT|"<<n<<L"|"<<ex<<L"|"<<v<<L"\n";ns=_countof(n);}RegCloseKey(h);}}
void MarkFail(const std::wstring&s){++failures;Log(L"失败: "+s+L" "+Err());}
bool Apply(bool audit){if(!IsAuthorized()){Log(L"需要 SYSTEM 或已提权的管理员权限");return false;} if(!audit)SaveState(); bool ok=true; if(!Firewall(!audit)){MarkFail(L"防火墙");ok=false;} if(audit){SvcState s,t;GetSvc(L"LanmanServer",s);GetSvc(L"TermService",t);DWORD v=0;bool ex=false;RegDword(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",L"fDenyTSConnections",v,ex);if(s.running||s.start!=SERVICE_DISABLED){Log(L"不合规: Server 服务");ok=false;}if(t.running||t.start!=SERVICE_DISABLED||!ex||v!=1){Log(L"不合规: 远程桌面");ok=false;}return ok;} if(!SetSvc(L"LanmanServer",SERVICE_DISABLED,false)){MarkFail(L"关闭 Server 服务");ok=false;}else changed=true;if(!SetSvc(L"TermService",SERVICE_DISABLED,false)){MarkFail(L"关闭远程桌面服务");ok=false;}else changed=true;if(!SetDword(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",L"fDenyTSConnections",1)){MarkFail(L"禁用远程桌面");ok=false;}else changed=true;HKEY h; if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces",0,KEY_READ,&h)==ERROR_SUCCESS){DWORD i=0;wchar_t n[256];DWORD ns=_countof(n);while(RegEnumKeyExW(h,i++,n,&ns,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS){std::wstring sub=L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\"+std::wstring(n);if(!SetDword(HKEY_LOCAL_MACHINE,sub,L"NetbiosOptions",2)){MarkFail(L"禁用 NetBIOS");ok=false;}else changed=true;ns=_countof(n);}RegCloseKey(h);}return ok;}
bool Rollback(){std::wifstream f(StateFile());if(!f)return false;RemoveRules();std::wstring l;while(std::getline(f,l)){std::wistringstream s(l);std::wstring k,a,b,c;std::getline(s,k,L'|');if(k==L"SVC"){std::getline(s,a,L'|');std::getline(s,b,L'|');std::getline(s,c,L'|');SetSvc(a.c_str(),std::stoul(b),c==L"1");}else if(k==L"RDP"){std::getline(s,a,L'|');std::getline(s,b,L'|');if(a==L"1")SetDword(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",L"fDenyTSConnections",std::stoul(b));else DeleteDword(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",L"fDenyTSConnections");}else if(k==L"NBT"){std::getline(s,a,L'|');std::getline(s,b,L'|');std::getline(s,c,L'|');std::wstring sub=L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\"+a;if(b==L"1")SetDword(HKEY_LOCAL_MACHINE,sub,L"NetbiosOptions",std::stoul(c));else DeleteDword(HKEY_LOCAL_MACHINE,sub,L"NetbiosOptions");}}return true;}
}

#if 0
int WINAPI wWinMain(HINSTANCE,HINSTANCE,LPWSTR,int){int argc=0;LPWSTR*av=CommandLineToArgvW(GetCommandLineW(),&argc);std::wstring mode=L"apply";for(int i=1;i<argc;i++){if(!_wcsicmp(av[i],L"/audit"))mode=L"audit";else if(!_wcsicmp(av[i],L"/rollback"))mode=L"rollback";else if(!_wcsicmp(av[i],L"/apply"))mode=L"apply";else if(!_wcsicmp(av[i],L"/log-dir")&&i+1<argc)logDir=av[++i];else if(!_wcsicmp(av[i],L"/rules")||!_wcsicmp(av[i],L"/signature")){++i;}}
if(logDir.empty()){wchar_t p[MAX_PATH];SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,p);logDir=Join(Join(p,kProduct),L"Logs");}CreateDirectoryW(Join(logDir,kProduct).c_str(),nullptr);logDir=Join(logDir,kProduct);CreateDirectoryW(logDir.c_str(),nullptr);SYSTEMTIME t;GetLocalTime(&t);wchar_t fn[64];swprintf_s(fn,L"%04u%02u%02u-%02u%02u%02u.log",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);logFile.open(Join(logDir,fn),std::ios::out);Log(L"SecurityRemediator 1.0 开始");int rc=0;if(mode==L"rollback")rc=Rollback()?0:1;else if(!IsSystem())rc=3;else if(mode==L"audit")rc=Apply(true)?0:5;else rc=Apply(false)?(rebootNeeded?4:0):1;Log(rc==0?L"完成":L"未完成");logFile.close();LocalFree(av);return rc;}
#endif

#define IsSystem IsAuthorized
int WINAPI wWinMain(HINSTANCE,HINSTANCE,LPWSTR,int){int argc=0;LPWSTR*av=CommandLineToArgvW(GetCommandLineW(),&argc);std::wstring mode=L"apply";bool bad=false;for(int i=1;i<argc;i++){if(!_wcsicmp(av[i],L"/audit"))mode=L"audit";else if(!_wcsicmp(av[i],L"/rollback"))mode=L"rollback";else if(!_wcsicmp(av[i],L"/apply"))mode=L"apply";else if(!_wcsicmp(av[i],L"/log-dir")&&i+1<argc)logDir=av[++i];else bad=true;}if(logDir.empty()){wchar_t p[MAX_PATH];SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,p);logDir=Join(Join(p,kProduct),L"Logs");}CreateDirectoryW(logDir.c_str(),nullptr);SYSTEMTIME t;GetLocalTime(&t);wchar_t fn[64];swprintf_s(fn,L"%04u%02u%02u-%02u%02u%02u.log",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);logFile.open(Join(logDir,fn),std::ios::out);Log(L"SecurityRemediator started");int rc=0;if(bad)rc=2;else if(mode==L"rollback")rc=Rollback()?0:1;else if(!IsSystem())rc=3;else if(mode==L"audit")rc=Apply(true)?0:5;else rc=Apply(false)?(rebootNeeded?4:0):1;std::wofstream jf(Join(logDir,L"last-result.json"),std::ios::trunc);jf<<L"{\"exitCode\":"<<rc<<L",\"mode\":\""<<mode<<L"\",\"changed\":"<<(changed?L"true":L"false")<<L",\"failures\":"<<failures<<L"}\n";jf.close();Log(rc==0?L"completed":L"incomplete");logFile.close();LocalFree(av);return rc;}
