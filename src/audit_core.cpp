#define _WIN32_WINNT 0x0601
#include "audit_core.h"
#include "win7_fs.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netfw.h>
#include <objbase.h>
#include <setupapi.h>
#include <sqlite3.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <regex>
#include <set>
#include <sstream>

namespace sr {
namespace {
std::wstring Clean(const std::wstring &value) {
  std::wstring out = value;
  for (auto &c : out)
    if (c == L'\r' || c == L'\n' || c == L'\t')
      c = L' ';
  return out.empty() ? L"-" : out;
}
std::wstring Utf16(const std::string &value) {
  if (value.empty())
    return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                              static_cast<int>(value.size()), nullptr, 0);
  std::wstring out(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      out.data(), n);
  return out;
}
std::string Utf8(const std::wstring &value) {
  if (value.empty())
    return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                              static_cast<int>(value.size()), nullptr, 0,
                              nullptr, nullptr);
  std::string out(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      out.data(), n, nullptr, nullptr);
  return out;
}
std::wstring Html(const std::wstring &value) {
  std::wstring out;
  for (wchar_t c : value) {
    if (c == L'&')
      out += L"&amp;";
    else if (c == L'<')
      out += L"&lt;";
    else if (c == L'>')
      out += L"&gt;";
    else if (c == L'\"')
      out += L"&quot;";
    else if (c == L'\'')
      out += L"&#39;";
    else
      out += c;
  }
  return out;
}
std::wstring Json(const std::wstring &value) {
  std::wostringstream o;
  o << L'\"';
  for (wchar_t c : value) {
    switch (c) {
    case L'\"':
      o << L"\\\"";
      break;
    case L'\\':
      o << L"\\\\";
      break;
    case L'\b':
      o << L"\\b";
      break;
    case L'\f':
      o << L"\\f";
      break;
    case L'\n':
      o << L"\\n";
      break;
    case L'\r':
      o << L"\\r";
      break;
    case L'\t':
      o << L"\\t";
      break;
    default:
      if (c < 32)
        o << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0')
          << static_cast<int>(c) << std::dec;
      else
        o << c;
    }
  }
  o << L'\"';
  return o.str();
}
std::wstring Now(const wchar_t *format = L"%Y-%m-%d %H:%M:%S") {
  SYSTEMTIME t{};
  GetLocalTime(&t);
  wchar_t b[80]{};
  swprintf_s(b, format, t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
             t.wSecond, t.wMilliseconds);
  return b;
}
std::wstring Env(const wchar_t *name) {
  DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
  if (!n)
    return {};
  std::wstring v(n, L'\0');
  GetEnvironmentVariableW(name, v.data(), n);
  v.resize(wcslen(v.c_str()));
  return v;
}
std::wstring RegString(HKEY key, const wchar_t *name) {
  DWORD type = 0, size = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) !=
          ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ))
    return {};
  std::wstring value(size / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, name, nullptr, &type,
                       reinterpret_cast<BYTE *>(value.data()),
                       &size) != ERROR_SUCCESS)
    return {};
  value.resize(wcslen(value.c_str()));
  if (type == REG_EXPAND_SZ) {
    DWORD n = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    std::wstring expanded(n, L'\0');
    ExpandEnvironmentStringsW(value.c_str(), expanded.data(), n);
    expanded.resize(wcslen(expanded.c_str()));
    return expanded;
  }
  return value;
}
bool RegDword(HKEY root, const wchar_t *path, const wchar_t *name,
              DWORD &value) {
  HKEY key{};
  if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &key) !=
      ERROR_SUCCESS)
    return false;
  DWORD type = 0, size = sizeof(value);
  LONG e = RegQueryValueExW(key, name, nullptr, &type,
                            reinterpret_cast<BYTE *>(&value), &size);
  RegCloseKey(key);
  return e == ERROR_SUCCESS && type == REG_DWORD;
}
std::vector<std::wstring> Subkeys(HKEY root, const wchar_t *path,
                                  REGSAM extra = KEY_WOW64_64KEY) {
  std::vector<std::wstring> result;
  HKEY key{};
  if (RegOpenKeyExW(root, path, 0, KEY_READ | extra, &key) != ERROR_SUCCESS)
    return result;
  DWORD count = 0, maxLen = 0;
  RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &count, &maxLen, nullptr,
                   nullptr, nullptr, nullptr, nullptr, nullptr);
  std::vector<wchar_t> name(maxLen + 2);
  for (DWORD i = 0; i < count; i++) {
    DWORD n = maxLen + 1;
    if (RegEnumKeyExW(key, i, name.data(), &n, nullptr, nullptr, nullptr,
                      nullptr) == ERROR_SUCCESS)
      result.emplace_back(name.data(), n);
  }
  RegCloseKey(key);
  return result;
}
void Add(AuditResult &r, std::wstring item, std::wstring expected,
         std::wstring actual, Verdict verdict) {
  r.summary.push_back(
      {std::move(item), std::move(expected), std::move(actual), verdict});
  if (verdict == Verdict::Pass)
    r.passed++;
  else if (verdict == Verdict::Fail)
    r.failed++;
  else if (verdict == Verdict::Review)
    r.review++;
}
std::wstring VerdictText(Verdict v) {
  switch (v) {
  case Verdict::Pass:
    return L"通过";
  case Verdict::Fail:
    return L"异常";
  case Verdict::Review:
    return L"需复核";
  case Verdict::NotApplicable:
    return L"不适用";
  default:
    return L"已识别";
  }
}
std::wstring VerdictClass(Verdict v) {
  switch (v) {
  case Verdict::Pass:
    return L"pass";
  case Verdict::Fail:
    return L"fail";
  case Verdict::Review:
    return L"review";
  case Verdict::NotApplicable:
    return L"na";
  default:
    return L"info";
  }
}

void Identity(AuditResult &r) {
  wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
  DWORD n = static_cast<DWORD>(std::size(computer));
  GetComputerNameW(computer, &n);
  r.computer = computer;
  wchar_t user[512]{};
  n = static_cast<DWORD>(std::size(user));
  GetUserNameW(user, &n);
  r.executionIdentity = user;
  PSID systemSid = nullptr;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0,
                               0, 0, &systemSid)) {
    BOOL member = FALSE;
    CheckTokenMembership(nullptr, systemSid, &member);
    if (member)
      r.executionIdentity = L"SYSTEM";
    FreeSid(systemSid);
  }
}
bool LooksVirtualOrLoopback(const IP_ADAPTER_ADDRESSES &adapter) {
  std::wstring text = adapter.FriendlyName ? adapter.FriendlyName : L"";
  text += L" ";
  text += adapter.Description ? adapter.Description : L"";
  std::transform(text.begin(), text.end(), text.begin(), towlower);
  for (const wchar_t *marker :
       {L"loopback", L"环回", L"km-test", L"virtual", L"host-only",
        L"vmware", L"hyper-v", L"vethernet", L"虚拟", L"wan miniport"})
    if (text.find(marker) != std::wstring::npos)
      return true;
  return false;
}
void NetworkIdentity(AuditResult &r) {
  ULONG size = 16000;
  std::vector<BYTE> data(size);
  auto *addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(data.data());
  ULONG status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS,
                                      nullptr, addresses, &size);
  if (status == ERROR_BUFFER_OVERFLOW) {
    data.resize(size);
    addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(data.data());
    status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, nullptr,
                                  addresses, &size);
  }
  if (status != NO_ERROR) {
    r.ip = L"UNKNOWN";
    r.mac = L"UNKNOWN";
    r.adapter = L"未识别";
    return;
  }
  int bestScore = -1;
  for (auto *a = addresses; a; a = a->Next) {
    if (a->OperStatus != IfOperStatusUp ||
        a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == IF_TYPE_TUNNEL ||
        LooksVirtualOrLoopback(*a))
      continue;
    const sockaddr_in *selected = nullptr;
    for (auto *u = a->FirstUnicastAddress; u; u = u->Next) {
      if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET)
        continue;
      const auto *candidate =
          reinterpret_cast<const sockaddr_in *>(u->Address.lpSockaddr);
      const ULONG host = ntohl(candidate->sin_addr.s_addr);
      if (host == 0 || (host >> 24) == 127)
        continue;
      selected = candidate;
      break;
    }
    if (!selected)
      continue;
    MIB_IF_ROW2 interfaceRow{};
    interfaceRow.InterfaceLuid = a->Luid;
    const bool hardware = GetIfEntry2(&interfaceRow) == NO_ERROR &&
                          interfaceRow.InterfaceAndOperStatusFlags.HardwareInterface;
    int score = a->FirstGatewayAddress ? 100 : 0;
    if (hardware)
      score += 50;
    if (a->IfType == IF_TYPE_ETHERNET_CSMACD)
      score += 120;
    else if (a->IfType == IF_TYPE_IEEE80211)
      score += 15;
    if (GetIfEntry2(&interfaceRow) == NO_ERROR &&
        interfaceRow.PhysicalMediumType != NdisPhysicalMediumUnspecified)
      score += 20;
    if (a->PhysicalAddressLength >= 6)
      score += 10;
    const ULONG host = ntohl(selected->sin_addr.s_addr);
    if ((host & 0xFFFF0000u) == 0xA9FE0000u)
      score -= 80;
    if (score <= bestScore)
      continue;
    wchar_t ip[INET_ADDRSTRLEN]{};
    InetNtopW(AF_INET, &selected->sin_addr, ip, INET_ADDRSTRLEN);
    std::wostringstream mac;
    for (ULONG i = 0; i < a->PhysicalAddressLength; i++) {
      if (i)
        mac << L'-';
      mac << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0')
          << static_cast<int>(a->PhysicalAddress[i]);
    }
    bestScore = score;
    r.ip = ip;
    r.adapter = a->FriendlyName ? a->FriendlyName : L"-";
    r.mac = mac.str().empty() ? L"UNKNOWN" : mac.str();
  }
  if (bestScore >= 0)
    return;
  r.ip = L"UNKNOWN";
  r.mac = L"UNKNOWN";
  r.adapter = L"未识别";
}

std::wstring ServiceStateText(DWORD value) {
  switch (value) {
  case SERVICE_STOPPED:
    return L"已停止";
  case SERVICE_START_PENDING:
    return L"正在启动";
  case SERVICE_STOP_PENDING:
    return L"正在停止";
  case SERVICE_RUNNING:
    return L"正在运行";
  case SERVICE_CONTINUE_PENDING:
    return L"正在继续";
  case SERVICE_PAUSE_PENDING:
    return L"正在暂停";
  case SERVICE_PAUSED:
    return L"已暂停";
  default:
    return L"未知状态（" + std::to_wstring(value) + L"）";
  }
}
std::wstring ServiceStartText(DWORD value) {
  switch (value) {
  case SERVICE_AUTO_START:
    return L"自动";
  case SERVICE_BOOT_START:
    return L"引导启动";
  case SERVICE_SYSTEM_START:
    return L"系统启动";
  case SERVICE_DEMAND_START:
    return L"手动";
  case SERVICE_DISABLED:
    return L"已禁用";
  default:
    return L"未知类型（" + std::to_wstring(value) + L"）";
  }
}
void ServiceCheck(AuditResult &r, const wchar_t *service,
                  const wchar_t *display) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm) {
    Add(r, display, L"已停止、已禁用", L"无法打开服务管理器", Verdict::Fail);
    return;
  }
  SC_HANDLE handle =
      OpenServiceW(scm, service, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
  if (!handle) {
    CloseServiceHandle(scm);
    Add(r, display, L"已停止、已禁用", L"无法读取服务", Verdict::Fail);
    return;
  }
  SERVICE_STATUS_PROCESS state{};
  DWORD needed = 0;
  bool stateOk = QueryServiceStatusEx(handle, SC_STATUS_PROCESS_INFO,
                                      reinterpret_cast<BYTE *>(&state),
                                      sizeof(state), &needed) != FALSE;
  QueryServiceConfigW(handle, nullptr, 0, &needed);
  std::vector<BYTE> data(needed);
  auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(data.data());
  bool configOk = QueryServiceConfigW(handle, config, needed, &needed) != FALSE;
  bool stopped = stateOk && state.dwCurrentState == SERVICE_STOPPED,
       disabled = configOk && config->dwStartType == SERVICE_DISABLED;
  std::wstring actual =
      L"状态=" +
      (!stateOk ? std::wstring(L"无法读取")
                : ServiceStateText(state.dwCurrentState)) +
      L"，启动类型=" +
      (configOk ? ServiceStartText(config->dwStartType) : L"无法读取");
  Add(r, display, L"已停止、已禁用", actual,
      stopped && disabled ? Verdict::Pass : Verdict::Fail);
  CloseServiceHandle(handle);
  CloseServiceHandle(scm);
}
void RdpCheck(AuditResult &r) {
  DWORD v = 0;
  bool ok = RegDword(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                     L"fDenyTSConnections", v);
  Add(r, L"远程桌面连接策略", L"禁止连接（值为1）",
      ok ? (v == 1 ? L"已禁止连接（值为1）" : L"当前值=" + std::to_wstring(v))
         : L"无法读取",
      ok && v == 1 ? Verdict::Pass : Verdict::Fail);
}

void FirewallCheck(AuditResult &r) {
  struct Expected {
    const wchar_t *tag;
    long protocol;
    const wchar_t *port;
  };
  const Expected expected[] = {{L"TCP-22", NET_FW_IP_PROTOCOL_TCP, L"22"},
                               {L"TCP-135", NET_FW_IP_PROTOCOL_TCP, L"135"},
                               {L"TCP-136", NET_FW_IP_PROTOCOL_TCP, L"136"},
                               {L"UDP-136", NET_FW_IP_PROTOCOL_UDP, L"136"},
                               {L"UDP-137", NET_FW_IP_PROTOCOL_UDP, L"137"},
                               {L"UDP-138", NET_FW_IP_PROTOCOL_UDP, L"138"},
                               {L"TCP-139", NET_FW_IP_PROTOCOL_TCP, L"139"},
                               {L"TCP-445", NET_FW_IP_PROTOCOL_TCP, L"445"},
                               {L"TCP-3389", NET_FW_IP_PROTOCOL_TCP, L"3389"},
                               {L"UDP-3389", NET_FW_IP_PROTOCOL_UDP, L"3389"}};
  DetailTable table{
      L"防火墙规则逐项明细", {L"规则", L"预期", L"实际数量", L"结论"}, {}};
  HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  INetFwPolicy2 *policy = nullptr;
  HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                                CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                reinterpret_cast<void **>(&policy));
  if (FAILED(hr)) {
    for (const auto &e : expected) {
      Add(r, L"防火墙规则 " + std::wstring(e.tag), L"恰好保留1条", L"无法读取",
          Verdict::Fail);
    }
    if (SUCCEEDED(init))
      CoUninitialize();
    return;
  }
  VARIANT_BOOL enabled = VARIANT_FALSE;
  bool allEnabled = true;
  for (long profile : {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
                       NET_FW_PROFILE2_PUBLIC})
    if (FAILED(policy->get_FirewallEnabled(static_cast<NET_FW_PROFILE_TYPE2>(profile), &enabled)) ||
        enabled != VARIANT_TRUE)
      allEnabled = false;
  Add(r, L"Windows 防火墙配置文件", L"域、专用、公用均启用",
      allEnabled ? L"全部启用" : L"至少一个未启用或无法读取",
      allEnabled ? Verdict::Pass : Verdict::Fail);
  INetFwRules *rules = nullptr;
  policy->get_Rules(&rules);
  std::map<std::wstring, int> counts;
  if (rules) {
    IUnknown *unknown = nullptr;
    if (SUCCEEDED(rules->get__NewEnum(&unknown)) && unknown) {
      IEnumVARIANT *values = nullptr;
      if (SUCCEEDED(unknown->QueryInterface(IID_PPV_ARGS(&values)))) {
        VARIANT value;
        VariantInit(&value);
        ULONG fetched = 0;
        while (values->Next(1, &value, &fetched) == S_OK) {
          if (value.vt == VT_DISPATCH && value.pdispVal) {
            INetFwRule *rule = nullptr;
            if (SUCCEEDED(
                    value.pdispVal->QueryInterface(IID_PPV_ARGS(&rule)))) {
              BSTR name = nullptr;
              rule->get_Name(&name);
              if (name) {
                counts[name]++;
                SysFreeString(name);
              }
              rule->Release();
            }
          }
          VariantClear(&value);
        }
        values->Release();
      }
      unknown->Release();
    }
    rules->Release();
  }
  for (const auto &e : expected) {
    std::wstring name = L"SecurityRemediator - Block " + std::wstring(e.tag);
    int count = counts[name];
    Verdict v = count == 1 ? Verdict::Pass : Verdict::Fail;
    Add(r, L"防火墙规则 " + std::wstring(e.tag), L"恰好保留1条",
        std::to_wstring(count) + L"条" +
            (count == 0  ? L"，缺失"
             : count > 1 ? L"，存在重复"
                         : L""),
        v);
    table.rows.push_back(
        {e.tag, L"1条", std::to_wstring(count) + L"条", VerdictText(v)});
  }
  r.details.push_back(std::move(table));
  policy->Release();
  if (SUCCEEDED(init))
    CoUninitialize();
}

void NetbiosCheck(AuditResult &r) {
  const wchar_t *path =
      L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces";
  HKEY root{};
  DetailTable table{L"NetBIOS 网卡逐项明细",
                    {L"网卡接口", L"预期值", L"实际值", L"结论"},
                    {}};
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY,
                    &root) != ERROR_SUCCESS) {
    Add(r, L"NetBIOS 配置汇总", L"所有网卡均禁用（值为2）", L"读取失败",
        Verdict::Fail);
    return;
  }
  DWORD count = 0, maxLen = 0;
  RegQueryInfoKeyW(root, nullptr, nullptr, nullptr, &count, &maxLen, nullptr,
                   nullptr, nullptr, nullptr, nullptr, nullptr);
  int passed = 0;
  std::vector<wchar_t> name(maxLen + 2);
  for (DWORD i = 0; i < count; i++) {
    DWORD n = maxLen + 1;
    if (RegEnumKeyExW(root, i, name.data(), &n, nullptr, nullptr, nullptr,
                      nullptr) != ERROR_SUCCESS)
      continue;
    HKEY key{};
    DWORD v = 0, type = 0, size = sizeof(v);
    bool ok =
        RegOpenKeyExW(root, name.data(), 0, KEY_READ, &key) == ERROR_SUCCESS &&
        RegQueryValueExW(key, L"NetbiosOptions", nullptr, &type,
                         reinterpret_cast<BYTE *>(&v),
                         &size) == ERROR_SUCCESS &&
        type == REG_DWORD;
    if (key)
      RegCloseKey(key);
    if (ok && v == 2)
      passed++;
    table.rows.push_back({std::wstring(name.data(), n), L"2（禁用）",
                          ok ? std::to_wstring(v) : L"读取失败",
                          ok && v == 2 ? L"通过" : L"异常"});
  }
  RegCloseKey(root);
  Add(r, L"NetBIOS 配置汇总", L"所有网卡均禁用（值为2）",
      std::to_wstring(passed) + L"/" + std::to_wstring(table.rows.size()) +
          L"个网卡为禁用",
      !table.rows.empty() && passed == static_cast<int>(table.rows.size())
          ? Verdict::Pass
          : Verdict::Fail);
  r.details.push_back(std::move(table));
}

void ListenerCheck(AuditResult &r) {
  DetailTable details{L"相关端口监听逐项明细",
                      {L"协议", L"本地地址", L"端口", L"进程 PID"}, {}};
  int tcpCount = 0, udpCount = 0;
  DWORD size = 0;
  GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                      TCP_TABLE_OWNER_PID_LISTENER, 0);
  std::vector<BYTE> data(size);
  if (GetExtendedTcpTable(data.data(), &size, FALSE, AF_INET,
                          TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR) {
    auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(data.data());
    std::set<int> targets = {22, 135, 136, 139, 445, 3389};
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
      const auto &row = table->table[i];
      int port = ntohs(static_cast<u_short>(row.dwLocalPort));
      if (!targets.count(port))
        continue;
      IN_ADDR address{};
      address.S_un.S_addr = row.dwLocalAddr;
      wchar_t text[INET_ADDRSTRLEN]{};
      InetNtopW(AF_INET, &address, text, static_cast<DWORD>(std::size(text)));
      details.rows.push_back({L"TCP", text, std::to_wstring(port),
                              std::to_wstring(row.dwOwningPid)});
      tcpCount++;
    }
  }
  size = 0;
  GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET,
                      UDP_TABLE_OWNER_PID, 0);
  data.assign(size, 0);
  if (GetExtendedUdpTable(data.data(), &size, FALSE, AF_INET,
                          UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
    auto *table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID *>(data.data());
    std::set<int> targets = {136, 137, 138, 3389};
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
      const auto &row = table->table[i];
      int port = ntohs(static_cast<u_short>(row.dwLocalPort));
      if (!targets.count(port))
        continue;
      IN_ADDR address{};
      address.S_un.S_addr = row.dwLocalAddr;
      wchar_t text[INET_ADDRSTRLEN]{};
      InetNtopW(AF_INET, &address, text, static_cast<DWORD>(std::size(text)));
      details.rows.push_back({L"UDP", text, std::to_wstring(port),
                              std::to_wstring(row.dwOwningPid)});
      udpCount++;
    }
  }
  Add(r, L"端口外部连通性", L"其他电脑无法连接目标端口",
      L"本机发现" + std::to_wstring(tcpCount + udpCount) +
          L"条相关监听记录（TCP " + std::to_wstring(tcpCount) + L"条，UDP " +
          std::to_wstring(udpCount) + L"条），见明细",
      Verdict::Review);
  r.details.push_back(std::move(details));
}

std::wstring RegTime(HKEY key, const wchar_t *name) {
  DWORD type = 0, size = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) !=
          ERROR_SUCCESS ||
      type != REG_BINARY || size < 16)
    return L"-";
  std::vector<BYTE> b(size);
  RegQueryValueExW(key, name, nullptr, &type, b.data(), &size);
  const auto word = [&](int at) {
    return *reinterpret_cast<const WORD *>(b.data() + at);
  };
  wchar_t text[32]{};
  swprintf_s(text, L"%04u-%02u-%02u %02u:%02u:%02u", word(0), word(2), word(6),
             word(8), word(10), word(12));
  return text;
}
void NetworkHistory(AuditResult &r) {
  const wchar_t *path =
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
  HKEY root{};
  DetailTable table{L"网络配置注册表记录逐项明细",
                    {L"GUID", L"网络名称", L"描述", L"类别", L"类型",
                     L"创建时间", L"最后连接时间"},
                    {}};
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY,
                    &root) != ERROR_SUCCESS) {
    Add(r, L"网络配置记录", L"能够正常读取", L"读取失败", Verdict::Fail);
    return;
  }
  DWORD count = 0, maxLen = 0;
  RegQueryInfoKeyW(root, nullptr, nullptr, nullptr, &count, &maxLen, nullptr,
                   nullptr, nullptr, nullptr, nullptr, nullptr);
  std::vector<wchar_t> name(maxLen + 2);
  int wireless = 0, unknown = 0;
  for (DWORD i = 0; i < count; i++) {
    DWORD n = maxLen + 1;
    if (RegEnumKeyExW(root, i, name.data(), &n, nullptr, nullptr, nullptr,
                      nullptr) != ERROR_SUCCESS)
      continue;
    HKEY key{};
    if (RegOpenKeyExW(root, name.data(), 0, KEY_READ, &key) != ERROR_SUCCESS)
      continue;
    DWORD category = 99, type = 0, valueType = 0, size = sizeof(DWORD);
    RegQueryValueExW(key, L"Category", nullptr, &valueType,
                     reinterpret_cast<BYTE *>(&category), &size);
    size = sizeof(DWORD);
    bool typeOk = RegQueryValueExW(key, L"NameType", nullptr, &valueType,
                                   reinterpret_cast<BYTE *>(&type),
                                   &size) == ERROR_SUCCESS &&
                  valueType == REG_DWORD;
    std::wstring kind = typeOk && type == 71  ? L"无线"
                        : typeOk && type == 6 ? L"有线"
                                              : L"未知";
    if (kind == L"无线")
      wireless++;
    else if (kind == L"未知")
      unknown++;
    std::wstring cat = category == 0   ? L"公用"
                       : category == 1 ? L"专用"
                       : category == 2 ? L"域"
                                       : std::to_wstring(category);
    table.rows.push_back(
        {std::wstring(name.data(), n), Clean(RegString(key, L"ProfileName")),
         Clean(RegString(key, L"Description")), cat,
         kind + (typeOk ? L"（NameType=" + std::to_wstring(type) + L"）"
                        : L"（字段缺失）"),
         RegTime(key, L"DateCreated"), RegTime(key, L"DateLastConnected")});
    RegCloseKey(key);
  }
  RegCloseKey(root);
  const Verdict historyVerdict = wireless > 0   ? Verdict::Fail
                                 : unknown > 0 ? Verdict::Review
                                               : Verdict::Pass;
  Add(r, L"网络配置记录", L"无线记录为0条；未知类型需人工确认",
      L"共" + std::to_wstring(table.rows.size()) + L"条；无线" +
          std::to_wstring(wireless) + L"条；未知" + std::to_wstring(unknown) +
          L"条",
      historyVerdict);
  r.details.push_back(std::move(table));
}

struct RegistryDeviceRecord {
  std::wstring type;
  std::wstring instance;
  std::wstring friendlyName;
  std::wstring description;
  std::wstring manufacturer;
  std::wstring containerId;
};

struct RegistryDeviceTree {
  std::vector<RegistryDeviceRecord> records;
  DWORD error = ERROR_SUCCESS;
};

RegistryDeviceTree ReadRegistryDeviceTree(const wchar_t *path) {
  RegistryDeviceTree result;
  HKEY root = nullptr;
  LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
                              KEY_READ | KEY_WOW64_64KEY, &root);
  if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
    return result;
  if (status != ERROR_SUCCESS) {
    result.error = static_cast<DWORD>(status);
    return result;
  }
  auto fail = [&](LONG error) {
    if (result.error == ERROR_SUCCESS)
      result.error = static_cast<DWORD>(error);
  };
  DWORD types = 0, maxType = 0;
  status = RegQueryInfoKeyW(root, nullptr, nullptr, nullptr, &types, &maxType,
                            nullptr, nullptr, nullptr, nullptr, nullptr,
                            nullptr);
  if (status != ERROR_SUCCESS) {
    fail(status);
    RegCloseKey(root);
    return result;
  }
  std::vector<wchar_t> typeName(maxType + 2);
  for (DWORD i = 0; i < types; i++) {
    DWORD typeLength = maxType + 1;
    status = RegEnumKeyExW(root, i, typeName.data(), &typeLength, nullptr,
                           nullptr, nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
      fail(status);
      continue;
    }
    HKEY typeKey = nullptr;
    status = RegOpenKeyExW(root, typeName.data(), 0, KEY_READ, &typeKey);
    if (status != ERROR_SUCCESS) {
      fail(status);
      continue;
    }
    DWORD instances = 0, maxInstance = 0;
    status = RegQueryInfoKeyW(typeKey, nullptr, nullptr, nullptr, &instances,
                              &maxInstance, nullptr, nullptr, nullptr, nullptr,
                              nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
      fail(status);
      RegCloseKey(typeKey);
      continue;
    }
    std::vector<wchar_t> instanceName(maxInstance + 2);
    for (DWORD j = 0; j < instances; j++) {
      DWORD instanceLength = maxInstance + 1;
      status = RegEnumKeyExW(typeKey, j, instanceName.data(), &instanceLength,
                             nullptr, nullptr, nullptr, nullptr);
      if (status != ERROR_SUCCESS) {
        fail(status);
        continue;
      }
      HKEY instanceKey = nullptr;
      status =
          RegOpenKeyExW(typeKey, instanceName.data(), 0, KEY_READ, &instanceKey);
      if (status != ERROR_SUCCESS) {
        fail(status);
        continue;
      }
      result.records.push_back(
          {std::wstring(typeName.data(), typeLength),
           std::wstring(instanceName.data(), instanceLength),
           RegString(instanceKey, L"FriendlyName"),
           RegString(instanceKey, L"DeviceDesc"),
           RegString(instanceKey, L"Mfg"),
           RegString(instanceKey, L"ContainerID")});
      RegCloseKey(instanceKey);
    }
    RegCloseKey(typeKey);
  }
  RegCloseKey(root);
  return result;
}

void UsbHistory(AuditResult &r) {
  DetailTable table{
      L"USB 存储设备注册表记录逐项明细",
      {L"设备类型", L"实例ID/序列号", L"友好名称", L"设备描述", L"厂商"},
      {}};
  const RegistryDeviceTree usb = ReadRegistryDeviceTree(
      L"SYSTEM\\CurrentControlSet\\Enum\\USB");
  const RegistryDeviceTree usbStor = ReadRegistryDeviceTree(
      L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");
  const RegistryDeviceTree scsi = ReadRegistryDeviceTree(
      L"SYSTEM\\CurrentControlSet\\Enum\\SCSI");
  std::set<std::wstring> usbContainers;
  for (const auto &device : usb.records)
    if (!device.containerId.empty())
      usbContainers.insert(device.containerId);
  std::set<std::wstring> recordedContainers;
  for (const auto &device : usbStor.records) {
    table.rows.push_back({device.type, device.instance,
                          Clean(device.friendlyName),
                          Clean(device.description),
                          Clean(device.manufacturer)});
    if (!device.containerId.empty())
      recordedContainers.insert(device.containerId);
  }
  for (const auto &device : scsi.records) {
    if (device.containerId.empty() ||
        usbContainers.find(device.containerId) == usbContainers.end() ||
        recordedContainers.find(device.containerId) != recordedContainers.end())
      continue;
    table.rows.push_back({L"SCSI/UASP: " + device.type, device.instance,
                          Clean(device.friendlyName),
                          Clean(device.description),
                          Clean(device.manufacturer)});
    recordedContainers.insert(device.containerId);
  }
  DWORD error = usb.error;
  if (error == ERROR_SUCCESS)
    error = usbStor.error;
  if (error == ERROR_SUCCESS)
    error = scsi.error;
  if (error != ERROR_SUCCESS) {
    Add(r, L"USB 存储设备记录", L"清理后应为0条；历史记录需现场核查",
        L"读取不完整（错误" + std::to_wstring(error) + L"），已识别" +
            std::to_wstring(table.rows.size()) + L"条",
        Verdict::Fail);
    r.details.push_back(std::move(table));
    return;
  }
  Add(r, L"USB 存储设备记录", L"清理后应为0条；历史记录需现场核查",
      table.rows.empty()
          ? L"未发现 USB 存储设备记录（0条）"
          : L"读取成功，剩余" + std::to_wstring(table.rows.size()) + L"条",
      table.rows.empty() ? Verdict::Pass : Verdict::Review);
  r.details.push_back(std::move(table));
}

std::vector<std::pair<std::wstring, std::wstring>> UserProfiles() {
  std::vector<std::pair<std::wstring, std::wstring>> result;
  const wchar_t *path =
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
  HKEY root{};
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY,
                    &root) != ERROR_SUCCESS)
    return result;
  for (const auto &sid : Subkeys(HKEY_LOCAL_MACHINE, path)) {
    HKEY key{};
    if (RegOpenKeyExW(root, sid.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
      continue;
    std::wstring folder = RegString(key, L"ProfileImagePath");
    RegCloseKey(key);
    std::wstring leaf = win7fs::Filename(folder);
    std::wstring lower = leaf;
    std::transform(lower.begin(), lower.end(), lower.begin(), towlower);
    if (folder.empty() || lower == L"default" || lower == L"public" ||
        lower == L"systemprofile" || lower == L"localservice" ||
        lower == L"networkservice")
      continue;
    if (win7fs::IsDirectory(folder))
      result.push_back({sid, folder});
  }
  RegCloseKey(root);
  return result;
}
bool ExistsAny(const std::vector<std::wstring> &paths) {
  return std::any_of(paths.begin(), paths.end(),
                     [](const std::wstring &path) {
                       return win7fs::Exists(path);
                     });
}
void BrowserAudit(AuditResult &r) {
  DetailTable table{
      L"浏览器已保存密码逐项明细",
      {L"Windows用户", L"浏览器", L"配置", L"预期", L"实际", L"结论", L"依据"},
      {}};
  DetailTable accounts{L"保存密码的网站与账号",
                       {L"Windows用户", L"浏览器", L"配置", L"网站", L"账号"},
                       {}};
  auto profiles = UserProfiles();
  auto pf = Env(L"ProgramFiles"), pfx = Env(L"ProgramFiles(x86)");
  struct Browser {
    const wchar_t *name;
    const wchar_t *executable;
    const wchar_t *data;
    bool roaming;
  };
  const Browser chromium[] = {
      {L"Microsoft Edge", L"Microsoft\\Edge\\Application\\msedge.exe",
       L"Microsoft\\Edge\\User Data", false},
      {L"Google Chrome", L"Google\\Chrome\\Application\\chrome.exe",
       L"Google\\Chrome\\User Data", false},
      {L"360 极速浏览器", L"360Chrome\\Chrome\\Application\\360chrome.exe",
       L"360Chrome\\Chrome\\User Data", false},
      {L"360 安全浏览器", L"360\\360se6\\Application\\360se.exe",
       L"360se6\\User Data", true},
      {L"世界之窗浏览器", L"TheWorld6\\Application\\TheWorld.exe",
       L"TheWorld6\\User Data", false},
      {L"QQ 浏览器", L"Tencent\\QQBrowser\\QQBrowser.exe",
       L"Tencent\\QQBrowser\\User Data", false},
      {L"Brave", L"BraveSoftware\\Brave-Browser\\Application\\brave.exe",
       L"BraveSoftware\\Brave-Browser\\User Data", false},
      {L"Vivaldi", L"Vivaldi\\Application\\vivaldi.exe",
       L"Vivaldi\\User Data", false}};
  int pass = 0, fail = 0, review = 0;
  for (const auto &browser : chromium) {
    bool installed =
        ExistsAny({win7fs::Join(pf, browser.executable),
                   win7fs::Join(pfx, browser.executable)});
    std::vector<std::pair<std::wstring, std::wstring>> browserRoots;
    for (const auto &profile : profiles) {
      const std::wstring appData =
          win7fs::Join(profile.second, L"AppData",
                       browser.roaming ? L"Roaming" : L"Local");
      const std::wstring root = win7fs::Join(appData, browser.data);
      if (win7fs::Exists(win7fs::Join(appData, browser.executable)) ||
          win7fs::IsDirectory(root))
        installed = true;
      if (win7fs::IsDirectory(root))
        browserRoots.push_back({win7fs::Filename(profile.second), root});
    }
    if (!installed) {
      table.rows.push_back({L"本机", browser.name, L"安装状态", L"仅记录",
                            L"未安装", L"不适用", L"未发现程序文件"});
      continue;
    }
    table.rows.push_back({L"本机", browser.name, L"安装状态", L"仅记录",
                          L"已安装", L"已识别", L"发现程序文件"});
    for (const auto &profile : browserRoots) {
      DWORD directoryError = ERROR_SUCCESS;
      for (const auto &entry :
           win7fs::Enumerate(profile.second, false, directoryError)) {
        if (!entry.IsDirectory())
          continue;
        for (const wchar_t *dbName :
             {L"Login Data", L"Login Data For Account"}) {
          const std::wstring db = win7fs::Join(entry.path, dbName);
          if (!win7fs::Exists(db))
            continue;
          sqlite3 *database = nullptr;
          int code = sqlite3_open_v2(Utf8(db).c_str(), &database,
                                     SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                                     nullptr);
          if (code != SQLITE_OK) {
            if (database)
              sqlite3_close(database);
            table.rows.push_back(
                {profile.first, browser.name,
                 entry.name + L" / " + dbName,
                 L"没有保存密码", L"读取失败", L"需复核",
                 L"密码库可能被占用或无权限"});
            review++;
            continue;
          }
          sqlite3_busy_timeout(database, 1500);
          sqlite3_stmt *stmt = nullptr;
          code = sqlite3_prepare_v2(
              database,
              "SELECT origin_url, username_value FROM logins WHERE "
              "password_value IS NOT NULL AND length(password_value)>0",
              -1, &stmt, nullptr);
          int count = 0;
          if (code == SQLITE_OK) {
            while ((code = sqlite3_step(stmt)) == SQLITE_ROW) {
              count++;
              accounts.rows.push_back(
                  {profile.first, browser.name,
                   entry.name + L" / " + dbName,
                   sqlite3_column_text(stmt, 0)
                       ? Utf16(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)))
                       : L"",
                   sqlite3_column_text(stmt, 1)
                       ? Utf16(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)))
                       : L""});
            }
            sqlite3_finalize(stmt);
          }
          sqlite3_close(database);
          if (code != SQLITE_DONE) {
            table.rows.push_back(
                {profile.first, browser.name,
                 entry.name + L" / " + dbName,
                 L"没有保存密码", L"读取失败", L"需复核",
                 L"数据库格式不受支持或被占用"});
            review++;
          } else if (count) {
            table.rows.push_back(
                {profile.first, browser.name,
                 entry.name + L" / " + dbName,
                 L"没有保存密码", L"发现" + std::to_wstring(count) + L"条",
                 L"异常", L"网站和账号见明细；未读取密码"});
            fail++;
          } else {
            table.rows.push_back(
                {profile.first, browser.name,
                 entry.name + L" / " + dbName,
                 L"没有保存密码", L"0条", L"通过", L"只读查询密码记录"});
            pass++;
          }
        }
      }
    }
  }
std::vector<std::pair<std::wstring, std::wstring>> firefoxRoots;
for (const auto &profile : profiles) {
  const std::wstring root = win7fs::Join(profile.second, L"AppData", L"Roaming",
                                         L"Mozilla", L"Firefox", L"Profiles");
  if (win7fs::IsDirectory(root))
    firefoxRoots.push_back({win7fs::Filename(profile.second), root});
}
bool firefoxInstalled =
    ExistsAny({win7fs::Join(pf, L"Mozilla Firefox", L"firefox.exe"),
               win7fs::Join(pfx, L"Mozilla Firefox", L"firefox.exe")}) ||
    !firefoxRoots.empty();
table.rows.push_back({L"本机", L"Mozilla Firefox", L"安装状态", L"仅记录",
                      firefoxInstalled ? L"已安装" : L"未安装",
                      firefoxInstalled ? L"已识别" : L"不适用",
                      firefoxInstalled ? L"发现程序或用户配置" : L"未发现程序和用户配置"});
for (const auto &profile : firefoxRoots) {
  DWORD directoryError = ERROR_SUCCESS;
  for (const auto &entry :
       win7fs::Enumerate(profile.second, false, directoryError)) {
    if (!entry.IsDirectory())
      continue;
    const std::wstring file = win7fs::Join(entry.path, L"logins.json");
    if (!win7fs::Exists(file))
      continue;
    std::ifstream input(file.c_str(), std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(input)), {});
    std::regex host("\\\"hostname\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    int count = 0;
    for (std::sregex_iterator m(text.begin(), text.end(), host), end; m != end;
         ++m) {
      count++;
      accounts.rows.push_back(
          {profile.first, L"Mozilla Firefox",
           entry.name, Utf16((*m)[1].str()),
           L"账号已加密，请在 Firefox 中查看"});
    }
    if (count) {
      table.rows.push_back({profile.first,
                            L"Mozilla Firefox", entry.name,
                            L"没有保存密码",
                            L"发现" + std::to_wstring(count) + L"条", L"异常",
                            L"仅列网站；未解密账号或密码"});
      fail++;
    } else {
      table.rows.push_back({profile.first,
                            L"Mozilla Firefox", entry.name,
                            L"没有保存密码", L"0条", L"通过",
                            L"未发现登录记录"});
      pass++;
    }
  }
}
if (pass == 0 && fail == 0 && review == 0) {
  Add(r, L"浏览器已保存密码", L"普通用户浏览器均没有保存密码",
      profiles.empty() ? L"未识别到普通用户配置" : L"未发现可检查的密码库",
      Verdict::Review);
} else
  Add(r, L"浏览器已保存密码", L"普通用户浏览器均没有保存密码",
      L"通过" + std::to_wstring(pass) + L"项，有密码" + std::to_wstring(fail) +
          L"项，需复核" + std::to_wstring(review) + L"项",
      fail     ? Verdict::Fail
      : review ? Verdict::Review
               : Verdict::Pass);
r.details.push_back(std::move(table));
r.details.push_back(std::move(accounts));
}

std::wstring WifiProfileName(const std::wstring &file) {
  std::ifstream input(file.c_str(), std::ios::binary);
  std::string bytes((std::istreambuf_iterator<char>(input)), {});
  std::wstring xml;
  if (bytes.size() >= 2 && static_cast<unsigned char>(bytes[0]) == 0xFF &&
      static_cast<unsigned char>(bytes[1]) == 0xFE) {
    const size_t count = (bytes.size() - 2) / sizeof(wchar_t);
    xml.resize(count);
    if (count)
      memcpy(xml.data(), bytes.data() + 2, count * sizeof(wchar_t));
  } else {
    if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xEF &&
        static_cast<unsigned char>(bytes[1]) == 0xBB &&
        static_cast<unsigned char>(bytes[2]) == 0xBF)
      bytes.erase(0, 3);
    xml = Utf16(bytes);
  }
  std::wsmatch match;
  if (std::regex_search(xml, match,
                        std::wregex(LR"(<name>([^<]*)</name>)",
                                    std::regex_constants::icase)))
    return Clean(match[1].str());
  return L"无法识别名称";
}
void Wireless(AuditResult &r) {
  const std::wstring profiles =
      win7fs::Join(Env(L"ProgramData"), L"Microsoft", L"Wlansvc",
                   L"Profiles", L"Interfaces");
  DetailTable profileDetails{L"已保存 Wi-Fi 配置逐项明细",
                             {L"Wi-Fi 名称", L"接口 GUID", L"配置文件"}, {}};
  int count = 0;
  DWORD directoryError = ERROR_SUCCESS;
  if (win7fs::Exists(profiles)) {
    for (const auto &entry :
         win7fs::Enumerate(profiles, true, directoryError))
      if (entry.IsRegularFile() &&
          _wcsicmp(win7fs::Extension(entry.path).c_str(), L".xml") == 0) {
        count++;
        profileDetails.rows.push_back(
            {WifiProfileName(entry.path),
             win7fs::Filename(win7fs::Parent(entry.path)), entry.name});
      }
  }
  if (directoryError != ERROR_SUCCESS)
    Add(r, L"已保存 Wi-Fi 配置", L"本机 WLAN 配置文件为0",
        L"读取失败：Windows错误" + std::to_wstring(directoryError),
        Verdict::Review);
  else
    Add(r, L"已保存 Wi-Fi 配置", L"本机 WLAN 配置文件为0",
        L"剩余" + std::to_wstring(count) + L"个配置文件",
        count ? Verdict::Fail : Verdict::Pass);
  r.details.push_back(std::move(profileDetails));
  PMIB_IF_TABLE2 table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR) {
    Add(r, L"无线网卡", L"全部禁用", L"无法读取网卡", Verdict::Review);
    return;
  }
  int found = 0;
  for (ULONG i = 0; i < table->NumEntries; i++) {
    const auto &row = table->Table[i];
    if (row.Type != IF_TYPE_IEEE80211 ||
        !row.InterfaceAndOperStatusFlags.HardwareInterface)
      continue;
    found++;
    bool disabled = row.AdminStatus == NET_IF_ADMIN_STATUS_DOWN;
    Add(r, L"无线网卡 / " + std::wstring(row.Alias), L"管理状态为禁用",
        disabled ? L"已禁用" : L"未禁用（未连接不等于已禁用）",
        disabled ? Verdict::Pass : Verdict::Fail);
  }
  FreeMibTable(table);
  if (!found)
    Add(r, L"无线网卡", L"全部禁用", L"未识别到无线网卡",
        Verdict::NotApplicable);
}
}

AuditResult RunAudit() {
  AuditResult r;
  auto stage=[&](const char* name,auto action){try{action();}catch(const std::exception& e){throw std::runtime_error(std::string(name)+": "+e.what());}};
  stage("identity",[&]{Identity(r);NetworkIdentity(r);});
  stage("services",[&]{ServiceCheck(r, L"LanmanServer", L"Server 文件共享服务");ServiceCheck(r, L"TermService", L"远程桌面服务");RdpCheck(r);});
  stage("firewall",[&]{FirewallCheck(r);});
  stage("netbios",[&]{NetbiosCheck(r);});
  stage("listeners",[&]{ListenerCheck(r);});
  stage("network-history",[&]{NetworkHistory(r);});
  stage("usb",[&]{UsbHistory(r);});
  stage("browser",[&]{BrowserAudit(r);});
  stage("wireless",[&]{Wireless(r);});
  r.finished = Now(L"%04u-%02u-%02u %02u:%02u:%02u");
  return r;
}

std::wstring ToJson(const AuditResult &r) {
  std::wostringstream o;
  o << L"{\"schema\":1,\"computer\":" << Json(r.computer)
    << L",\"executionIdentity\":" << Json(r.executionIdentity) << L",\"ip\":"
    << Json(r.ip) << L",\"mac\":" << Json(r.mac) << L",\"adapter\":"
    << Json(r.adapter) << L",\"finished\":" << Json(r.finished)
    << L",\"passed\":" << r.passed << L",\"failed\":" << r.failed
    << L",\"review\":" << r.review << L",\"summary\":[";
  for (size_t i = 0; i < r.summary.size(); i++) {
    if (i)
      o << L',';
    const auto &x = r.summary[i];
    o << L"{\"item\":" << Json(x.item) << L",\"expected\":" << Json(x.expected)
      << L",\"actual\":" << Json(x.actual) << L",\"conclusion\":"
      << Json(VerdictText(x.verdict)) << L"}";
  }
  o << L"],\"details\":[";
  for (size_t i = 0; i < r.details.size(); i++) {
    if (i)
      o << L',';
    const auto &t = r.details[i];
    o << L"{\"title\":" << Json(t.title) << L",\"columns\":[";
    for (size_t j = 0; j < t.columns.size(); j++) {
      if (j)
        o << L',';
      o << Json(t.columns[j]);
    }
    o << L"],\"rows\":[";
    for (size_t j = 0; j < t.rows.size(); j++) {
      if (j)
        o << L',';
      o << L'[';
      for (size_t k = 0; k < t.rows[j].size(); k++) {
        if (k)
          o << L',';
        o << Json(t.rows[j][k]);
      }
      o << L']';
    }
    o << L"]}";
  }
  return o.str() + L"]}";
}
std::wstring ToHtml(const AuditResult &r) {
  std::wostringstream o;
  o << L"<!doctype html><html lang=\"zh-CN\"><meta "
       L"charset=\"utf-8\"><title>终端安全检查报告</"
       L"title><style>body{margin:0;background:#f3f5f7;color:#202124;font-"
       L"family:Microsoft YaHei,Arial}.wrap{max-width:1200px;margin:24px "
       L"auto}.card{background:#fff;border:1px solid "
       L"#dfe3e8;border-radius:7px;margin:16px;padding:20px}table{width:100%;"
       L"border-collapse:collapse}th,td{border:1px solid "
       L"#d9dde2;padding:8px;text-align:left;word-break:break-all}th{"
       L"background:#eef2f5}.pass{color:#1b5e20;font-weight:bold}.fail{color:#"
       L"b71c1c;font-weight:bold}.review{color:#9a6700;font-weight:bold}.na{"
       L"color:#687078}.info{color:#1565c0}</style><div class=wrap><div "
       L"class=card><h1>终端安全检查报告</h1><p>被检查终端IP地址:"
    << Html(r.ip) << L"　MAC地址：" << Html(r.mac) << L"</p><p>主用网卡："
    << Html(r.adapter) << L"　计算机：" << Html(r.computer) << L"　执行身份："
    << Html(r.executionIdentity) << L"　检查时间：" << Html(r.finished)
    << L"</p><p>通过 " << r.passed << L" 项　异常 " << r.failed
    << L" 项　需复核 " << r.review
    << L" 项</p></div><div "
       L"class=card><h2>一、检查结果汇总</h2><table><tr><th>序号</"
       L"th><th>检查项目</th><th>预期结果</th><th>实际结果</th><th>结论</th></"
       L"tr>";
  for (size_t i = 0; i < r.summary.size(); i++) {
    const auto &x = r.summary[i];
    o << L"<tr><td>" << i + 1 << L"</td><td>" << Html(x.item) << L"</td><td>"
      << Html(x.expected) << L"</td><td>" << Html(x.actual)
      << L"</td><td class=" << VerdictClass(x.verdict) << L">"
      << VerdictText(x.verdict) << L"</td></tr>";
  }
  o << L"</"
       L"table><p>"
       L"说明：端口外部连通性必须从另一台电脑验证；需复核不等于检查通过。</p></"
       L"div>";
  for (size_t i = 0; i < r.details.size(); i++) {
    const auto &t = r.details[i];
    o << L"<div class=card><h2>" << Html(t.title) << L"</h2><table><tr>";
    for (const auto &c : t.columns)
      o << L"<th>" << Html(c) << L"</th>";
    o << L"</tr>";
    for (const auto &row : t.rows) {
      o << L"<tr>";
      for (const auto &cell : row)
        o << L"<td>" << Html(cell) << L"</td>";
      o << L"</tr>";
    }
    if (t.rows.empty())
      o << L"<tr><td colspan=" << std::max<size_t>(1, t.columns.size())
        << L">未发现记录</td></tr>";
    o << L"</table></div>";
  }
  o << L"</div></html>";
  return o.str();
}
ReportFiles WriteReports(const AuditResult &r, const std::wstring &directory,
                         const std::wstring &prefix) {
  if (!win7fs::CreateDirectories(directory))
    throw std::runtime_error("create report directory failed");
  std::wstring stamp = Now(L"%04u%02u%02u-%02u%02u%02u-%03u");
  std::wstring safeIp = r.ip, safeMac = r.mac;
  for (auto *v : {&safeIp, &safeMac})
    for (auto &c : *v)
      if (!(iswalnum(c) || c == L'.' || c == L'-' || c == L'_'))
        c = L'-';
  std::wstring base = prefix + L"_" + safeIp + L"_" + safeMac + L"_" + stamp;
  ReportFiles files;
  files.html = ToHtml(r);
  files.json = ToJson(r);
  files.htmlPath = win7fs::Join(directory, base + L".html");
  files.jsonPath = win7fs::Join(directory, base + L".json");
  std::ofstream html(files.htmlPath.c_str(), std::ios::binary),
      json(files.jsonPath.c_str(), std::ios::binary);
  const auto h = Utf8(files.html), j = Utf8(files.json);
  html.write("\xEF\xBB\xBF", 3);
  html.write(h.data(), static_cast<std::streamsize>(h.size()));
  json.write("\xEF\xBB\xBF", 3);
  json.write(j.data(), static_cast<std::streamsize>(j.size()));
  if (!html || !json)
    throw std::runtime_error("write report failed");
  return files;
}
}
