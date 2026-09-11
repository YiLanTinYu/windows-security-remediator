#define _WIN32_WINNT 0x0601
#include "system_remediation.h"
#include "firewall_remediation.h"
#include <windows.h>
#include <shlobj.h>
#include <winsvc.h>
#include <fstream>
#include <sstream>
#include <vector>

namespace sr {
namespace {
const wchar_t *kNetbiosRoot =
    L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces";
const wchar_t *kRdpPath = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server";

struct ServiceState {
  std::wstring name;
  DWORD startType = SERVICE_DEMAND_START;
  bool running = false;
};
using RegistryState = NetbiosOptionSnapshot;
struct BackupState {
  bool valid = false;
  ServiceState server, terminal;
  RegistryState rdp;
  std::vector<RegistryState> netbios;
  FirewallState firewall;
};

std::wstring Join(const std::wstring &left, const std::wstring &right) {
  return left + (left.empty() || left.back() == L'\\' ? L"" : L"\\") + right;
}

std::wstring BackupPath() {
  wchar_t common[MAX_PATH]{};
  if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                             SHGFP_TYPE_CURRENT, common)))
    return L"";
  const std::wstring directory = Join(common, L"SecurityRemediator");
  SHCreateDirectoryExW(nullptr, directory.c_str(), nullptr);
  return Join(directory, L"backup-v2.state");
}

std::wstring Hex(const std::wstring &value) {
  const wchar_t *digits = L"0123456789ABCDEF";
  std::wstring output;
  output.reserve(value.size() * 4);
  for (wchar_t c : value) {
    const unsigned int v = static_cast<unsigned short>(c);
    output += digits[(v >> 12) & 15]; output += digits[(v >> 8) & 15];
    output += digits[(v >> 4) & 15]; output += digits[v & 15];
  }
  return output;
}

bool Unhex(const std::wstring &value, std::wstring &output) {
  if (value.size() % 4) return false;
  auto digit = [](wchar_t c) -> int {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
  };
  output.clear();
  for (size_t i = 0; i < value.size(); i += 4) {
    int a = digit(value[i]), b = digit(value[i + 1]);
    int c = digit(value[i + 2]), d = digit(value[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) return false;
    output += static_cast<wchar_t>((a << 12) | (b << 8) | (c << 4) | d);
  }
  return true;
}

bool QueryServiceState(const wchar_t *name, ServiceState &state) {
  state.name = name;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return false;
  SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
  if (!service) { CloseServiceHandle(manager); return false; }
  DWORD size = 0;
  QueryServiceConfigW(service, nullptr, 0, &size);
  std::vector<BYTE> buffer(size);
  auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(buffer.data());
  SERVICE_STATUS_PROCESS status{};
  DWORD statusSize = 0;
  const bool ok = QueryServiceConfigW(service, config, size, &size) &&
      QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                           reinterpret_cast<BYTE *>(&status), sizeof(status),
                           &statusSize);
  if (ok) {
    state.startType = config->dwStartType;
    state.running = status.dwCurrentState != SERVICE_STOPPED;
  }
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return ok;
}

bool ConfigureService(const wchar_t *name, DWORD startType, bool shouldRun) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return false;
  SC_HANDLE service = OpenServiceW(manager, name, SERVICE_CHANGE_CONFIG |
      SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (!service) { CloseServiceHandle(manager); return false; }
  const DWORD operationalStartType =
      shouldRun && startType == SERVICE_DISABLED ? SERVICE_DEMAND_START : startType;
  bool ok = ChangeServiceConfigW(service, SERVICE_NO_CHANGE, operationalStartType,
      SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
      nullptr) != FALSE;
  SERVICE_STATUS status{};
  if (shouldRun) {
    if (QueryServiceStatus(service, &status) && status.dwCurrentState == SERVICE_STOPPED)
      ok = (StartServiceW(service, 0, nullptr) ||
            GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) && ok;
  } else if (QueryServiceStatus(service, &status) &&
             status.dwCurrentState != SERVICE_STOPPED) {
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status) &&
        GetLastError() != ERROR_SERVICE_NOT_ACTIVE) ok = false;
    for (int i = 0; i < 50; ++i) {
      if (!QueryServiceStatus(service, &status) || status.dwCurrentState == SERVICE_STOPPED)
        break;
      Sleep(100);
    }
    if (status.dwCurrentState != SERVICE_STOPPED) ok = false;
  }
  if (shouldRun && startType == SERVICE_DISABLED) {
    ok = ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_DISABLED,
        SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr) != FALSE && ok;
  }
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return ok;
}

bool QueryDword(const std::wstring &subkey, const wchar_t *name,
                RegistryState &state) {
  state.subkey = subkey;
  HKEY key = nullptr;
  LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0,
                              KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
  if (opened == ERROR_FILE_NOT_FOUND) return true;
  if (opened != ERROR_SUCCESS) return false;
  DWORD type = 0, size = sizeof(state.value);
  const LONG result = RegQueryValueExW(key, name, nullptr, &type,
      reinterpret_cast<BYTE *>(&state.value), &size);
  RegCloseKey(key);
  if (result == ERROR_FILE_NOT_FOUND) return true;
  state.exists = result == ERROR_SUCCESS && type == REG_DWORD;
  return state.exists;
}

bool SetDword(const std::wstring &subkey, const wchar_t *name, DWORD value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, nullptr, 0,
      KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, nullptr) != ERROR_SUCCESS)
    return false;
  const LONG result = RegSetValueExW(key, name, 0, REG_DWORD,
      reinterpret_cast<const BYTE *>(&value), sizeof(value));
  RegCloseKey(key);
  return result == ERROR_SUCCESS;
}

bool RestoreDword(const RegistryState &state, const wchar_t *name) {
  if (state.exists) return SetDword(state.subkey, name, state.value);
  HKEY key = nullptr;
  LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, state.subkey.c_str(), 0,
                              KEY_SET_VALUE | KEY_WOW64_64KEY, &key);
  if (opened == ERROR_FILE_NOT_FOUND) return true;
  if (opened != ERROR_SUCCESS) return false;
  const LONG result = RegDeleteValueW(key, name);
  RegCloseKey(key);
  return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
}

bool EnumerateNetbios(std::vector<RegistryState> &states) {
  HKEY root = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kNetbiosRoot, 0,
      KEY_READ | KEY_WOW64_64KEY, &root) != ERROR_SUCCESS) return false;
  DWORD count = 0, maximum = 0;
  if (RegQueryInfoKeyW(root, nullptr, nullptr, nullptr, &count, &maximum,
      nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
    RegCloseKey(root); return false;
  }
  std::vector<wchar_t> name(maximum + 2);
  bool ok = true;
  for (DWORD i = 0; i < count; ++i) {
    DWORD size = maximum + 1;
    if (RegEnumKeyExW(root, i, name.data(), &size, nullptr, nullptr, nullptr,
                      nullptr) != ERROR_SUCCESS) { ok = false; continue; }
    RegistryState state;
    const std::wstring subkey = std::wstring(kNetbiosRoot) + L"\\" +
                                std::wstring(name.data(), size);
    if (!QueryDword(subkey, L"NetbiosOptions", state)) ok = false;
    states.push_back(state);
  }
  RegCloseKey(root);
  return ok;
}

bool Capture(BackupState &state, std::wstring &detail) {
  state.server.name = L"LanmanServer";
  state.terminal.name = L"TermService";
  state.rdp.subkey = kRdpPath;
  if (!QueryServiceState(L"LanmanServer", state.server))
    detail = L"无法读取 LanmanServer 服务状态";
  else if (!QueryServiceState(L"TermService", state.terminal))
    detail = L"无法读取 TermService 服务状态";
  else if (!QueryDword(kRdpPath, L"fDenyTSConnections", state.rdp))
    detail = L"无法读取远程桌面连接策略";
  else if (!CaptureNetbiosOptionSnapshots(state.netbios))
    detail = L"无法读取 NetBIOS 网卡配置";
  else if (!CaptureFirewallState(state.firewall))
    detail = L"无法读取 Windows 防火墙原始状态";
  else {
    state.valid = true;
    detail = L"已完整读取修复前状态";
    return true;
  }
  state.valid = false;
  return false;
}

bool Save(const BackupState &state) {
  const std::wstring path = BackupPath();
  if (path.empty()) return false;
  std::wofstream output(path.c_str(), std::ios::trunc);
  if (!output) return false;
  output << L"VERSION|2\n";
  output << L"SVC|" << state.server.name << L'|' << state.server.startType << L'|'
         << state.server.running << L"\n";
  output << L"SVC|" << state.terminal.name << L'|' << state.terminal.startType << L'|'
         << state.terminal.running << L"\n";
  output << L"RDP|" << state.rdp.exists << L'|' << state.rdp.value << L"\n";
  for (const auto &item : state.netbios)
    output << L"NBT|" << Hex(item.subkey) << L'|' << item.exists << L'|'
           << item.value << L"\n";
  output << L"FWP|" << state.firewall.domainEnabled << L'|'
         << state.firewall.privateEnabled << L'|' << state.firewall.publicEnabled << L"\n";
  for (const auto &rule : state.firewall.rules)
    output << L"FWR|" << Hex(rule.name) << L'|' << Hex(rule.description) << L'|'
           << Hex(rule.localPorts) << L'|' << rule.protocol << L'|' << rule.direction
           << L'|' << rule.action << L'|' << rule.profiles << L'|' << rule.enabled << L"\n";
  output << L"END|1\n";
  return static_cast<bool>(output);
}

std::vector<std::wstring> Split(const std::wstring &line) {
  std::vector<std::wstring> parts;
  std::wistringstream input(line);
  std::wstring part;
  while (std::getline(input, part, L'|')) parts.push_back(part);
  return parts;
}

bool Load(BackupState &state) {
  std::wifstream input(BackupPath().c_str());
  if (!input) return false;
  bool version = false, end = false, server = false, terminal = false,
       rdp = false, profiles = false;
  std::wstring line;
  try {
    while (std::getline(input, line)) {
      const auto p = Split(line);
      if (p.size() == 2 && p[0] == L"VERSION" && p[1] == L"2") version = true;
      else if (p.size() == 4 && p[0] == L"SVC") {
        ServiceState *target = p[1] == L"LanmanServer" ? &state.server :
                               p[1] == L"TermService" ? &state.terminal : nullptr;
        if (!target) return false;
        target->name = p[1]; target->startType = std::stoul(p[2]);
        target->running = p[3] == L"1";
        if (p[1] == L"LanmanServer") server = true; else terminal = true;
      } else if (p.size() == 3 && p[0] == L"RDP") {
        state.rdp = {kRdpPath, p[1] == L"1", std::stoul(p[2])}; rdp = true;
      } else if (p.size() == 4 && p[0] == L"NBT") {
        RegistryState item;
        if (!Unhex(p[1], item.subkey)) return false;
        item.exists = p[2] == L"1"; item.value = std::stoul(p[3]);
        state.netbios.push_back(item);
      } else if (p.size() == 4 && p[0] == L"FWP") {
        state.firewall.domainEnabled = p[1] == L"1";
        state.firewall.privateEnabled = p[2] == L"1";
        state.firewall.publicEnabled = p[3] == L"1"; profiles = true;
      } else if (p.size() == 9 && p[0] == L"FWR") {
        FirewallRuleState rule;
        if (!Unhex(p[1], rule.name) || !Unhex(p[2], rule.description) ||
            !Unhex(p[3], rule.localPorts)) return false;
        rule.protocol = std::stol(p[4]); rule.direction = std::stol(p[5]);
        rule.action = std::stol(p[6]); rule.profiles = std::stol(p[7]);
        rule.enabled = p[8] == L"1"; state.firewall.rules.push_back(rule);
      } else if (p.size() == 2 && p[0] == L"END" && p[1] == L"1") end = true;
      else return false;
    }
  } catch (...) { return false; }
  state.firewall.valid = profiles;
  state.valid = version && end && server && terminal && rdp && profiles;
  return state.valid;
}

bool EnsureInitialBackup(std::wstring &detail, bool &created) {
  created = false;
  const std::wstring path = BackupPath();
  if (path.empty()) {
    detail = L"无法确定首次状态备份路径，已停止修复";
    return false;
  }
  const DWORD attributes = GetFileAttributesW(path.c_str());
  if (attributes != INVALID_FILE_ATTRIBUTES) {
    BackupState existing;
    if (Load(existing)) { detail = L"已保留首次修复前备份"; return true; }
    detail = L"首次状态备份已损坏，已停止修复且未覆盖原文件";
    return false;
  }
  if (GetLastError() != ERROR_FILE_NOT_FOUND) {
    detail = L"无法读取首次状态备份，已停止修复";
    return false;
  }
  BackupState captured;
  std::wstring captureDetail;
  if (!Capture(captured, captureDetail)) {
    detail = captureDetail + L"，已停止修复";
    return false;
  }
  if (!Save(captured)) {
    detail = L"修复前状态已读取，但无法写入首次备份文件，已停止修复";
    return false;
  }
  created = true;
  detail = L"已保存首次修复前状态";
  return true;
}

RemediationAction ServiceAction(const wchar_t *name, const wchar_t *item) {
  ServiceState before;
  RemediationAction action{item, L"停止服务并将启动类型设为禁用"};
  if (!QueryServiceState(name, before)) { action.result = L"读取服务状态失败"; return action; }
  action.changed = before.running || before.startType != SERVICE_DISABLED;
  ServiceState after;
  action.success = ConfigureService(name, SERVICE_DISABLED, false) &&
      QueryServiceState(name, after) && !after.running &&
      after.startType == SERVICE_DISABLED;
  action.result = action.success ? (action.changed ? L"已停止并禁用" : L"原状态已符合")
                                 : L"停止或禁用失败";
  return action;
}

void AddAction(RemediationResult &result, RemediationAction action) {
  result.success = result.success && action.success;
  result.changed = result.changed || action.changed;
  result.actions.push_back(std::move(action));
}
}

bool CaptureNetbiosOptionSnapshots(
    std::vector<NetbiosOptionSnapshot> &states) {
  states.clear();
  return EnumerateNetbios(states);
}

bool IsRemediationAuthorized() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const bool elevated = GetTokenInformation(token, TokenElevation, &elevation,
      sizeof(elevation), &size) && elevation.TokenIsElevated;
  CloseHandle(token);
  return elevated;
}

RemediationResult ApplySystemRemediation() {
  RemediationResult result;
  result.authorized = IsRemediationAuthorized();
  result.success = result.authorized;
  if (!result.authorized) {
    result.actions.push_back({L"权限检查", L"确认 SYSTEM 或已提权管理员",
                              L"权限不足，未修改系统", false, false});
    return result;
  }
  std::wstring backupDetail;
  bool backupCreated = false;
  const bool backupOk = EnsureInitialBackup(backupDetail, backupCreated);
  AddAction(result, {L"初始状态备份", L"保存首次修复前状态", backupDetail,
                     backupOk, backupCreated});
  if (!backupOk) return result;

  const FirewallRepairResult firewall = RepairFirewallRules();
  AddAction(result, {L"Windows 防火墙", L"启用全部配置文件并维护10条入站阻断规则",
                     firewall.detail, firewall.success, firewall.changed});
  AddAction(result, ServiceAction(L"LanmanServer", L"Server 文件共享服务"));
  AddAction(result, ServiceAction(L"TermService", L"远程桌面服务"));

  RegistryState rdp;
  RemediationAction rdpAction{L"远程桌面连接策略", L"设置 fDenyTSConnections=1"};
  if (QueryDword(kRdpPath, L"fDenyTSConnections", rdp)) {
    rdpAction.changed = !rdp.exists || rdp.value != 1;
    RegistryState verified;
    rdpAction.success = SetDword(kRdpPath, L"fDenyTSConnections", 1) &&
        QueryDword(kRdpPath, L"fDenyTSConnections", verified) &&
        verified.exists && verified.value == 1;
    rdpAction.result = rdpAction.success ? (rdpAction.changed ? L"已禁止连接" : L"原状态已符合")
                                         : L"策略写入或复检失败";
  } else rdpAction.result = L"策略读取失败";
  AddAction(result, std::move(rdpAction));

  std::vector<RegistryState> adapters;
  RemediationAction netbios{L"NetBIOS 配置", L"将所有网卡 NetbiosOptions 设置为2"};
  if (CaptureNetbiosOptionSnapshots(adapters)) {
    size_t completed = 0;
    for (const auto &adapter : adapters) {
      netbios.changed = netbios.changed || !adapter.exists || adapter.value != 2;
      RegistryState verified;
      if (SetDword(adapter.subkey, L"NetbiosOptions", 2) &&
          QueryDword(adapter.subkey, L"NetbiosOptions", verified) &&
          verified.exists && verified.value == 2) ++completed;
    }
    netbios.success = completed == adapters.size();
    netbios.result = adapters.empty() ? L"未发现可配置的网卡接口，无需修改"
        : std::to_wstring(completed) + L"/" + std::to_wstring(adapters.size()) +
          L"个网卡已禁用";
  } else netbios.result = L"枚举网卡配置失败";
  AddAction(result, std::move(netbios));
  return result;
}

RemediationResult RollbackSystemRemediation() {
  RemediationResult result;
  result.authorized = IsRemediationAuthorized();
  result.success = result.authorized;
  if (!result.authorized) return result;
  BackupState state;
  if (!Load(state)) {
    result.success = false;
    result.actions.push_back({L"初始状态备份", L"读取备份", L"备份不存在或已损坏",
                              false, false});
    return result;
  }
  std::wstring firewallDetail;
  const bool firewall = RestoreFirewallState(state.firewall, firewallDetail);
  AddAction(result, {L"Windows 防火墙", L"恢复修复前配置",
                     firewallDetail, firewall, true});
  const bool server = ConfigureService(state.server.name.c_str(),
                                       state.server.startType, state.server.running);
  AddAction(result, {L"Server 文件共享服务", L"恢复修复前状态",
                     server ? L"已恢复" : L"恢复失败", server, true});
  const bool terminal = ConfigureService(state.terminal.name.c_str(),
      state.terminal.startType, state.terminal.running);
  AddAction(result, {L"远程桌面服务", L"恢复修复前状态",
                     terminal ? L"已恢复" : L"恢复失败", terminal, true});
  const bool rdp = RestoreDword(state.rdp, L"fDenyTSConnections");
  AddAction(result, {L"远程桌面连接策略", L"恢复修复前状态",
                     rdp ? L"已恢复" : L"恢复失败", rdp, true});
  bool netbios = true;
  for (const auto &item : state.netbios)
    if (!RestoreDword(item, L"NetbiosOptions")) netbios = false;
  AddAction(result, {L"NetBIOS 配置", L"恢复修复前状态",
                     netbios ? L"已恢复" : L"恢复不完整", netbios, true});
  return result;
}
}
