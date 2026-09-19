#define _WIN32_WINNT 0x0601
#include "scan_compatibility.h"
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>
#include <netfw.h>
#include <oleauto.h>
#include <winsvc.h>
#include <algorithm>
#include <cwctype>
#include <set>
#include <sstream>
#include <vector>

namespace sr {
namespace {
std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), towlower);
  return value;
}

std::wstring Trim(const std::wstring &value) {
  const size_t first = value.find_first_not_of(L" \t");
  if (first == std::wstring::npos) return L"";
  const size_t last = value.find_last_not_of(L" \t");
  return value.substr(first, last - first + 1);
}

bool IsFtpService(const ScanServiceEvidence &service) {
  const std::wstring identity = Lower(service.name + L" " +
      service.displayName + L" " + service.binaryPath);
  for (const wchar_t *marker : {L"ftp", L"filezilla", L"serv-u", L"servu"})
    if (identity.find(marker) != std::wstring::npos) return true;
  return false;
}

bool ParsePort(const std::wstring &value, unsigned short &port) {
  if (value.empty()) return false;
  wchar_t *end = nullptr;
  const unsigned long parsed = wcstoul(value.c_str(), &end, 10);
  if (!end || *end || parsed < 1 || parsed > 65535) return false;
  port = static_cast<unsigned short>(parsed);
  return true;
}

struct PortSet {
  std::vector<std::pair<unsigned short, unsigned short>> ranges;
  bool valid = true;

  bool Covers(unsigned short port) const {
    for (const auto &range : ranges)
      if (port >= range.first && port <= range.second) return true;
    return false;
  }

  bool HasBoundedPassiveRange() const {
    for (const auto &range : ranges)
      if (range.first >= 1024 && range.second > range.first &&
          static_cast<unsigned long>(range.second - range.first + 1) <= 2048)
        return true;
    return false;
  }
};

PortSet ParsePorts(const std::wstring &value) {
  PortSet result;
  std::wistringstream input(value);
  std::wstring token;
  while (std::getline(input, token, L',')) {
    token = Trim(token);
    const size_t dash = token.find(L'-');
    unsigned short first = 0, last = 0;
    if (dash == std::wstring::npos) {
      if (!ParsePort(token, first)) result.valid = false;
      last = first;
    } else if (!ParsePort(Trim(token.substr(0, dash)), first) ||
               !ParsePort(Trim(token.substr(dash + 1)), last) || first > last) {
      result.valid = false;
    }
    if (!result.valid) break;
    result.ranges.push_back({first, last});
  }
  if (result.ranges.empty()) result.valid = false;
  return result;
}

bool ControlledSource(const std::wstring &remoteAddresses) {
  const std::wstring value = Lower(Trim(remoteAddresses));
  return !value.empty() && value != L"*" && value != L"any";
}

bool IsFtpRule(const FirewallAllowEvidence &rule) {
  const std::wstring name = Lower(rule.name);
  for (const wchar_t *marker :
       {L"ftp", L"filezilla", L"serv-u", L"servu", L"scan", L"扫描"})
    if (name.find(marker) != std::wstring::npos) return true;
  return false;
}

std::wstring BstrValue(BSTR value) {
  return value ? std::wstring(value, SysStringLen(value)) : L"";
}

bool CollectServices(ScanCompatibilityEvidence &evidence) {
  SC_HANDLE manager = OpenSCManagerW(
      nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
  if (!manager) return false;
  DWORD needed = 0, count = 0, resume = 0;
  EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                        SERVICE_STATE_ALL, nullptr, 0, &needed, &count,
                        &resume, nullptr);
  if (GetLastError() != ERROR_MORE_DATA || needed == 0) {
    CloseServiceHandle(manager);
    return false;
  }
  std::vector<BYTE> buffer(needed);
  resume = 0;
  const bool enumerated = EnumServicesStatusExW(
      manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
      buffer.data(), needed, &needed, &count, &resume, nullptr) != FALSE;
  if (!enumerated) {
    CloseServiceHandle(manager);
    return false;
  }
  auto *services =
      reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW *>(buffer.data());
  for (DWORD i = 0; i < count; ++i) {
    const auto &item = services[i];
    ScanServiceEvidence service;
    service.name = item.lpServiceName ? item.lpServiceName : L"";
    service.displayName = item.lpDisplayName ? item.lpDisplayName : L"";
    service.running = item.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING;
    service.processId = item.ServiceStatusProcess.dwProcessId;
    if (service.running) {
      SC_HANDLE handle = OpenServiceW(manager, service.name.c_str(),
                                      SERVICE_QUERY_CONFIG);
      if (handle) {
        DWORD configSize = 0;
        QueryServiceConfigW(handle, nullptr, 0, &configSize);
        if (configSize) {
          std::vector<BYTE> configBuffer(configSize);
          auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(
              configBuffer.data());
          if (QueryServiceConfigW(handle, config, configSize, &configSize) &&
              config->lpBinaryPathName)
            service.binaryPath = config->lpBinaryPathName;
        }
        CloseServiceHandle(handle);
      }
    }
    evidence.services.push_back(std::move(service));
  }
  CloseServiceHandle(manager);
  return true;
}

bool CollectListeners(ScanCompatibilityEvidence &evidence) {
  DWORD size = 0;
  GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                      TCP_TABLE_OWNER_PID_LISTENER, 0);
  if (!size) return false;
  std::vector<BYTE> buffer(size);
  if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
                          TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR)
    return false;
  auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buffer.data());
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const auto &row = table->table[i];
    evidence.listeners.push_back(
        {ntohs(static_cast<u_short>(row.dwLocalPort)), row.dwOwningPid});
  }
  return true;
}

bool CollectFirewallAllows(ScanCompatibilityEvidence &evidence) {
  HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return false;
  INetFwPolicy2 *policy = nullptr;
  bool ok = SUCCEEDED(CoCreateInstance(
      __uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
      __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&policy))) && policy;
  INetFwRules *rules = nullptr;
  if (ok) ok = SUCCEEDED(policy->get_Rules(&rules)) && rules;
  IUnknown *unknown = nullptr;
  IEnumVARIANT *enumerator = nullptr;
  if (ok) ok = SUCCEEDED(rules->get__NewEnum(&unknown)) && unknown;
  if (ok) {
    ok = SUCCEEDED(unknown->QueryInterface(
        IID_IEnumVARIANT, reinterpret_cast<void **>(&enumerator))) && enumerator;
  }
  if (ok) {
    VARIANT item;
    VariantInit(&item);
    ULONG fetched = 0;
    HRESULT next = S_OK;
    while ((next = enumerator->Next(1, &item, &fetched)) == S_OK) {
      if (item.vt == VT_DISPATCH && item.pdispVal) {
        INetFwRule *rule = nullptr;
        if (SUCCEEDED(item.pdispVal->QueryInterface(
                __uuidof(INetFwRule), reinterpret_cast<void **>(&rule))) &&
            rule) {
          VARIANT_BOOL enabled = VARIANT_FALSE;
          NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_MAX;
          NET_FW_ACTION action = NET_FW_ACTION_MAX;
          long protocol = 0;
          if (SUCCEEDED(rule->get_Enabled(&enabled)) &&
              SUCCEEDED(rule->get_Direction(&direction)) &&
              SUCCEEDED(rule->get_Action(&action)) &&
              SUCCEEDED(rule->get_Protocol(&protocol)) &&
              enabled == VARIANT_TRUE && direction == NET_FW_RULE_DIR_IN &&
              action == NET_FW_ACTION_ALLOW &&
              protocol == NET_FW_IP_PROTOCOL_TCP) {
            BSTR name = nullptr, ports = nullptr, sources = nullptr;
            long profiles = 0;
            const bool readable = SUCCEEDED(rule->get_Name(&name)) &&
                SUCCEEDED(rule->get_LocalPorts(&ports)) &&
                SUCCEEDED(rule->get_RemoteAddresses(&sources)) &&
                SUCCEEDED(rule->get_Profiles(&profiles));
            if (readable)
              evidence.firewallAllows.push_back(
                  {BstrValue(name), BstrValue(ports), BstrValue(sources),
                   profiles});
            SysFreeString(name);
            SysFreeString(ports);
            SysFreeString(sources);
          }
          rule->Release();
        }
      }
      VariantClear(&item);
      VariantInit(&item);
    }
    VariantClear(&item);
    ok = next == S_FALSE;
  }
  if (enumerator) enumerator->Release();
  if (unknown) unknown->Release();
  if (rules) rules->Release();
  if (policy) policy->Release();
  if (SUCCEEDED(initialized)) CoUninitialize();
  return ok;
}

bool CollectShares(ScanCompatibilityEvidence &evidence) {
  LPBYTE buffer = nullptr;
  DWORD read = 0, total = 0, resume = 0;
  NET_API_STATUS status = NetShareEnum(
      nullptr, 1, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
  if (status == NERR_ServerNotStarted) return true;
  if (status != NERR_Success) {
    if (buffer) NetApiBufferFree(buffer);
    return false;
  }
  auto *shares = reinterpret_cast<SHARE_INFO_1 *>(buffer);
  for (DWORD i = 0; i < read; ++i) {
    const DWORD type = shares[i].shi1_type;
    if ((type & STYPE_MASK) != STYPE_DISKTREE || (type & STYPE_SPECIAL) ||
        !shares[i].shi1_netname)
      continue;
    evidence.nonAdministrativeShares.push_back(shares[i].shi1_netname);
  }
  NetApiBufferFree(buffer);
  return true;
}
}

ScanCompatibilityAssessment AssessScanCompatibility(
    const ScanCompatibilityEvidence &evidence) {
  ScanCompatibilityAssessment result;
  for (const auto &source : {
           std::pair<const wchar_t *, bool>{L"Windows服务", evidence.servicesReadable},
           {L"TCP监听端口", evidence.listenersReadable},
           {L"防火墙入站允许规则", evidence.firewallReadable},
           {L"SMB共享", evidence.sharesReadable}}) {
    result.details.push_back({L"证据来源", source.first,
                              source.second ? L"读取成功" : L"读取失败",
                              source.second ? L"可判定" : L"需复核"});
  }
  std::set<unsigned long> ftpProcesses;
  for (const auto &service : evidence.services) {
    if (!service.running || !IsFtpService(service)) continue;
    result.ftpDetected = true;
    if (service.processId) ftpProcesses.insert(service.processId);
    result.details.push_back(
        {L"FTP服务", service.name, service.displayName + L"；正在运行", L"已识别"});
  }

  std::set<unsigned short> controlPorts;
  for (const auto &listener : evidence.listeners) {
    if (listener.port == 21 || ftpProcesses.count(listener.processId)) {
      result.ftpDetected = true;
      controlPorts.insert(listener.port);
      result.details.push_back(
          {L"FTP监听", L"TCP " + std::to_wstring(listener.port),
           L"PID=" + std::to_wstring(listener.processId), L"已识别"});
    }
  }

  std::vector<PortSet> controlledRules;
  bool passiveAllowed = false;
  for (const auto &rule : evidence.firewallAllows) {
    const PortSet ports = ParsePorts(rule.localPorts);
    const bool ftpRule = IsFtpRule(rule);
    const bool controlled = ftpRule &&
                            ControlledSource(rule.remoteAddresses) &&
                            (rule.profiles & 7) == 7 && ports.valid;
    if (controlled) {
      controlledRules.push_back(ports);
      passiveAllowed = passiveAllowed || ports.HasBoundedPassiveRange();
    }
    bool coversControlPort = false;
    if (ports.valid) {
      for (const unsigned short port : controlPorts)
        coversControlPort = coversControlPort || ports.Covers(port);
    }
    if (ftpRule || coversControlPort) {
      result.details.push_back(
          {L"入站允许规则", rule.name,
           L"端口=" + rule.localPorts + L"；来源=" + rule.remoteAddresses +
               L"；配置文件=" + std::to_wstring(rule.profiles),
           controlled ? L"范围受控" : L"范围不完整或过宽"});
    }
  }

  bool controlsAllowed = !controlPorts.empty();
  for (const unsigned short port : controlPorts) {
    bool covered = false;
    for (const auto &ports : controlledRules)
      covered = covered || ports.Covers(port);
    controlsAllowed = controlsAllowed && covered;
  }

  const bool evidenceComplete = evidence.servicesReadable &&
      evidence.listenersReadable && evidence.firewallReadable &&
      evidence.sharesReadable;
  result.ftpProtected = result.ftpDetected && evidenceComplete &&
                        controlsAllowed && passiveAllowed;
  result.smbConflict = !evidence.nonAdministrativeShares.empty();
  for (const auto &share : evidence.nonAdministrativeShares)
    result.details.push_back(
        {L"SMB共享", share, L"非管理共享", L"与关闭Server服务及445端口冲突"});

  result.preserveDisabledFirewallProfiles =
      result.ftpDetected && !result.ftpProtected;
  result.review = !evidenceComplete ||
                  (result.ftpDetected && !result.ftpProtected) ||
                  result.smbConflict;
  if (result.ftpDetected && result.ftpProtected)
    result.actual = L"检测到FTP接收服务；控制端口、受限来源及有限被动端口范围已有允许规则";
  else if (result.ftpDetected)
    result.actual = L"检测到FTP接收服务，但控制端口、被动端口范围、允许来源或规则配置文件不完整";
  else if (!evidenceComplete)
    result.actual = L"FTP/SMB兼容性证据读取不完整";
  else
    result.actual = L"未检测到FTP接收服务";
  if (result.smbConflict)
    result.actual += L"；检测到非管理SMB共享，与当前安全基线冲突";
  return result;
}

ScanCompatibilityEvidence CollectScanCompatibilityEvidence() {
  ScanCompatibilityEvidence evidence;
  evidence.servicesReadable = CollectServices(evidence);
  evidence.listenersReadable = CollectListeners(evidence);
  evidence.firewallReadable = CollectFirewallAllows(evidence);
  evidence.sharesReadable = CollectShares(evidence);
  return evidence;
}

ScanCompatibilityAssessment InspectScanCompatibility() {
  return AssessScanCompatibility(CollectScanCompatibilityEvidence());
}
}
