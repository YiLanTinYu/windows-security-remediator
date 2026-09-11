#define _WIN32_WINNT 0x0601
#include "firewall_remediation.h"
#include <windows.h>
#include <netfw.h>
#include <oleauto.h>
#include <string>

namespace sr {
namespace {
const wchar_t *kRulePrefix = L"SecurityRemediator - Block ";
struct RuleSpec {
  int port;
  long protocol;
  const wchar_t *tag;
};
const RuleSpec kRules[] = {
    {22, NET_FW_IP_PROTOCOL_TCP, L"TCP-22"},
    {135, NET_FW_IP_PROTOCOL_TCP, L"TCP-135"},
    {136, NET_FW_IP_PROTOCOL_TCP, L"TCP-136"},
    {136, NET_FW_IP_PROTOCOL_UDP, L"UDP-136"},
    {137, NET_FW_IP_PROTOCOL_UDP, L"UDP-137"},
    {138, NET_FW_IP_PROTOCOL_UDP, L"UDP-138"},
    {139, NET_FW_IP_PROTOCOL_TCP, L"TCP-139"},
    {445, NET_FW_IP_PROTOCOL_TCP, L"TCP-445"},
    {3389, NET_FW_IP_PROTOCOL_TCP, L"TCP-3389"},
    {3389, NET_FW_IP_PROTOCOL_UDP, L"UDP-3389"}};

bool IsManagedRuleName(const std::wstring &name) {
  for (const RuleSpec &spec : kRules)
    if (name == std::wstring(kRulePrefix) + spec.tag) return true;
  return false;
}

bool Elevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return false;
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const bool ok =
      GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation),
                          &size) &&
      elevation.TokenIsElevated;
  CloseHandle(token);
  return ok;
}

bool FindRules(INetFwRules *rules, const std::wstring &name, DWORD &count,
               INetFwRule **first) {
  count = 0;
  if (first)
    *first = nullptr;
  IUnknown *unknown = nullptr;
  if (FAILED(rules->get__NewEnum(&unknown)) || !unknown)
    return false;
  IEnumVARIANT *enumerator = nullptr;
  HRESULT hr = unknown->QueryInterface(
      IID_IEnumVARIANT, reinterpret_cast<void **>(&enumerator));
  unknown->Release();
  if (FAILED(hr) || !enumerator)
    return false;
  VARIANT item;
  VariantInit(&item);
  ULONG fetched = 0;
  bool ok = true;
  while ((hr = enumerator->Next(1, &item, &fetched)) == S_OK) {
    if (item.vt == VT_DISPATCH && item.pdispVal) {
      INetFwRule *rule = nullptr;
      if (SUCCEEDED(item.pdispVal->QueryInterface(
              __uuidof(INetFwRule), reinterpret_cast<void **>(&rule))) &&
          rule) {
        BSTR ruleName = nullptr;
        if (SUCCEEDED(rule->get_Name(&ruleName)) && ruleName &&
            name == ruleName) {
          ++count;
          if (first && !*first)
            *first = rule;
          else
            rule->Release();
        } else {
          rule->Release();
        }
        SysFreeString(ruleName);
      }
    }
    VariantClear(&item);
    VariantInit(&item);
  }
  if (hr != S_FALSE)
    ok = false;
  VariantClear(&item);
  enumerator->Release();
  return ok;
}

bool Matches(INetFwRule *rule, const RuleSpec &spec, long profiles) {
  long protocol = 0, actualProfiles = 0;
  NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_MAX;
  NET_FW_ACTION action = NET_FW_ACTION_MAX;
  VARIANT_BOOL enabled = VARIANT_FALSE;
  BSTR ports = nullptr;
  const bool queried =
      SUCCEEDED(rule->get_Protocol(&protocol)) &&
      SUCCEEDED(rule->get_LocalPorts(&ports)) &&
      SUCCEEDED(rule->get_Direction(&direction)) &&
      SUCCEEDED(rule->get_Action(&action)) &&
      SUCCEEDED(rule->get_Enabled(&enabled)) &&
      SUCCEEDED(rule->get_Profiles(&actualProfiles));
  const bool match =
      queried && ports && std::to_wstring(spec.port) == ports &&
      protocol == spec.protocol && direction == NET_FW_RULE_DIR_IN &&
      action == NET_FW_ACTION_BLOCK && enabled == VARIANT_TRUE &&
      actualProfiles == profiles;
  SysFreeString(ports);
  return match;
}

bool Configure(INetFwRule *rule, const std::wstring &name,
               const RuleSpec &spec, long profiles) {
  BSTR ruleName = SysAllocString(name.c_str());
  BSTR description = SysAllocString(
      L"Inbound hardening rule; managed by SecurityRemediator.");
  BSTR ports = SysAllocString(std::to_wstring(spec.port).c_str());
  if (!ruleName || !description || !ports) {
    SysFreeString(ruleName);
    SysFreeString(description);
    SysFreeString(ports);
    return false;
  }
  bool ok = SUCCEEDED(rule->put_Name(ruleName)) &&
            SUCCEEDED(rule->put_Description(description)) &&
            SUCCEEDED(rule->put_Protocol(spec.protocol)) &&
            SUCCEEDED(rule->put_LocalPorts(ports)) &&
            SUCCEEDED(rule->put_Direction(NET_FW_RULE_DIR_IN)) &&
            SUCCEEDED(rule->put_Action(NET_FW_ACTION_BLOCK)) &&
            SUCCEEDED(rule->put_Enabled(VARIANT_TRUE)) &&
            SUCCEEDED(rule->put_Profiles(profiles));
  SysFreeString(ruleName);
  SysFreeString(description);
  SysFreeString(ports);
  return ok;
}

bool RemoveAll(INetFwRules *rules, const std::wstring &name) {
  DWORD count = 0;
  if (!FindRules(rules, name, count, nullptr))
    return false;
  while (count > 0) {
    BSTR ruleName = SysAllocString(name.c_str());
    if (!ruleName)
      return false;
    HRESULT hr = rules->Remove(ruleName);
    SysFreeString(ruleName);
    if (FAILED(hr))
      return false;
    DWORD remaining = 0;
    if (!FindRules(rules, name, remaining, nullptr) || remaining >= count)
      return false;
    count = remaining;
  }
  return true;
}

bool AddStateRule(INetFwRules *rules, const FirewallRuleState &state) {
  INetFwRule *rule = nullptr;
  if (FAILED(CoCreateInstance(__uuidof(NetFwRule), nullptr,
                              CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
                              reinterpret_cast<void **>(&rule))) || !rule)
    return false;
  BSTR name = SysAllocString(state.name.c_str());
  BSTR description = SysAllocString(state.description.c_str());
  BSTR ports = SysAllocString(state.localPorts.c_str());
  const bool ok = name && description && ports &&
      SUCCEEDED(rule->put_Name(name)) &&
      SUCCEEDED(rule->put_Description(description)) &&
      SUCCEEDED(rule->put_Protocol(state.protocol)) &&
      SUCCEEDED(rule->put_LocalPorts(ports)) &&
      SUCCEEDED(rule->put_Direction(
          static_cast<NET_FW_RULE_DIRECTION>(state.direction))) &&
      SUCCEEDED(rule->put_Action(static_cast<NET_FW_ACTION>(state.action))) &&
      SUCCEEDED(rule->put_Enabled(state.enabled ? VARIANT_TRUE : VARIANT_FALSE)) &&
      SUCCEEDED(rule->put_Profiles(state.profiles)) && SUCCEEDED(rules->Add(rule));
  SysFreeString(name);
  SysFreeString(description);
  SysFreeString(ports);
  rule->Release();
  return ok;
}

bool CollectStateRules(INetFwRules *rules, FirewallState &state) {
  IUnknown *unknown = nullptr;
  if (FAILED(rules->get__NewEnum(&unknown)) || !unknown) return false;
  IEnumVARIANT *enumerator = nullptr;
  HRESULT hr = unknown->QueryInterface(
      IID_IEnumVARIANT, reinterpret_cast<void **>(&enumerator));
  unknown->Release();
  if (FAILED(hr) || !enumerator) return false;
  VARIANT item;
  VariantInit(&item);
  ULONG fetched = 0;
  while ((hr = enumerator->Next(1, &item, &fetched)) == S_OK) {
    if (item.vt == VT_DISPATCH && item.pdispVal) {
      INetFwRule *rule = nullptr;
      if (SUCCEEDED(item.pdispVal->QueryInterface(
              __uuidof(INetFwRule), reinterpret_cast<void **>(&rule))) && rule) {
        BSTR name = nullptr;
        if (SUCCEEDED(rule->get_Name(&name)) && name &&
            IsManagedRuleName(name)) {
          FirewallRuleState saved;
          saved.name = name;
          BSTR description = nullptr, ports = nullptr;
          VARIANT_BOOL enabled = VARIANT_FALSE;
          NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_MAX;
          NET_FW_ACTION action = NET_FW_ACTION_MAX;
          const bool ok = SUCCEEDED(rule->get_Description(&description)) &&
              SUCCEEDED(rule->get_LocalPorts(&ports)) &&
              SUCCEEDED(rule->get_Protocol(&saved.protocol)) &&
              SUCCEEDED(rule->get_Direction(&direction)) &&
              SUCCEEDED(rule->get_Action(&action)) &&
              SUCCEEDED(rule->get_Enabled(&enabled)) &&
              SUCCEEDED(rule->get_Profiles(&saved.profiles));
          if (ok) {
            if (description) saved.description = description;
            if (ports) saved.localPorts = ports;
            saved.direction = direction;
            saved.action = action;
            saved.enabled = enabled == VARIANT_TRUE;
            state.rules.push_back(saved);
          }
          SysFreeString(description);
          SysFreeString(ports);
          if (!ok) {
            SysFreeString(name);
            rule->Release();
            VariantClear(&item);
            enumerator->Release();
            return false;
          }
        }
        SysFreeString(name);
        rule->Release();
      }
    }
    VariantClear(&item);
    VariantInit(&item);
  }
  VariantClear(&item);
  enumerator->Release();
  return hr == S_FALSE;
}

bool EnsureRule(INetFwRules *rules, const RuleSpec &spec, long profiles,
                bool &changed) {
  const std::wstring name = std::wstring(kRulePrefix) + spec.tag;
  DWORD count = 0;
  INetFwRule *existing = nullptr;
  if (!FindRules(rules, name, count, &existing))
    return false;
  if (count == 1 && existing) {
    if (Matches(existing, spec, profiles)) {
      existing->Release();
      return true;
    }
    const bool ok = Configure(existing, name, spec, profiles) &&
                    Matches(existing, spec, profiles);
    existing->Release();
    changed = changed || ok;
    return ok;
  }
  if (existing)
    existing->Release();
  if (count > 0 && !RemoveAll(rules, name))
    return false;
  INetFwRule *rule = nullptr;
  if (FAILED(CoCreateInstance(__uuidof(NetFwRule), nullptr,
                              CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
                              reinterpret_cast<void **>(&rule))) ||
      !rule)
    return false;
  const bool added =
      Configure(rule, name, spec, profiles) && SUCCEEDED(rules->Add(rule));
  rule->Release();
  if (!added)
    return false;
  DWORD finalCount = 0;
  const bool ok =
      FindRules(rules, name, finalCount, nullptr) && finalCount == 1;
  changed = changed || ok;
  return ok;
}
} // namespace

FirewallRepairResult RepairFirewallRules() {
  FirewallRepairResult result;
  if (!Elevated()) {
    result.detail = L"需要 SYSTEM 或已提升的管理员权限";
    return result;
  }
  HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) {
    result.detail = L"COM 初始化失败";
    return result;
  }
  INetFwPolicy2 *policy = nullptr;
  HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                                CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                reinterpret_cast<void **>(&policy));
  if (FAILED(hr) || !policy) {
    result.detail = L"无法打开 Windows 防火墙策略";
    if (SUCCEEDED(initialized))
      CoUninitialize();
    return result;
  }
  bool ok = true;
  const long allProfiles = NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE |
                           NET_FW_PROFILE2_PUBLIC;
  for (long profile : {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
                       NET_FW_PROFILE2_PUBLIC}) {
    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (FAILED(policy->get_FirewallEnabled(
            static_cast<NET_FW_PROFILE_TYPE2>(profile), &enabled))) {
      ok = false;
    } else if (enabled != VARIANT_TRUE) {
      if (SUCCEEDED(policy->put_FirewallEnabled(
              static_cast<NET_FW_PROFILE_TYPE2>(profile), VARIANT_TRUE)))
        result.changed = true;
      else
        ok = false;
    }
  }
  INetFwRules *rules = nullptr;
  if (FAILED(policy->get_Rules(&rules)) || !rules) {
    ok = false;
  } else {
    for (const RuleSpec &rule : kRules)
      if (!EnsureRule(rules, rule, allProfiles, result.changed))
        ok = false;
    rules->Release();
  }
  policy->Release();
  if (SUCCEEDED(initialized))
    CoUninitialize();
  result.success = ok;
  result.detail = ok ? (result.changed ? L"防火墙规则已修复并复检"
                                       : L"防火墙规则已符合要求")
                     : L"至少一项防火墙规则修复失败";
  return result;
}

bool CaptureFirewallState(FirewallState &state) {
  state = FirewallState{};
  HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return false;
  INetFwPolicy2 *policy = nullptr;
  bool ok = SUCCEEDED(CoCreateInstance(
      __uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
      __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&policy))) && policy;
  if (ok) {
    VARIANT_BOOL domain = VARIANT_FALSE, privateProfile = VARIANT_FALSE,
                 publicProfile = VARIANT_FALSE;
    ok = SUCCEEDED(policy->get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, &domain)) &&
         SUCCEEDED(policy->get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, &privateProfile)) &&
         SUCCEEDED(policy->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &publicProfile));
    state.domainEnabled = domain == VARIANT_TRUE;
    state.privateEnabled = privateProfile == VARIANT_TRUE;
    state.publicEnabled = publicProfile == VARIANT_TRUE;
    INetFwRules *rules = nullptr;
    if (!ok || FAILED(policy->get_Rules(&rules)) || !rules) ok = false;
    else {
      ok = CollectStateRules(rules, state);
      rules->Release();
    }
    policy->Release();
  }
  if (SUCCEEDED(initialized)) CoUninitialize();
  state.valid = ok;
  return ok;
}

bool RestoreFirewallState(const FirewallState &state, std::wstring &detail) {
  if (!state.valid || !Elevated()) {
    detail = L"防火墙备份无效或权限不足";
    return false;
  }
  HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return false;
  INetFwPolicy2 *policy = nullptr;
  bool ok = SUCCEEDED(CoCreateInstance(
      __uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
      __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&policy))) && policy;
  if (ok) {
    ok = SUCCEEDED(policy->put_FirewallEnabled(
             NET_FW_PROFILE2_DOMAIN, state.domainEnabled ? VARIANT_TRUE : VARIANT_FALSE)) && ok;
    ok = SUCCEEDED(policy->put_FirewallEnabled(
             NET_FW_PROFILE2_PRIVATE, state.privateEnabled ? VARIANT_TRUE : VARIANT_FALSE)) && ok;
    ok = SUCCEEDED(policy->put_FirewallEnabled(
             NET_FW_PROFILE2_PUBLIC, state.publicEnabled ? VARIANT_TRUE : VARIANT_FALSE)) && ok;
    INetFwRules *rules = nullptr;
    if (FAILED(policy->get_Rules(&rules)) || !rules) ok = false;
    else {
      for (const RuleSpec &spec : kRules) {
        const std::wstring name = std::wstring(kRulePrefix) + spec.tag;
        if (!RemoveAll(rules, name)) ok = false;
      }
      for (const auto &rule : state.rules)
        if (!AddStateRule(rules, rule)) ok = false;
      rules->Release();
    }
    policy->Release();
  }
  if (SUCCEEDED(initialized)) CoUninitialize();
  detail = ok ? L"防火墙配置已恢复" : L"防火墙配置恢复不完整";
  return ok;
}
} // namespace sr
