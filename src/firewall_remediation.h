#pragma once
#include <string>
#include <vector>

namespace sr {
struct FirewallRepairResult {
  bool success = false;
  bool changed = false;
  std::wstring detail;
};

struct FirewallRuleState {
  std::wstring name;
  std::wstring description;
  std::wstring localPorts;
  long protocol = 0;
  long direction = 0;
  long action = 0;
  long profiles = 0;
  bool enabled = false;
};

struct FirewallState {
  bool valid = false;
  bool domainEnabled = false;
  bool privateEnabled = false;
  bool publicEnabled = false;
  std::vector<FirewallRuleState> rules;
};

FirewallRepairResult RepairFirewallRules();
bool CaptureFirewallState(FirewallState &state);
bool RestoreFirewallState(const FirewallState &state, std::wstring &detail);
}
