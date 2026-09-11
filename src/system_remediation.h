#pragma once
#include <string>
#include <vector>

namespace sr {
struct NetbiosOptionSnapshot {
  std::wstring subkey;
  bool exists = false;
  unsigned long value = 0;
};

struct RemediationAction {
  std::wstring item;
  std::wstring action;
  std::wstring result;
  bool success = false;
  bool changed = false;
};

struct RemediationResult {
  bool authorized = false;
  bool success = false;
  bool changed = false;
  bool restartRequired = false;
  std::vector<RemediationAction> actions;
};

bool IsRemediationAuthorized();
bool CaptureNetbiosOptionSnapshots(
    std::vector<NetbiosOptionSnapshot> &states);
RemediationResult ApplySystemRemediation();
RemediationResult RollbackSystemRemediation();
}
