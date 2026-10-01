#include "execution_lock.h"
#include <windows.h>
#include <string>

int wmain() {
  const std::wstring name = L"Local\\SecurityRemediator.ExecutionLockTest." +
                            std::to_wstring(GetCurrentProcessId());
  {
    sr::ExecutionLock first(name.c_str());
    if (!first.acquired() || first.alreadyRunning() || first.error() != ERROR_SUCCESS)
      return 1;
    sr::ExecutionLock second(name.c_str());
    if (second.acquired() || !second.alreadyRunning() ||
        second.error() != ERROR_ALREADY_EXISTS)
      return 2;
  }
  sr::ExecutionLock afterRelease(name.c_str());
  return afterRelease.acquired() ? 0 : 3;
}
