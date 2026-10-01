#pragma once

#include <windows.h>

namespace sr {

class ExecutionLock {
public:
  explicit ExecutionLock(const wchar_t *name = nullptr);
  ~ExecutionLock();

  ExecutionLock(const ExecutionLock &) = delete;
  ExecutionLock &operator=(const ExecutionLock &) = delete;

  bool acquired() const { return acquired_; }
  bool alreadyRunning() const { return alreadyRunning_; }
  DWORD error() const { return error_; }

private:
  HANDLE handle_ = nullptr;
  bool acquired_ = false;
  bool alreadyRunning_ = false;
  DWORD error_ = ERROR_SUCCESS;
};

} // namespace sr
