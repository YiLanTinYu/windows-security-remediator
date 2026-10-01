#define _WIN32_WINNT 0x0601
#include "execution_lock.h"

#include <sddl.h>

namespace sr {
namespace {

constexpr wchar_t kExecutionMutexName[] =
    L"Global\\YiLanTinYu.SecurityRemediator.Execution";
constexpr wchar_t kExecutionMutexSddl[] =
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100001;;;AU)";

} // namespace

ExecutionLock::ExecutionLock(const wchar_t *name) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          kExecutionMutexSddl, SDDL_REVISION_1, &descriptor, nullptr)) {
    error_ = GetLastError();
    return;
  }
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.lpSecurityDescriptor = descriptor;
  attributes.bInheritHandle = FALSE;
  SetLastError(ERROR_SUCCESS);
  handle_ = CreateMutexW(&attributes, TRUE,
                         name && *name ? name : kExecutionMutexName);
  error_ = GetLastError();
  LocalFree(descriptor);
  if (!handle_)
    return;
  if (error_ == ERROR_ALREADY_EXISTS) {
    alreadyRunning_ = true;
    return;
  }
  acquired_ = true;
  error_ = ERROR_SUCCESS;
}

ExecutionLock::~ExecutionLock() {
  if (handle_) {
    if (acquired_)
      ReleaseMutex(handle_);
    CloseHandle(handle_);
  }
}

} // namespace sr
