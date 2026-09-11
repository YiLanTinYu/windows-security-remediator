#pragma once

#include <windows.h>

#include <algorithm>
#include <string>
#include <vector>

namespace sr::win7fs {

struct Entry {
  std::wstring path;
  std::wstring name;
  DWORD attributes = 0;

  bool IsDirectory() const {
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  }
  bool IsRegularFile() const { return !IsDirectory(); }
};

inline std::wstring Join(const std::wstring &left, const std::wstring &right) {
  if (left.empty())
    return right;
  if (right.empty())
    return left;
  if ((right.size() >= 2 && right[1] == L':') || right[0] == L'\\' ||
      right[0] == L'/')
    return right;
  if (left.back() == L'\\' || left.back() == L'/')
    return left + right;
  return left + L'\\' + right;
}

template <typename... Rest>
inline std::wstring Join(const std::wstring &first, const std::wstring &second,
                         const Rest &...rest) {
  return Join(Join(first, second), rest...);
}

inline std::wstring Parent(const std::wstring &path) {
  const size_t end = path.find_last_not_of(L"\\/");
  if (end == std::wstring::npos)
    return {};
  const size_t slash = path.find_last_of(L"\\/", end);
  if (slash == std::wstring::npos)
    return {};
  if (slash == 2 && path.size() >= 3 && path[1] == L':')
    return path.substr(0, 3);
  return path.substr(0, slash);
}

inline std::wstring Filename(const std::wstring &path) {
  const size_t end = path.find_last_not_of(L"\\/");
  if (end == std::wstring::npos)
    return {};
  const size_t slash = path.find_last_of(L"\\/", end);
  return path.substr(slash == std::wstring::npos ? 0 : slash + 1,
                     end - (slash == std::wstring::npos ? 0 : slash + 1) + 1);
}

inline std::wstring Extension(const std::wstring &path) {
  const std::wstring name = Filename(path);
  const size_t dot = name.find_last_of(L'.');
  return dot == std::wstring::npos ? std::wstring{} : name.substr(dot);
}

inline DWORD Attributes(const std::wstring &path) {
  return GetFileAttributesW(path.c_str());
}

inline bool Exists(const std::wstring &path) {
  return Attributes(path) != INVALID_FILE_ATTRIBUTES;
}

inline bool IsDirectory(const std::wstring &path) {
  const DWORD attributes = Attributes(path);
  return attributes != INVALID_FILE_ATTRIBUTES &&
         (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

inline bool CreateDirectories(const std::wstring &path) {
  if (path.empty() || IsDirectory(path))
    return true;
  const std::wstring parent = Parent(path);
  if (!parent.empty() && parent != path && !IsDirectory(parent) &&
      !CreateDirectories(parent))
    return false;
  if (CreateDirectoryW(path.c_str(), nullptr))
    return true;
  return GetLastError() == ERROR_ALREADY_EXISTS && IsDirectory(path);
}

inline void EnumerateInto(const std::wstring &directory, bool recursive,
                          std::vector<Entry> &entries, DWORD &error) {
  WIN32_FIND_DATAW data{};
  HANDLE find = FindFirstFileW(Join(directory, L"*").c_str(), &data);
  if (find == INVALID_HANDLE_VALUE) {
    const DWORD current = GetLastError();
    if (current != ERROR_FILE_NOT_FOUND && current != ERROR_PATH_NOT_FOUND &&
        error == ERROR_SUCCESS)
      error = current;
    return;
  }
  do {
    if (wcscmp(data.cFileName, L".") == 0 ||
        wcscmp(data.cFileName, L"..") == 0)
      continue;
    Entry entry{Join(directory, data.cFileName), data.cFileName,
                data.dwFileAttributes};
    entries.push_back(entry);
    if (recursive && entry.IsDirectory() &&
        (entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
      EnumerateInto(entry.path, true, entries, error);
  } while (FindNextFileW(find, &data));
  const DWORD current = GetLastError();
  FindClose(find);
  if (current != ERROR_NO_MORE_FILES && error == ERROR_SUCCESS)
    error = current;
}

inline std::vector<Entry> Enumerate(const std::wstring &directory,
                                    bool recursive, DWORD &error) {
  std::vector<Entry> entries;
  error = ERROR_SUCCESS;
  if (!IsDirectory(directory))
    return entries;
  EnumerateInto(directory, recursive, entries, error);
  return entries;
}

} // namespace sr::win7fs
