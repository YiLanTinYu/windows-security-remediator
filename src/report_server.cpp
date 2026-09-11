#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <http.h>
#include <netfw.h>
#include <shellapi.h>
#include <sddl.h>
#include <wincrypt.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
namespace {
std::string Utf8(const std::wstring &v) {
  if (v.empty())
    return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, v.data(), static_cast<int>(v.size()),
                              nullptr, 0, nullptr, nullptr);
  std::string o(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, v.data(), static_cast<int>(v.size()),
                      o.data(), n, nullptr, nullptr);
  return o;
}
std::wstring Utf16(const std::string &v) {
  if (v.empty())
    return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, v.data(), static_cast<int>(v.size()),
                              nullptr, 0);
  std::wstring o(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, v.data(), static_cast<int>(v.size()),
                      o.data(), n);
  return o;
}
std::string Hex(const BYTE *data, size_t size) {
  std::ostringstream o;
  o << std::hex << std::uppercase << std::setfill('0');
  for (size_t i = 0; i < size; i++)
    o << std::setw(2) << static_cast<unsigned>(data[i]);
  return o.str();
}
bool Unhex(const std::string &text, std::vector<BYTE> &out) {
  if (text.size() % 2)
    return false;
  out.clear();
  for (size_t i = 0; i < text.size(); i += 2) {
    unsigned x = 0;
    std::istringstream in(text.substr(i, 2));
    in >> std::hex >> x;
    if (!in || x > 255)
      return false;
    out.push_back(static_cast<BYTE>(x));
  }
  return true;
}
std::string RandomHex(size_t bytes) {
  std::vector<BYTE> b(bytes);
  if (BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(b.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    throw std::runtime_error("random generation failed");
  return Hex(b.data(), b.size());
}
std::string Sha256(const std::vector<BYTE> &input,
                   const std::vector<BYTE> *key = nullptr) {
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD objectSize = 0, hashSize = 0, done = 0;
  std::vector<BYTE> object, output;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  key ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) < 0)
    goto fail;
  if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<BYTE *>(&objectSize),
                        sizeof(objectSize), &done, 0) < 0 ||
      BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                        reinterpret_cast<BYTE *>(&hashSize), sizeof(hashSize),
                        &done, 0) < 0)
    goto fail;
  object.resize(objectSize);
  output.resize(hashSize);
  if (BCryptCreateHash(alg, &hash, object.data(), objectSize,
                       key ? const_cast<BYTE *>(key->data()) : nullptr,
                       key ? static_cast<ULONG>(key->size()) : 0, 0) < 0 ||
      BCryptHashData(hash, const_cast<BYTE *>(input.data()),
                     static_cast<ULONG>(input.size()), 0) < 0 ||
      BCryptFinishHash(hash, output.data(), hashSize, 0) < 0)
    goto fail;
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(alg, 0);
  return Hex(output.data(), output.size());
fail:
  if (hash)
    BCryptDestroyHash(hash);
  if (alg)
    BCryptCloseAlgorithmProvider(alg, 0);
  throw std::runtime_error("hash failed");
}
bool ConstantEqual(const std::string &a, const std::string &b) {
  if (a.size() != b.size())
    return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); i++)
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  return diff == 0;
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
std::string Escape8(const std::string &value) {
  return Utf8(Html(Utf16(value)));
}
std::string UrlDecode(const std::string &value) {
  std::string out;
  for (size_t i = 0; i < value.size(); i++) {
    if (value[i] == '+')
      out += ' ';
    else if (value[i] == '%' && i + 2 < value.size()) {
      unsigned x = 0;
      std::istringstream in(value.substr(i + 1, 2));
      in >> std::hex >> x;
      if (in) {
        out += static_cast<char>(x);
        i += 2;
      } else
        out += value[i];
    } else
      out += value[i];
  }
  return out;
}
std::map<std::string, std::string> Form(const std::vector<BYTE> &body) {
  std::map<std::string, std::string> result;
  std::string text(body.begin(), body.end());
  size_t start = 0;
  while (start <= text.size()) {
    size_t amp = text.find('&', start);
    std::string item = text.substr(
        start, amp == std::string::npos ? std::string::npos : amp - start);
    size_t eq = item.find('=');
    result[UrlDecode(item.substr(0, eq))] =
        eq == std::string::npos ? "" : UrlDecode(item.substr(eq + 1));
    if (amp == std::string::npos)
      break;
    start = amp + 1;
  }
  return result;
}

struct Options {
  fs::path data;
  std::wstring host = L"+";
  USHORT port = 8443;
  bool selfTest = false, console = false, service = false, install = false,
       uninstall = false;
};
Options Parse(int argc, wchar_t **argv) {
  wchar_t *raw = nullptr;
  size_t count = 0;
  _wdupenv_s(&raw, &count, L"ProgramData");
  std::unique_ptr<wchar_t, decltype(&free)> programData(raw, &free);
  fs::path base = raw ? raw : L"C:\\ProgramData";
  Options o;
  o.data = base / L"SecurityInspectionReportServer";
  for (int i = 1; i < argc; i++) {
    std::wstring a = argv[i];
    if (a.rfind(L"/data=", 0) == 0)
      o.data = fs::absolute(a.substr(6));
    else if (a.rfind(L"/listen=", 0) == 0)
      o.host = a.substr(8);
    else if (a.rfind(L"/port=", 0) == 0) {
      long p = wcstol(a.c_str() + 6, nullptr, 10);
      if (p < 1 || p > 65535)
        throw std::invalid_argument("port");
      o.port = static_cast<USHORT>(p);
    } else if (a == L"/self-test")
      o.selfTest = true;
    else if (a == L"/console")
      o.console = true;
    else if (a == L"/service")
      o.service = true;
    else if (a == L"/install")
      o.install = true;
    else if (a == L"/uninstall")
      o.uninstall = true;
    else
      throw std::invalid_argument("argument");
  }
  return o;
}

std::string PasswordError(const std::string &password, const std::string &user,
                          const std::string &host) {
  std::wstring w = Utf16(password);
  if (w.size() < 15)
    return "密码至少需要15个字符";
  if (w.size() > 128)
    return "密码不能超过128个字符";
  std::string lower = password;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return static_cast<char>(tolower(c)); });
  std::string userLower = user;
  std::transform(userLower.begin(), userLower.end(), userLower.begin(),
                 [](unsigned char c) { return static_cast<char>(tolower(c)); });
  static const std::set<std::string> blocked = {
      "123456789012345", "passwordpassword", "administrator123",
      "qwertyuiop12345", "adminadminadmin",  "woainiwoaini123",
      "111111111111111"};
  if (blocked.count(lower) ||
      (!userLower.empty() && lower.find(userLower) != std::string::npos) ||
      lower.find("reportserver") != std::string::npos ||
      (!host.empty() && lower.find(host) != std::string::npos))
    return "密码属于常见或与当前环境相关的弱密码";
  std::set<unsigned char> chars(password.begin(), password.end());
  if (chars.size() <= 3)
    return "密码包含过多重复字符";
  bool upper = false, lowerCase = false, digit = false, symbol = false;
  for (unsigned char c : password) {
    upper |= isupper(c) != 0;
    lowerCase |= islower(c) != 0;
    digit |= isdigit(c) != 0;
    symbol |= !isalnum(c);
  }
  if (static_cast<int>(upper) + lowerCase + digit + symbol < 3)
    return "密码必须包含大写字母、小写字母、数字、符号中的至少三类";
  return {};
}
bool ValidUser(const std::string &name) {
  std::wstring decoded = Utf16(name);
  if (decoded.size() < 3 || decoded.size() > 64)
    return false;
  return std::none_of(name.begin(), name.end(), [](unsigned char c) {
    return c < ' ' || c == 127 || c == '/' || c == '\\' || c == ':';
  });
}
struct User {
  std::string name, salt, hash;
  ULONG iterations = 600000;
};
class Users {
  fs::path path;
  std::vector<User> users;
  std::mutex lock;
  void Save() {
    fs::create_directories(path.parent_path());
    fs::path temp = path;
    temp += L".tmp";
    std::ofstream out(temp, std::ios::binary);
    for (const auto &u : users)
      out << u.name << '\t' << u.salt << '\t' << u.hash << '\t' << u.iterations
          << '\n';
    out.close();
    if (!out || !MoveFileExW(temp.c_str(), path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      throw std::runtime_error("cannot save user database");
  }
  std::string Derive(const std::string &p, const std::string &s, ULONG it) {
    std::vector<BYTE> salt;
    Unhex(s, salt);
    std::vector<BYTE> pass(p.begin(), p.end()), hash(32);
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
      throw std::runtime_error("pbkdf2 provider");
    NTSTATUS status =
        BCryptDeriveKeyPBKDF2(alg, pass.data(), static_cast<ULONG>(pass.size()),
                              salt.data(), static_cast<ULONG>(salt.size()), it,
                              hash.data(), static_cast<ULONG>(hash.size()), 0);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (status < 0)
      throw std::runtime_error("pbkdf2 failed");
    return Hex(hash.data(), hash.size());
  }

public:
  explicit Users(fs::path p) : path(std::move(p)) {
    std::ifstream in(path, std::ios::binary);
    std::string line;
    while (std::getline(in, line)) {
      std::istringstream row(line);
      User u;
      std::string iterations;
      if (std::getline(row, u.name, '\t') && std::getline(row, u.salt, '\t') &&
          std::getline(row, u.hash, '\t') && std::getline(row, iterations))
        try {
          u.iterations = static_cast<ULONG>(std::stoul(iterations));
          users.push_back(u);
        } catch (...) {
        }
    }
  }
  size_t Count() {
    std::lock_guard<std::mutex> g(lock);
    return users.size();
  }
  std::vector<std::string> Names() {
    std::lock_guard<std::mutex> g(lock);
    std::vector<std::string> n;
    for (auto &u : users)
      n.push_back(u.name);
    return n;
  }
  bool Contains(const std::string &name) {
    std::lock_guard<std::mutex> g(lock);
    return std::any_of(users.begin(), users.end(), [&](const User &u) {
      return _stricmp(u.name.c_str(), name.c_str()) == 0;
    });
  }
  void Add(const std::string &name, const std::string &password) {
    if (!ValidUser(name))
      throw std::invalid_argument("invalid user name");
    std::lock_guard<std::mutex> g(lock);
    User u{name, RandomHex(16), {}, 600000};
    u.hash = Derive(password, u.salt, u.iterations);
    users.push_back(u);
    Save();
  }
  bool Verify(const std::string &name, const std::string &password) {
    std::lock_guard<std::mutex> g(lock);
    auto it = std::find_if(users.begin(), users.end(), [&](const User &u) {
      return _stricmp(u.name.c_str(), name.c_str()) == 0;
    });
    if (it == users.end())
      return false;
    return ConstantEqual(it->hash, Derive(password, it->salt, it->iterations));
  }
};

struct Envelope {
  std::string computer, ip, mac, finished, passed, failed, review, html, json;
};
std::string Field(const std::vector<BYTE> &body, size_t &at, size_t limit) {
  if (at + 4 > body.size())
    throw std::runtime_error("truncated envelope");
  uint32_t n = body[at] | (body[at + 1] << 8) | (body[at + 2] << 16) |
               (body[at + 3] << 24);
  at += 4;
  if (n > limit || at + n > body.size())
    throw std::runtime_error("invalid field length");
  std::string value(reinterpret_cast<const char *>(body.data() + at), n);
  at += n;
  return value;
}
Envelope Decode(const std::vector<BYTE> &body) {
  if (body.size() < 4 || memcmp(body.data(), "SRR1", 4) != 0)
    throw std::runtime_error("invalid envelope");
  size_t at = 4;
  Envelope e;
  e.computer = Field(body, at, 256);
  e.ip = Field(body, at, 128);
  e.mac = Field(body, at, 128);
  e.finished = Field(body, at, 128);
  e.passed = Field(body, at, 16);
  e.failed = Field(body, at, 16);
  e.review = Field(body, at, 16);
  e.html = Field(body, at, 8000000);
  e.json = Field(body, at, 4000000);
  if (at != body.size() || e.computer.empty() || e.html.size() < 20 ||
      e.json.size() < 2)
    throw std::runtime_error("incomplete envelope");
  return e;
}
void Append(std::vector<BYTE> &body, const std::string &v) {
  uint32_t n = static_cast<uint32_t>(v.size());
  for (int i = 0; i < 4; i++)
    body.push_back(static_cast<BYTE>(n >> (8 * i)));
  body.insert(body.end(), v.begin(), v.end());
}
std::vector<BYTE> Encode(const Envelope &e) {
  std::vector<BYTE> b{'S', 'R', 'R', '1'};
  for (const auto &v : {e.computer, e.ip, e.mac, e.finished, e.passed, e.failed,
                        e.review, e.html, e.json})
    Append(b, v);
  return b;
}
struct Report {
  std::string id, computer, ip, mac, finished, passed, failed, review;
};
class Reports {
  fs::path dir;

public:
  explicit Reports(fs::path p) : dir(std::move(p)) {
    fs::create_directories(dir);
  }
  std::string Save(const Envelope &e) {
    SYSTEMTIME t{};
    GetSystemTime(&t);
    char stamp[80]{};
    sprintf_s(stamp, "%04u%02u%02u-%02u%02u%02u-%03u_", t.wYear, t.wMonth,
              t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    std::string id = stamp + RandomHex(6);
    fs::path base = dir / Utf16(id);
    std::ofstream h(base.wstring() + L".html", std::ios::binary),
        j(base.wstring() + L".json", std::ios::binary),
        m(base.wstring() + L".meta", std::ios::binary);
    h.write(e.html.data(), static_cast<std::streamsize>(e.html.size()));
    j.write(e.json.data(), static_cast<std::streamsize>(e.json.size()));
    m << e.computer << '\t' << e.ip << '\t' << e.mac << '\t' << e.finished
      << '\t' << e.passed << '\t' << e.failed << '\t' << e.review;
    if (!h || !j || !m)
      throw std::runtime_error("report write failed");
    return id;
  }
  std::vector<Report> List(const std::string &q = {}) {
    std::vector<Report> v;
    std::error_code ec;
    for (auto it = fs::directory_iterator(
             dir, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::directory_iterator(); it.increment(ec)) {
      if (it->path().extension() != L".meta")
        continue;
      std::ifstream in(it->path(), std::ios::binary);
      Report r;
      r.id = Utf8(it->path().stem().wstring());
      if (std::getline(in, r.computer, '\t') && std::getline(in, r.ip, '\t') &&
          std::getline(in, r.mac, '\t') && std::getline(in, r.finished, '\t') &&
          std::getline(in, r.passed, '\t') &&
          std::getline(in, r.failed, '\t') && std::getline(in, r.review)) {
        if (q.empty() || (r.computer + r.ip + r.mac + r.finished).find(q) !=
                             std::string::npos)
          v.push_back(r);
      }
    }
    std::sort(v.begin(), v.end(),
              [](const Report &a, const Report &b) { return a.id > b.id; });
    return v;
  }
  fs::path Path(const std::string &id, const std::wstring &ext) {
    if (id.empty() || !std::all_of(id.begin(), id.end(), [](unsigned char c) {
          return isalnum(c) || c == '-' || c == '_';
        }))
      return {};
    fs::path p = dir / Utf16(id + Utf8(ext));
    return fs::is_regular_file(p) ? p : fs::path{};
  }
};

std::vector<BYTE> ReadFileBytes(const fs::path &path, size_t limit) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return {};
  in.seekg(0, std::ios::end);
  auto n = in.tellg();
  if (n < 0 || static_cast<unsigned long long>(n) > limit)
    return {};
  in.seekg(0);
  std::vector<BYTE> b(static_cast<size_t>(n));
  in.read(reinterpret_cast<char *>(b.data()), n);
  return in ? b : std::vector<BYTE>{};
}
std::string Header(const HTTP_REQUEST &request, const char *name) {
  for (USHORT i = 0; i < request.Headers.UnknownHeaderCount; i++) {
    const auto &h = request.Headers.pUnknownHeaders[i];
    if (h.NameLength == strlen(name) &&
        _strnicmp(h.pName, name, h.NameLength) == 0)
      return std::string(h.pRawValue, h.RawValueLength);
  }
  return {};
}
std::string KnownHeader(const HTTP_REQUEST &request, HTTP_HEADER_ID id) {
  const auto &h = request.Headers.KnownHeaders[id];
  return h.pRawValue ? std::string(h.pRawValue, h.RawValueLength)
                     : std::string{};
}
std::string ClientAddress(const HTTP_REQUEST &request) {
  char text[INET6_ADDRSTRLEN]{};
  const SOCKADDR *sa = request.Address.pRemoteAddress;
  if (!sa)
    return {};
  if (sa->sa_family == AF_INET) {
    auto *v = reinterpret_cast<const sockaddr_in *>(sa);
    InetNtopA(AF_INET, const_cast<IN_ADDR *>(&v->sin_addr), text, sizeof(text));
  } else if (sa->sa_family == AF_INET6) {
    auto *v = reinterpret_cast<const sockaddr_in6 *>(sa);
    InetNtopA(AF_INET6, const_cast<IN6_ADDR *>(&v->sin6_addr), text,
              sizeof(text));
  }
  return text;
}
bool IsLoopback(const std::string &ip) {
  return ip == "127.0.0.1" || ip == "::1" || ip == "0:0:0:0:0:0:0:1";
}
std::string CookieValue(const std::string &cookie, const std::string &name) {
  size_t at = 0;
  while (at < cookie.size()) {
    while (at < cookie.size() && (cookie[at] == ' ' || cookie[at] == ';'))
      at++;
    size_t eq = cookie.find('=', at), end = cookie.find(';', at);
    if (eq != std::string::npos && (end == std::string::npos || eq < end) &&
        cookie.substr(at, eq - at) == name)
      return cookie.substr(
          eq + 1, (end == std::string::npos ? cookie.size() : end) - eq - 1);
    if (end == std::string::npos)
      break;
    at = end + 1;
  }
  return {};
}
std::string QueryValue(const std::wstring &query, const std::string &name) {
  if (query.empty())
    return {};
  std::string q = Utf8(query[0] == L'?' ? query.substr(1) : query);
  auto values = Form(std::vector<BYTE>(q.begin(), q.end()));
  auto it = values.find(name);
  return it == values.end() ? std::string{} : it->second;
}
std::wstring HttpUrlPart(PCWSTR value, USHORT lengthBytes) {
  if (!value || lengthBytes == 0)
    return {};
  return std::wstring(value, lengthBytes / sizeof(wchar_t));
}
std::string Page(const std::string &title, const std::string &body) {
  return "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta "
         "name=\"viewport\" "
         "content=\"width=device-width,initial-scale=1\"><title>" +
         title +
         "</title><style>body{font-family:'Microsoft "
         "YaHei',sans-serif;background:#f4f6f8;color:#17212b;margin:0}.wrap{"
         "max-width:1100px;margin:36px "
         "auto;background:#fff;padding:30px;border:1px solid "
         "#d9e0e7;border-radius:10px}h1{font-size:24px}input,button{font:"
         "inherit;padding:9px;margin:4px;border:1px solid "
         "#bdc8d2;border-radius:5px}button{background:#1769aa;color:#fff}table{"
         "border-collapse:collapse;width:100%;margin-top:20px}th,td{border:1px "
         "solid "
         "#d7dee5;padding:9px;text-align:left}th{background:#eef2f5}.bad{color:"
         "#b42318}.ok{color:#067647}.note{background:#fff7df;padding:12px}."
         "right{float:right}a{color:#1769aa}</style><div class=\"wrap\">" +
         body + "</div></html>";
}

struct Session {
  std::string user, csrf;
  std::chrono::steady_clock::time_point expires;
};
class WebServer {
  Options options;
  Users users;
  Reports reports;
  std::vector<BYTE> uploadKey;
  HANDLE queue = nullptr;
  HTTP_SERVER_SESSION_ID sessionId = 0;
  HTTP_URL_GROUP_ID groupId = 0;
  std::mutex stateLock;
  std::map<std::string, Session> sessions;
  std::map<std::string, std::vector<std::chrono::steady_clock::time_point>>
      failures;
  std::map<std::string, std::chrono::steady_clock::time_point> nonces;
  void Respond(HTTP_REQUEST_ID id, USHORT code, const std::string &body,
               const char *type = "text/html; charset=utf-8",
               const std::string &extra = {}) {
    HTTP_RESPONSE response{};
    response.StatusCode = code;
    const char *reason = code == 200   ? "OK"
                         : code == 201 ? "Created"
                         : code == 302 ? "Found"
                         : code == 400 ? "Bad Request"
                         : code == 401 ? "Unauthorized"
                         : code == 403 ? "Forbidden"
                         : code == 404 ? "Not Found"
                         : code == 409 ? "Conflict"
                         : code == 413 ? "Payload Too Large"
                         : code == 429 ? "Too Many Requests"
                                       : "Internal Server Error";
    response.pReason = reason;
    response.ReasonLength = static_cast<USHORT>(strlen(reason));
    response.Headers.KnownHeaders[HttpHeaderContentType].pRawValue = type;
    response.Headers.KnownHeaders[HttpHeaderContentType].RawValueLength =
        static_cast<USHORT>(strlen(type));
    std::string name, value;
    if (!extra.empty()) {
      size_t colon = extra.find(':');
      if (colon != std::string::npos) {
        name = extra.substr(0, colon);
        size_t start = colon + 1;
        while (start < extra.size() && extra[start] == ' ')
          start++;
        value = extra.substr(start);
        HTTP_KNOWN_HEADER *known = nullptr;
        if (_stricmp(name.c_str(), "Location") == 0)
          known = &response.Headers.KnownHeaders[HttpHeaderLocation];
        else if (_stricmp(name.c_str(), "Set-Cookie") == 0)
          known = &response.Headers.KnownHeaders[HttpHeaderSetCookie];
        if (known) {
          known->pRawValue = value.data();
          known->RawValueLength = static_cast<USHORT>(value.size());
        }
      }
    }
    std::string defaultLocation;
    if (code == 302 &&
        !response.Headers.KnownHeaders[HttpHeaderLocation].pRawValue) {
      defaultLocation = "/";
      response.Headers.KnownHeaders[HttpHeaderLocation].pRawValue =
          defaultLocation.data();
      response.Headers.KnownHeaders[HttpHeaderLocation].RawValueLength = 1;
    }
    const char *csp = "default-src 'none'; style-src 'unsafe-inline'; "
                      "form-action 'self'; base-uri 'none'",
               *nosniff = "nosniff";
    HTTP_UNKNOWN_HEADER security[2] = {
        {static_cast<USHORT>(strlen("Content-Security-Policy")),
         static_cast<USHORT>(strlen(csp)), "Content-Security-Policy", csp},
        {static_cast<USHORT>(strlen("X-Content-Type-Options")),
         static_cast<USHORT>(strlen(nosniff)), "X-Content-Type-Options",
         nosniff}};
    response.Headers.UnknownHeaderCount = 2;
    response.Headers.pUnknownHeaders = security;
    HTTP_DATA_CHUNK chunk{};
    chunk.DataChunkType = HttpDataChunkFromMemory;
    chunk.FromMemory.pBuffer = const_cast<char *>(body.data());
    chunk.FromMemory.BufferLength = static_cast<ULONG>(body.size());
    response.EntityChunkCount = body.empty() ? 0 : 1;
    response.pEntityChunks = body.empty() ? nullptr : &chunk;
    ULONG sent = 0;
    HttpSendHttpResponse(queue, id, 0, &response, nullptr, &sent, nullptr, 0,
                         nullptr, nullptr);
  }
  std::vector<BYTE> Body(const HTTP_REQUEST &r) {
    std::vector<BYTE> b;
    BYTE part[32768];
    for (;;) {
      ULONG got = 0;
      ULONG rc = HttpReceiveRequestEntityBody(queue, r.RequestId, 0, part,
                                              sizeof(part), &got, nullptr);
      if (got) {
        if (b.size() + got > 12 * 1024 * 1024)
          throw std::length_error("body");
        b.insert(b.end(), part, part + got);
      }
      if (rc == ERROR_HANDLE_EOF)
        break;
      if (rc == NO_ERROR && got == 0)
        break;
      if (rc != NO_ERROR && rc != ERROR_MORE_DATA)
        throw std::runtime_error("request body");
    }
    return b;
  }
  Session *Auth(const HTTP_REQUEST &r, std::string &token) {
    token = CookieValue(KnownHeader(r, HttpHeaderCookie), "SRSESSION");
    std::lock_guard<std::mutex> g(stateLock);
    auto it = sessions.find(token);
    if (it == sessions.end() ||
        it->second.expires < std::chrono::steady_clock::now()) {
      if (it != sessions.end())
        sessions.erase(it);
      return nullptr;
    }
    it->second.expires =
        std::chrono::steady_clock::now() + std::chrono::hours(8);
    return &it->second;
  }
  bool Limited(const std::string &ip, bool record) {
    std::lock_guard<std::mutex> g(stateLock);
    auto now = std::chrono::steady_clock::now();
    auto &v = failures[ip];
    v.erase(std::remove_if(
                v.begin(), v.end(),
                [&](auto t) { return now - t > std::chrono::minutes(15); }),
            v.end());
    if (record)
      v.push_back(now);
    return v.size() >= 8;
  }
  bool FreshNonce(const std::string &nonce) {
    std::lock_guard<std::mutex> g(stateLock);
    auto now = std::chrono::steady_clock::now();
    for (auto it = nonces.begin(); it != nonces.end();)
      if (now - it->second > std::chrono::minutes(10))
        it = nonces.erase(it);
      else
        ++it;
    if (nonces.count(nonce))
      return false;
    nonces[nonce] = now;
    return true;
  }
  std::string Dashboard(const Session &s, const std::string &q) {
    std::ostringstream b;
    b << "<a class=right "
         "href=\"/logout\">退出</a><h1>终端安全检查报告</h1><p>当前管理员："
      << Escape8(s.user) << "</p><form method=get><input name=q value=\""
      << Escape8(q)
      << "\" "
         "placeholder=\"计算机名、IP、MAC或时间\"><button>查询</button></"
         "form><table><tr><th>检查时间</th><th>计算机</th><th>IP</th><th>MAC</"
         "th><th>通过</th><th>异常</th><th>复核</th><th>报告</th></tr>";
    for (auto &r : reports.List(q))
      b << "<tr><td>" << Escape8(r.finished) << "</td><td>"
        << Escape8(r.computer) << "</td><td>" << Escape8(r.ip) << "</td><td>"
        << Escape8(r.mac) << "</td><td class=ok>" << Escape8(r.passed)
        << "</td><td class=bad>" << Escape8(r.failed) << "</td><td>"
        << Escape8(r.review) << "</td><td><a href=\"/report?id=" << r.id
        << "\">查看</a> · <a href=\"/download?id=" << r.id
        << "\">JSON</a></td></tr>";
    b << "</table><h2>添加管理员</h2><form method=post action=/admin><input "
         "type=hidden name=csrf value=\""
      << s.csrf
      << "\"><input name=user placeholder=\"用户名\" required><input "
         "name=password type=password placeholder=\"至少15位强密码\" "
         "required><button>添加</button></form>";
    return Page("报告管理", b.str());
  }
  bool CheckUpload(const HTTP_REQUEST &r, const std::vector<BYTE> &body,
                   std::string &reason) {
    std::string stamp = Header(r, "X-SR-Timestamp"),
                nonce = Header(r, "X-SR-Nonce"),
                signature = Header(r, "X-SR-Signature");
    if (stamp.empty() || nonce.size() < 16 || signature.size() != 64) {
      reason = "missing-or-invalid-headers";
      return false;
    }
    long long remote = 0;
    try {
      remote = std::stoll(stamp);
    } catch (...) {
      reason = "invalid-timestamp";
      return false;
    }
    long long now = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    if (llabs(now - remote) > 300) {
      reason = "timestamp-outside-window";
      return false;
    }
    if (!FreshNonce(nonce)) {
      reason = "replayed-nonce";
      return false;
    }
    std::string bodyHash = Sha256(body);
    std::string signedText = stamp + "\n" + nonce + "\n" + bodyHash;
    std::vector<BYTE> input(signedText.begin(), signedText.end());
    if (!ConstantEqual(Sha256(input, &uploadKey), signature)) {
      reason = "signature-mismatch";
      return false;
    }
    reason = "ok";
    return true;
  }
  void Handle(HTTP_REQUEST &r) {
    std::wstring path = HttpUrlPart(r.CookedUrl.pAbsPath,
                                    r.CookedUrl.AbsPathLength);
    if (path.empty())
      path = L"/";
    std::string method(r.pUnknownVerb ? r.pUnknownVerb : "",
                       r.pUnknownVerb ? r.UnknownVerbLength : 0);
    if (method.empty()) {
      if (r.Verb == HttpVerbGET)
        method = "GET";
      else if (r.Verb == HttpVerbPOST)
        method = "POST";
    }
    std::string client = ClientAddress(r);
    if (path == L"/health" && method == "GET") {
      Respond(r.RequestId, 200, "{\"status\":\"ok\"}", "application/json");
      return;
    }
    if (path == L"/upload" && method == "POST") {
      auto body = Body(r);
      std::string reason;
      if (!CheckUpload(r, body, reason)) {
        Respond(r.RequestId, 403,
                "{\"error\":\"authentication failed\",\"reason\":\"" +
                    reason + "\"}",
                "application/json");
        return;
      }
      auto envelope = Decode(body);
      if (envelope.ip.empty() || envelope.ip == "UNKNOWN")
        envelope.ip = client.empty() ? "UNKNOWN" : client;
      auto id = reports.Save(envelope);
      Respond(r.RequestId, 201, "{\"stored\":true,\"id\":\"" + id + "\"}",
              "application/json");
      return;
    }
    if (users.Count() == 0) {
      if (path == L"/setup" && method == "POST" && IsLoopback(client)) {
        auto form = Form(Body(r));
        std::string error =
            PasswordError(form["password"], form["user"], Utf8(options.host));
        if (!ValidUser(form["user"]))
          error = "用户名长度应为3至64个字符，且不能包含控制字符、冒号或斜杠";
        if (error.empty() && !users.Contains(form["user"])) {
          users.Add(form["user"], form["password"]);
          Respond(r.RequestId, 302, "", "text/plain", "Location: /");
        } else
          Respond(r.RequestId, 400,
                  Page("初始化失败", "<h1>初始化失败</h1><p class=bad>" +
                                         error +
                                         "</p><a href=/setup>返回</a>"));
        return;
      }
      if (path == L"/setup" && method == "GET" && IsLoopback(client)) {
        Respond(r.RequestId, 200,
                Page("首次设置",
                     "<h1>创建首位管理员</h1><p "
                     "class=note>"
                     "此页面仅能从服务器本机访问。密码至少15位，且不能使用常见"
                     "弱口令。</p><form method=post><input name=user "
                     "placeholder=\"管理员用户名\" required><input "
                     "type=password name=password placeholder=\"强密码\" "
                     "required><button>创建</button></form>"));
        return;
      }
      Respond(r.RequestId, 403,
              Page("尚未初始化", "<h1>服务尚未初始化</h1><p>请在服务器本机打开 "
                                 "<code>https://127.0.0.1:" +
                                     std::to_string(options.port) +
                                     "/setup</code> 创建首位管理员。</p>"));
      return;
    }
    if (path == L"/login" && method == "POST") {
      if (Limited(client, false)) {
        Respond(
            r.RequestId, 429,
            Page("暂时锁定", "<h1>登录尝试过多</h1><p>请15分钟后重试。</p>"));
        return;
      }
      auto form = Form(Body(r));
      if (!users.Verify(form["user"], form["password"])) {
        Limited(client, true);
        Respond(r.RequestId, 401,
                Page("登录失败",
                     "<h1>登录失败</h1><p class=bad>用户名或密码错误。</p><a "
                     "href=/login>返回</a>"));
        return;
      }
      std::string token = RandomHex(32);
      {
        std::lock_guard<std::mutex> g(stateLock);
        sessions[token] = {form["user"], RandomHex(24),
                           std::chrono::steady_clock::now() +
                               std::chrono::hours(8)};
      }
      Respond(r.RequestId, 302, "", "text/plain",
              "Set-Cookie: SRSESSION=" + token +
                  "; Path=/; Secure; HttpOnly; SameSite=Strict");
      return;
    }
    if (path == L"/login" && method == "GET") {
      Respond(
          r.RequestId, 200,
          Page("管理员登录", "<h1>报告管理登录</h1><form method=post><input "
                             "name=user placeholder=\"用户名\" required><input "
                             "type=password name=password placeholder=\"密码\" "
                             "required><button>登录</button></form>"));
      return;
    }
    std::string token;
    Session *authenticated = Auth(r, token);
    if (!authenticated) {
      Respond(r.RequestId, 302, "", "text/plain", "Location: /login");
      return;
    }
    Session session = *authenticated;
    if (path == L"/logout") {
      std::lock_guard<std::mutex> g(stateLock);
      sessions.erase(token);
      Respond(r.RequestId, 302, "", "text/plain",
              "Set-Cookie: SRSESSION=; Max-Age=0; Path=/; Secure; HttpOnly");
      return;
    }
    if (path == L"/admin" && method == "POST") {
      auto form = Form(Body(r));
      if (!ConstantEqual(form["csrf"], session.csrf)) {
        Respond(r.RequestId, 403, Page("请求无效", "<h1>请求校验失败</h1>"));
        return;
      }
      std::string error =
          PasswordError(form["password"], form["user"], Utf8(options.host));
      if (!ValidUser(form["user"]))
        error = "用户名长度应为3至64个字符，且不能包含控制字符、冒号或斜杠";
      if (users.Contains(form["user"]))
        error = "用户名已存在";
      if (!error.empty()) {
        Respond(r.RequestId, 400,
                Page("添加失败", "<h1>添加管理员失败</h1><p class=bad>" +
                                     error + "</p><a href=/>返回</a>"));
        return;
      }
      users.Add(form["user"], form["password"]);
      Respond(r.RequestId, 302, "", "text/plain", "Location: /");
      return;
    }
    std::string id = QueryValue(
        HttpUrlPart(r.CookedUrl.pQueryString,
                    r.CookedUrl.QueryStringLength),
        "id");
    if ((path == L"/report" || path == L"/download") && method == "GET") {
      auto file = reports.Path(id, path == L"/report" ? L".html" : L".json");
      auto bytes = ReadFileBytes(file, 12 * 1024 * 1024);
      if (file.empty() || bytes.empty()) {
        Respond(r.RequestId, 404, Page("未找到", "<h1>报告不存在</h1>"));
        return;
      }
      Respond(r.RequestId, 200, std::string(bytes.begin(), bytes.end()),
              path == L"/report" ? "text/html; charset=utf-8"
                                 : "application/json; charset=utf-8");
      return;
    }
    if (path == L"/" && method == "GET") {
      Respond(r.RequestId, 200,
              Dashboard(session, QueryValue(r.CookedUrl.pQueryString
                                                ? r.CookedUrl.pQueryString
                                                : L"",
                                            "q")));
      return;
    }
    Respond(r.RequestId, 404, Page("未找到", "<h1>页面不存在</h1>"));
  }

public:
  explicit WebServer(Options o)
      : options(std::move(o)), users(options.data / L"users.db"),
        reports(options.data / L"Reports") {
    fs::create_directories(options.data);
    auto keyText = ReadFileBytes(options.data / L"upload.key", 256);
    std::string keyHex(keyText.begin(), keyText.end());
    keyHex.erase(std::remove_if(keyHex.begin(), keyHex.end(),
                                [](unsigned char c) { return isspace(c); }),
                 keyHex.end());
    if (!Unhex(keyHex, uploadKey) || uploadKey.size() != 32)
      throw std::runtime_error("upload.key is missing or invalid");
  }
  int Run() {
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    if (HttpInitialize(version, HTTP_INITIALIZE_SERVER, nullptr) != NO_ERROR)
      throw std::runtime_error("HttpInitialize");
    if (HttpCreateServerSession(version, &sessionId, 0) != NO_ERROR ||
        HttpCreateUrlGroup(sessionId, &groupId, 0) != NO_ERROR ||
        HttpCreateRequestQueue(version, L"SecurityInspectionReportServer",
                               nullptr, 0, &queue) != NO_ERROR)
      throw std::runtime_error("HTTP server create");
    HTTP_BINDING_INFO binding{};
    binding.Flags.Present = 1;
    binding.RequestQueueHandle = queue;
    if (HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &binding,
                                sizeof(binding)) != NO_ERROR)
      throw std::runtime_error("HTTP queue binding");
    std::wstring prefix = L"https://" + options.host + L":" +
                          std::to_wstring(options.port) + L"/";
    ULONG add = HttpAddUrlToUrlGroup(groupId, prefix.c_str(), 0, 0);
    if (add != NO_ERROR)
      throw std::runtime_error("HTTPS URL binding failed: " +
                               std::to_string(add));
    std::wcout << L"报告服务已启动：" << prefix << L"\n";
    std::vector<BYTE> buffer(64 * 1024);
    HTTP_REQUEST_ID pending = HTTP_NULL_ID;
    for (;;) {
      auto *r = reinterpret_cast<HTTP_REQUEST *>(buffer.data());
      ULONG used = 0;
      ULONG rc = HttpReceiveHttpRequest(queue, pending, 0, r,
                                        static_cast<ULONG>(buffer.size()),
                                        &used, nullptr);
      if (rc == ERROR_MORE_DATA) {
        pending = r->RequestId;
        buffer.resize(used);
        continue;
      }
      if (rc != NO_ERROR)
        if (rc == ERROR_OPERATION_ABORTED)
          return 0;
      if (rc != NO_ERROR)
        throw std::runtime_error("receive failed: " + std::to_string(rc));
      try {
        Handle(*r);
      } catch (const std::length_error &) {
        Respond(r->RequestId, 413, "payload too large", "text/plain");
      } catch (const std::exception &e) {
        Respond(r->RequestId, 400, std::string("request rejected: ") + e.what(),
                "text/plain");
      }
      buffer.resize(64 * 1024);
      pending = HTTP_NULL_ID;
    }
  }
  void Stop() {
    if (queue)
      HttpShutdownRequestQueue(queue);
  }
  ~WebServer() {
    if (groupId)
      HttpCloseUrlGroup(groupId);
    if (sessionId)
      HttpCloseServerSession(sessionId);
    if (queue)
      CloseHandle(queue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);
  }
};

const wchar_t *kServiceName = L"SecurityInspectionReportServer";
GUID kAppId = {0xc77a31f0,
               0x830d,
               0x4e73,
               {0x96, 0x9d, 0x9a, 0x36, 0x75, 0x56, 0x3f, 0xc2}};
void WriteText(const fs::path &path, const std::string &value) {
  fs::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << value;
  if (!out)
    throw std::runtime_error("cannot write configuration");
}
void SecurePath(const fs::path &path, bool directory) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const wchar_t *sddl = directory
                            ? L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                            : L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl, SDDL_REVISION_1, &descriptor, nullptr))
    throw std::runtime_error("create data directory permissions");
  BOOL ok = SetFileSecurityW(
      path.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      descriptor);
  LocalFree(descriptor);
  if (!ok)
    throw std::runtime_error("protect data path permissions");
}
void SecureDataDirectory(const fs::path &root) {
  SecurePath(root, true);
  std::error_code ec;
  for (auto it = fs::recursive_directory_iterator(
           root, fs::directory_options::skip_permission_denied, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec))
    SecurePath(it->path(), it->is_directory(ec));
  if (ec)
    throw std::runtime_error("enumerate data directory permissions");
}
std::wstring ExecutablePath() {
  std::vector<wchar_t> p(32768);
  DWORD n = GetModuleFileNameW(nullptr, p.data(), static_cast<DWORD>(p.size()));
  if (!n || n == p.size())
    throw std::runtime_error("executable path");
  return std::wstring(p.data(), n);
}
PCCERT_CONTEXT EnsureCertificate(std::string &pin) {
  HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                   CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
  if (!store)
    throw std::runtime_error("open machine certificate store");
  PCCERT_CONTEXT cert = CertFindCertificateInStore(
      store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
      CERT_FIND_SUBJECT_STR_W, L"Security Inspection Report Server", nullptr);
  if (!cert) {
    HCRYPTPROV provider = 0;
    const wchar_t *container = L"SecurityInspectionReportServer-Key";
    if (!CryptAcquireContextW(&provider, container, MS_ENH_RSA_AES_PROV_W,
                              PROV_RSA_AES, CRYPT_MACHINE_KEYSET)) {
      if (GetLastError() != NTE_BAD_KEYSET ||
          !CryptAcquireContextW(&provider, container, MS_ENH_RSA_AES_PROV_W,
                                PROV_RSA_AES,
                                CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET)) {
        CertCloseStore(store, 0);
        throw std::runtime_error("create certificate key container");
      }
    }
    HCRYPTKEY key = 0;
    if (!CryptGetUserKey(provider, AT_KEYEXCHANGE, &key) &&
        !CryptGenKey(provider, AT_KEYEXCHANGE, (3072u << 16) | CRYPT_EXPORTABLE,
                     &key)) {
      CryptReleaseContext(provider, 0);
      CertCloseStore(store, 0);
      throw std::runtime_error("create certificate key");
    }
    if (key)
      CryptDestroyKey(key);
    std::wstring subject = L"CN=Security Inspection Report Server";
    DWORD encodedSize = 0;
    CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR,
                   nullptr, nullptr, &encodedSize, nullptr);
    std::vector<BYTE> encoded(encodedSize);
    if (!CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR,
                        nullptr, encoded.data(), &encodedSize, nullptr)) {
      CryptReleaseContext(provider, 0);
      CertCloseStore(store, 0);
      throw std::runtime_error("certificate subject");
    }
    CERT_NAME_BLOB name{encodedSize, encoded.data()};
    CRYPT_KEY_PROV_INFO providerInfo{};
    providerInfo.pwszContainerName = const_cast<wchar_t *>(container);
    providerInfo.pwszProvName = const_cast<wchar_t *>(MS_ENH_RSA_AES_PROV_W);
    providerInfo.dwProvType = PROV_RSA_AES;
    providerInfo.dwFlags = CRYPT_MACHINE_KEYSET;
    providerInfo.dwKeySpec = AT_KEYEXCHANGE;
    SYSTEMTIME start{}, end{};
    GetSystemTime(&start);
    end = start;
    end.wYear = static_cast<WORD>(start.wYear + 10);
    CRYPT_ALGORITHM_IDENTIFIER algorithm{};
    algorithm.pszObjId = const_cast<char *>(szOID_RSA_SHA256RSA);
    cert = CertCreateSelfSignCertificate(provider, &name, 0, &providerInfo,
                                         &algorithm, &start, &end, nullptr);
    CryptReleaseContext(provider, 0);
    if (!cert) {
      CertCloseStore(store, 0);
      throw std::runtime_error("create certificate");
    }
    PCCERT_CONTEXT added = nullptr;
    if (!CertAddCertificateContextToStore(
            store, cert, CERT_STORE_ADD_REPLACE_EXISTING, &added)) {
      CertFreeCertificateContext(cert);
      CertCloseStore(store, 0);
      throw std::runtime_error("store certificate");
    }
    CertFreeCertificateContext(cert);
    cert = added;
  }
  DWORD sha1Size = 0;
  CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, nullptr,
                                    &sha1Size);
  std::vector<BYTE> sha1(sha1Size);
  if (!CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID,
                                         sha1.data(), &sha1Size)) {
    CertFreeCertificateContext(cert);
    CertCloseStore(store, 0);
    throw std::runtime_error("certificate thumbprint");
  }
  std::vector<BYTE> der(cert->pbCertEncoded,
                        cert->pbCertEncoded + cert->cbCertEncoded);
  pin = Sha256(der);
  PCCERT_CONTEXT duplicate = CertDuplicateCertificateContext(cert);
  CertFreeCertificateContext(cert);
  CertCloseStore(store, 0);
  return duplicate;
}
sockaddr_in BindingAddress(USHORT port) {
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = 0;
  return address;
}
void ConfigureHttpSys(const Options &o, PCCERT_CONTEXT cert) {
  HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
  ULONG rc = HttpInitialize(version, HTTP_INITIALIZE_CONFIG, nullptr);
  if (rc != NO_ERROR)
    throw std::runtime_error("initialize HTTP configuration");
  std::wstring prefix = L"https://+:" + std::to_wstring(o.port) + L"/";
  std::wstring sddl = L"D:(A;;GX;;;SY)(A;;GX;;;BA)";
  HTTP_SERVICE_CONFIG_URLACL_SET url{};
  url.KeyDesc.pUrlPrefix = const_cast<wchar_t *>(prefix.c_str());
  url.ParamDesc.pStringSecurityDescriptor = const_cast<wchar_t *>(sddl.c_str());
  HttpDeleteServiceConfiguration(nullptr, HttpServiceConfigUrlAclInfo, &url,
                                 sizeof(url), nullptr);
  rc = HttpSetServiceConfiguration(nullptr, HttpServiceConfigUrlAclInfo, &url,
                                   sizeof(url), nullptr);
  if (rc != NO_ERROR) {
    HttpTerminate(HTTP_INITIALIZE_CONFIG, nullptr);
    throw std::runtime_error("reserve HTTPS URL: " + std::to_string(rc));
  }
  DWORD shaSize = 0;
  CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, nullptr,
                                    &shaSize);
  std::vector<BYTE> sha(shaSize);
  CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, sha.data(),
                                    &shaSize);
  sockaddr_in address = BindingAddress(o.port);
  HTTP_SERVICE_CONFIG_SSL_SET ssl{};
  ssl.KeyDesc.pIpPort = reinterpret_cast<SOCKADDR *>(&address);
  ssl.ParamDesc.SslHashLength = shaSize;
  ssl.ParamDesc.pSslHash = sha.data();
  ssl.ParamDesc.AppId = kAppId;
  ssl.ParamDesc.pSslCertStoreName = const_cast<wchar_t *>(L"MY");
  ssl.ParamDesc.DefaultCertCheckMode = 0;
  ssl.ParamDesc.DefaultFlags = 0;
  HttpDeleteServiceConfiguration(nullptr, HttpServiceConfigSSLCertInfo, &ssl,
                                 sizeof(ssl), nullptr);
  rc = HttpSetServiceConfiguration(nullptr, HttpServiceConfigSSLCertInfo, &ssl,
                                   sizeof(ssl), nullptr);
  HttpTerminate(HTTP_INITIALIZE_CONFIG, nullptr);
  if (rc != NO_ERROR)
    throw std::runtime_error("bind HTTPS certificate: " + std::to_string(rc));
}
void ConfigureFirewall(USHORT port, bool add) {
  HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  INetFwPolicy2 *policy = nullptr;
  HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                                CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                reinterpret_cast<void **>(&policy));
  if (FAILED(hr)) {
    if (SUCCEEDED(initialized))
      CoUninitialize();
    throw std::runtime_error("open Windows Firewall");
  }
  BSTR name = SysAllocString(L"Security Inspection Report Server HTTPS");
  INetFwRules *rules = nullptr;
  policy->get_Rules(&rules);
  if (add) {
    INetFwRule *rule = nullptr;
    CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                     __uuidof(INetFwRule), reinterpret_cast<void **>(&rule));
    std::wstring ports = std::to_wstring(port);
    BSTR portText = SysAllocString(ports.c_str()),
         description =
             SysAllocString(L"允许局域网终端上传安全检查报告并供管理员查看");
    rule->put_Name(name);
    rule->put_Description(description);
    rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
    rule->put_LocalPorts(portText);
    BSTR localSubnet = SysAllocString(L"LocalSubnet");
    rule->put_RemoteAddresses(localSubnet);
    rule->put_Direction(NET_FW_RULE_DIR_IN);
    rule->put_Profiles(NET_FW_PROFILE2_ALL);
    rule->put_Action(NET_FW_ACTION_ALLOW);
    rule->put_Enabled(VARIANT_TRUE);
    rules->Remove(name);
    hr = rules->Add(rule);
    SysFreeString(portText);
    SysFreeString(localSubnet);
    SysFreeString(description);
    rule->Release();
  } else
    hr = rules->Remove(name);
  SysFreeString(name);
  rules->Release();
  policy->Release();
  if (SUCCEEDED(initialized))
    CoUninitialize();
  if (add && FAILED(hr))
    throw std::runtime_error("create firewall rule");
}
void InstallService(const Options &o) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (!manager)
    throw std::runtime_error("open service manager");
  std::wstring command = L"\"" + ExecutablePath() + L"\" /service /data=\"" +
                         o.data.wstring() + L"\" /listen=+ /port=" +
                         std::to_wstring(o.port);
  SC_HANDLE service = CreateServiceW(
      manager, kServiceName, L"终端安全检查报告服务", SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
      command.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr);
  if (!service && GetLastError() == ERROR_SERVICE_EXISTS) {
    service = OpenServiceW(manager, kServiceName, SERVICE_ALL_ACCESS);
    if (service)
      ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                           SERVICE_NO_CHANGE, command.c_str(), nullptr, nullptr,
                           nullptr, nullptr, nullptr, L"终端安全检查报告服务");
  }
  if (!service) {
    CloseServiceHandle(manager);
    throw std::runtime_error("install service");
  }
  SERVICE_DESCRIPTIONW description{
      const_cast<wchar_t *>(L"接收并集中展示终端安全检查报告")};
  ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
  StartServiceW(service, 0, nullptr);
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
}
void RemoveService() {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager)
    return;
  SC_HANDLE service = OpenServiceW(
      manager, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
  if (service) {
    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    DeleteService(service);
    CloseServiceHandle(service);
  }
  CloseServiceHandle(manager);
}
bool IsAdministrator() {
  BOOL member = FALSE;
  SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
  PSID sid = nullptr;
  if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &sid)) {
    CheckTokenMembership(nullptr, sid, &member);
    FreeSid(sid);
  }
  return member == TRUE;
}
int Install(const Options &o) {
  if (!IsAdministrator())
    throw std::runtime_error("安装服务需要管理员权限");
  fs::create_directories(o.data);
  if (!fs::exists(o.data / L"upload.key"))
    WriteText(o.data / L"upload.key", RandomHex(32));
  std::string pin;
  PCCERT_CONTEXT cert = EnsureCertificate(pin);
  ConfigureHttpSys(o, cert);
  CertFreeCertificateContext(cert);
  WriteText(o.data / L"server-cert-sha256.txt", pin);
  SecureDataDirectory(o.data);
  ConfigureFirewall(o.port, true);
  InstallService(o);
  std::wcout << L"安装完成。HTTPS端口：" << o.port
             << L"\n首次设置： https://127.0.0.1:" << o.port
             << L"/setup\n客户端证书指纹已保存到："
             << (o.data / L"server-cert-sha256.txt").wstring() << L"\n";
  return 0;
}
int Uninstall(const Options &o) {
  if (!IsAdministrator())
    throw std::runtime_error("卸载服务需要管理员权限");
  RemoveService();
  ConfigureFirewall(o.port, false);
  std::wcout << L"服务和防火墙规则已移除；报告与账号数据未删除。\n";
  return 0;
}

SERVICE_STATUS_HANDLE gStatusHandle = nullptr;
SERVICE_STATUS gStatus{};
std::unique_ptr<WebServer> gServer;
Options gServiceOptions;
void WINAPI ServiceControl(DWORD control) {
  if (control == SERVICE_CONTROL_STOP && gStatusHandle) {
    gStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(gStatusHandle, &gStatus);
    if (gServer)
      gServer->Stop();
  }
}
void WINAPI ServiceMain(DWORD, wchar_t **) {
  gStatusHandle = RegisterServiceCtrlHandlerW(kServiceName, ServiceControl);
  if (!gStatusHandle)
    return;
  gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  gStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  gStatus.dwCurrentState = SERVICE_START_PENDING;
  SetServiceStatus(gStatusHandle, &gStatus);
  try {
    gServer = std::make_unique<WebServer>(gServiceOptions);
    gStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(gStatusHandle, &gStatus);
    gServer->Run();
  } catch (...) {
    gStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    gStatus.dwServiceSpecificExitCode = 1;
  }
  gStatus.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(gStatusHandle, &gStatus);
}

int SelfTest(const Options &o) {
  try {
    wchar_t cookedBuffer[] = L"/report?id=unrelated-data";
    if (HttpUrlPart(cookedBuffer,
                    static_cast<USHORT>(7 * sizeof(wchar_t))) != L"/report")
      throw std::runtime_error("HTTP cooked URL length handling");
    fs::create_directories(o.data);
    if (PasswordError("123456789012345", "admin", "127.0.0.1").empty())
      throw std::runtime_error("weak accepted");
    if (PasswordError("onlylowercaseletters", "admin", "127.0.0.1").empty())
      throw std::runtime_error("single-class password accepted");
    std::string strong = "Rain-over-long-corridor-2026-Reports";
    if (!PasswordError(strong, "admin", "127.0.0.1").empty())
      throw std::runtime_error("strong rejected");
    if (!ValidUser("auditor") || ValidUser("bad\tuser"))
      throw std::runtime_error("user name validation");
    Users users(o.data / L"users.db");
    users.Add("auditor", strong);
    users.Add("auditor2", "Another-Long-Report-Password-2026!");
    if (!users.Verify("auditor", strong) || users.Verify("auditor", "wrong"))
      throw std::runtime_error("password verify");
    Users reloaded(o.data / L"users.db");
    if (reloaded.Count() != 2 ||
        !reloaded.Verify("auditor2", "Another-Long-Report-Password-2026!"))
      throw std::runtime_error("multiple administrator persistence");
    Reports reports(o.data / L"Reports");
    Envelope e{"TEST-PC",
               "192.0.2.10",
               "00-11-22-33-44-55",
               "2026-09-09 19:00:00",
               "2",
               "1",
               "1",
               "<!doctype html><html><body>test report</body></html>",
               "{}"};
    auto encoded = Encode(e);
    auto decoded = Decode(encoded);
    bool rejected = false;
    try {
      Decode(std::vector<BYTE>{'S', 'R', 'R', '1', 20, 0, 0, 0});
    } catch (...) {
      rejected = true;
    }
    if (!rejected)
      throw std::runtime_error("truncated envelope accepted");
    std::vector<BYTE> key(32, 0x5a), message{'a', 'u', 'd', 'i', 't'};
    if (Sha256(message, &key) != Sha256(message, &key) ||
        Sha256(message, &key) == Sha256(message))
      throw std::runtime_error("HMAC validation");
    auto id = reports.Save(decoded);
    if (reports.List("TEST-PC").size() != 1 ||
        reports.Path(id, L".html").empty())
      throw std::runtime_error("report store");
    std::cout << "PASS: password policy, PBKDF2, envelope, report storage and "
                 "query\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
} // namespace

int wmain(int argc, wchar_t **argv) {
  try {
    Options options = Parse(argc, argv);
    if (options.selfTest)
      return SelfTest(options);
    if (options.install)
      return Install(options);
    if (options.uninstall)
      return Uninstall(options);
    if (options.service) {
      gServiceOptions = options;
      SERVICE_TABLE_ENTRYW table[] = {
          {const_cast<wchar_t *>(kServiceName), ServiceMain},
          {nullptr, nullptr}};
      if (!StartServiceCtrlDispatcherW(table))
        throw std::runtime_error("start service dispatcher");
      return 0;
    }
    if (options.console)
      return WebServer(options).Run();
    std::wcout << L"终端安全检查报告服务\n\n"
               << L"安装：report-server.exe /install /port=8443\n"
               << L"控制台运行：report-server.exe /console /port=8443\n"
               << L"卸载：report-server.exe /uninstall /port=8443\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 2;
  }
}
