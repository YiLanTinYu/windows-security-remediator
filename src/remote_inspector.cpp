#define _WIN32_WINNT 0x0601
#include "audit_core.h"
#include "win7_fs.h"
#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#ifndef SR_UPLOAD_KEY_HEX
#define SR_UPLOAD_KEY_HEX ""
#endif
#ifndef SR_SERVER_CERT_SHA256
#define SR_SERVER_CERT_SHA256 ""
#endif
#ifndef SR_DEFAULT_SERVER
#define SR_DEFAULT_SERVER L"192.0.2.10:8443"
#endif

namespace {
std::wstring ExePath() {
  std::vector<wchar_t> b(32768);
  DWORD n = GetModuleFileNameW(nullptr, b.data(), static_cast<DWORD>(b.size()));
  return std::wstring(b.data(), n);
}
std::wstring ExeDir() {
  return sr::win7fs::Parent(ExePath());
}
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
  if (v.empty()) return {};
  int n=MultiByteToWideChar(CP_UTF8,0,v.data(),static_cast<int>(v.size()),nullptr,0);
  std::wstring o(n,L'\0');
  MultiByteToWideChar(CP_UTF8,0,v.data(),static_cast<int>(v.size()),o.data(),n);
  return o;
}
std::wstring JsonQuote(const std::wstring &v) {
  std::wostringstream o;
  o << L'\"';
  for (wchar_t c : v) {
    if (c == L'\"')
      o << L"\\\"";
    else if (c == L'\\')
      o << L"\\\\";
    else if (c == L'\n')
      o << L"\\n";
    else if (c == L'\r')
      o << L"\\r";
    else if (c == L'\t')
      o << L"\\t";
    else if (c < 32)
      o << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0')
        << static_cast<int>(c) << std::dec;
    else
      o << c;
  }
  return o.str() + L"\"";
}
bool Hex(const std::string &text, std::vector<BYTE> &out) {
  if (text.size() % 2)
    return false;
  out.clear();
  for (size_t i = 0; i < text.size(); i += 2) {
    unsigned value = 0;
    std::istringstream in(text.substr(i, 2));
    in >> std::hex >> value;
    if (!in || value > 255)
      return false;
    out.push_back(static_cast<BYTE>(value));
  }
  return !out.empty();
}
std::string HexText(const BYTE *data, size_t size) {
  std::ostringstream o;
  o << std::hex << std::uppercase << std::setfill('0');
  for (size_t i = 0; i < size; i++)
    o << std::setw(2) << static_cast<unsigned>(data[i]);
  return o.str();
}
bool Hash(const std::vector<BYTE> &input, std::vector<BYTE> &output, bool hmac,
          const std::vector<BYTE> &key = {}) {
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD objectSize = 0, result = 0, hashSize = 0;
  bool ok = false;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) < 0)
    goto done;
  if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<BYTE *>(&objectSize),
                        sizeof(objectSize), &result, 0) < 0)
    goto done;
  if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                        reinterpret_cast<BYTE *>(&hashSize), sizeof(hashSize),
                        &result, 0) < 0)
    goto done;
  {
    std::vector<BYTE> object(objectSize);
    output.resize(hashSize);
    if (BCryptCreateHash(alg, &hash, object.data(), objectSize,
                         hmac ? const_cast<BYTE *>(key.data()) : nullptr,
                         hmac ? static_cast<ULONG>(key.size()) : 0, 0) < 0)
      goto done;
    if (BCryptHashData(hash, const_cast<BYTE *>(input.data()),
                       static_cast<ULONG>(input.size()), 0) < 0)
      goto done;
    if (BCryptFinishHash(hash, output.data(), hashSize, 0) < 0)
      goto done;
    ok = true;
  }
done:
  if (hash)
    BCryptDestroyHash(hash);
  if (alg)
    BCryptCloseAlgorithmProvider(alg, 0);
  return ok;
}
struct Server {
  std::wstring host;
  INTERNET_PORT port = 0;
};
bool ParseServer(const std::wstring &value, Server &server) {
  auto colon = value.rfind(L':');
  if (colon == std::wstring::npos || colon == 0)
    return false;
  server.host = value.substr(0, colon);
  wchar_t *end = nullptr;
  long port = wcstol(value.c_str() + colon + 1, &end, 10);
  if (!end || *end || port < 1 || port > 65535 ||
      server.host.find_first_of(L"/\\?#") != std::wstring::npos)
    return false;
  server.port = static_cast<INTERNET_PORT>(port);
  return true;
}
bool PinMatches(HINTERNET request, const std::string &expected) {
  PCCERT_CONTEXT cert = nullptr;
  DWORD size = sizeof(cert);
  if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert,
                          &size) ||
      !cert)
    return false;
  std::vector<BYTE> bytes(cert->pbCertEncoded,
                          cert->pbCertEncoded + cert->cbCertEncoded),
      digest;
  CertFreeCertificateContext(cert);
  return Hash(bytes, digest, false) &&
         _stricmp(HexText(digest.data(), digest.size()).c_str(),
                  expected.c_str()) == 0;
}
std::wstring Epoch() {
  FILETIME ft{};
  GetSystemTimeAsFileTime(&ft);
  ULARGE_INTEGER u{};
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return std::to_wstring((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}
std::string RandomHex() {
  std::vector<BYTE> b(24);
  BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(b.size()),
                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return HexText(b.data(), b.size());
}
bool Upload(const Server &server, const std::string &keyHex,
            const std::string &certPin, const std::vector<BYTE> &body,
            std::wstring &response, std::wstring &failureStage,
            DWORD &failureCode) {
  auto fail = [&](const wchar_t *stage) {
    failureStage = stage;
    failureCode = GetLastError();
  };
  std::vector<BYTE> key, digest, signature;
  if (!Hex(keyHex, key) || certPin.size() != 64 || !Hash(body, digest, false)) {
    fail(L"local-credentials");
    return false;
  }
  std::wstring timestamp = Epoch();
  std::string nonce = RandomHex(),
              bodyHash = HexText(digest.data(), digest.size());
  std::string canonical = Utf8(timestamp) + "\n" + nonce + "\n" + bodyHash;
  if (!Hash(std::vector<BYTE>(canonical.begin(), canonical.end()), signature,
            true, key)) {
    fail(L"local-hmac");
    return false;
  }
  const std::string signatureText = HexText(signature.data(), signature.size());
  std::wstring headers =
      L"Content-Type: application/octet-stream\r\nX-SR-Timestamp: " +
      timestamp + L"\r\nX-SR-Nonce: " +
      std::wstring(nonce.begin(), nonce.end()) + L"\r\nX-SR-Signature: " +
      std::wstring(signatureText.begin(), signatureText.end()) +
      L"\r\n";
  HINTERNET session = WinHttpOpen(
                L"SecurityInspectionReporter/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0),
            connect = nullptr, request = nullptr;
  bool ok = false;
  if (!session) {
    fail(L"open-session");
    goto done;
  }
  {
    // Windows 7 defaults WinHTTP to TLS 1.0. Require TLS 1.2 explicitly so
    // an unpatched endpoint fails safely and keeps its local report instead
    // of silently negotiating an obsolete protocol.
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if (!WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols,
                          sizeof(protocols))) {
      fail(L"tls12-not-supported-or-disabled");
      goto done;
    }
  }
  connect = WinHttpConnect(session, server.host.c_str(), server.port, 0);
  if (!connect) {
    fail(L"connect");
    goto done;
  }
  request = WinHttpOpenRequest(connect, L"POST", L"/upload", nullptr,
                               WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                               WINHTTP_FLAG_SECURE);
  if (!request) {
    fail(L"open-request");
    goto done;
  }
  {
    WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                     WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags,
                     sizeof(flags));
  }
  if (!WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1),
                          WINHTTP_NO_REQUEST_DATA, 0,
                          static_cast<DWORD>(body.size()), 0)) {
    DWORD sendError = GetLastError();
    if (sendError == ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY ||
        sendError == ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED) {
      WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                       WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);
      if (!WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1),
                              WINHTTP_NO_REQUEST_DATA, 0,
                              static_cast<DWORD>(body.size()), 0)) {
        fail(L"send-headers-after-no-client-cert");
        goto done;
      }
    } else {
      fail(L"send-headers");
      goto done;
    }
  }
  if (!PinMatches(request, certPin)) {
    fail(L"certificate-pin");
    goto done;
  }
  {
    DWORD written = 0;
    if (!WinHttpWriteData(request, body.data(), static_cast<DWORD>(body.size()),
                          &written) ||
        written != body.size()) {
      fail(L"write-body");
      goto done;
    }
  }
  if (!WinHttpReceiveResponse(request, nullptr)) {
    fail(L"receive-response");
    goto done;
  }
  {
    DWORD status = 0, size = sizeof(status);
    WinHttpQueryHeaders(
        request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
    std::string bytes;
    for (;;) {
      DWORD available = 0;
      if (!WinHttpQueryDataAvailable(request, &available) || !available)
        break;
      size_t at = bytes.size();
      bytes.resize(at + available);
      DWORD read = 0;
      if (!WinHttpReadData(request, bytes.data() + at, available, &read)) {
        fail(L"read-response");
        goto done;
      }
      bytes.resize(at + read);
    }
    response = Utf16(bytes);
    if (status != 201) {
      failureStage = L"http-status-" + std::to_wstring(status) + L"-" +
                     response;
      failureCode = 0;
      goto done;
    }
    ok = true;
  }
done:
  if (request)
    WinHttpCloseHandle(request);
  if (connect)
    WinHttpCloseHandle(connect);
  if (session)
    WinHttpCloseHandle(session);
  return ok;
}
void Status(const std::wstring &directory, const std::wstring &text) {
  const std::wstring path =
      sr::win7fs::Join(directory, L"upload-status.json");
  std::ofstream out(path.c_str(), std::ios::binary);
  auto bytes = Utf8(text);
  out.write("\xEF\xBB\xBF", 3);
  out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}
void AppendField(std::vector<BYTE> &body, const std::string &value) {
  const uint32_t size = static_cast<uint32_t>(value.size());
  body.push_back(static_cast<BYTE>(size));
  body.push_back(static_cast<BYTE>(size >> 8));
  body.push_back(static_cast<BYTE>(size >> 16));
  body.push_back(static_cast<BYTE>(size >> 24));
  body.insert(body.end(), value.begin(), value.end());
}
std::vector<BYTE> Envelope(const sr::AuditResult &result,
                           const sr::ReportFiles &reports) {
  std::vector<BYTE> body{'S', 'R', 'R', '1'};
  for (const auto &field :
       {Utf8(result.computer), Utf8(result.ip), Utf8(result.mac),
        Utf8(result.finished), std::to_string(result.passed),
        std::to_string(result.failed), std::to_string(result.review),
        Utf8(reports.html), Utf8(reports.json)})
    AppendField(body, field);
  return body;
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
  int argc = 0;
  LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  std::wstring serverValue = SR_DEFAULT_SERVER;
  std::string certPin = SR_SERVER_CERT_SHA256, key = SR_UPLOAD_KEY_HEX;
  bool localOnly = false;
  for (int i = 1; i < argc; i++) {
    std::wstring arg = argv[i];
    if (arg.rfind(L"/server=", 0) == 0)
      serverValue = arg.substr(8);
    else if (arg == L"/local-only")
      localOnly = true;
    else {
      LocalFree(argv);
      return 2;
    }
  }
  LocalFree(argv);
  Server server;
  if (!ParseServer(serverValue, server))
    return 2;
  try {
    auto result = sr::RunAudit();
    auto reports = sr::WriteReports(result, ExeDir());
    if (localOnly) {
      Status(ExeDir(), L"{\"uploaded\":false,\"reason\":\"local-only\"}");
      return result.failed ? 5 : 0;
    }
    std::vector<BYTE> body = Envelope(result, reports);
    std::wstring response;
    std::wstring failureStage;
    DWORD failureCode = 0;
    bool uploaded = false;
    for (int attempt = 0; attempt < 3 && !uploaded; attempt++) {
      uploaded = Upload(server, key, certPin, body, response, failureStage,
                        failureCode);
      if (!uploaded && attempt < 2)
        Sleep(static_cast<DWORD>((attempt + 1) * 2000));
    }
    if (uploaded) {
      Status(ExeDir(), L"{\"uploaded\":true,\"server\":" +
                           JsonQuote(serverValue) + L",\"response\":" +
                           JsonQuote(response) + L"}");
      return result.failed ? 5 : 0;
    }
    Status(ExeDir(), L"{\"uploaded\":false,\"server\":" +
                         JsonQuote(serverValue) +
                         L",\"reason\":\"HTTPS上传失败；本地报告已保留\",\"stage\":" +
                         JsonQuote(failureStage) + L",\"win32\":" +
                         std::to_wstring(failureCode) + L"}");
    return result.failed ? 7 : 6;
  } catch (const std::exception &e) {
    Status(ExeDir(), L"{\"uploaded\":false,\"reason\":"+JsonQuote(Utf16(e.what()))+L"}");
    return 1;
  }
}
