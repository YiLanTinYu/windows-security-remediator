#include "scan_compatibility.h"
#include <iostream>

namespace {
sr::ScanCompatibilityEvidence CompleteEvidence() {
  sr::ScanCompatibilityEvidence evidence;
  evidence.servicesReadable = true;
  evidence.listenersReadable = true;
  evidence.firewallReadable = true;
  evidence.sharesReadable = true;
  return evidence;
}

bool Require(bool condition, const wchar_t *message) {
  if (!condition) std::wcerr << message << L'\n';
  return condition;
}
}

int wmain() {
  {
    const auto result = sr::AssessScanCompatibility(CompleteEvidence());
    if (!Require(!result.ftpDetected && !result.review &&
                     !result.preserveDisabledFirewallProfiles,
                 L"no-FTP system should keep the existing firewall behavior"))
      return 1;
  }
  {
    auto evidence = CompleteEvidence();
    evidence.services.push_back(
        {L"FTPSVC", L"Microsoft FTP Service", L"C:\\Windows\\System32\\svchost.exe",
         true, 42});
    evidence.listeners.push_back({21, 42});
    evidence.firewallAllows.push_back(
        {L"Scanner FTP control", L"21", L"192.168.10.0/24", 7});
    evidence.firewallAllows.push_back(
        {L"Scanner FTP passive", L"50000-50100", L"192.168.10.0/24", 7});
    const auto result = sr::AssessScanCompatibility(evidence);
    if (!Require(result.ftpDetected && result.ftpProtected && !result.review &&
                     !result.preserveDisabledFirewallProfiles,
                 L"precisely allowed FTP service should permit firewall enablement"))
      return 1;
  }
  {
    auto evidence = CompleteEvidence();
    evidence.services.push_back(
        {L"FTPSVC", L"Microsoft FTP Service", L"C:\\Windows\\System32\\svchost.exe",
         true, 43});
    evidence.listeners.push_back({21, 43});
    evidence.firewallAllows.push_back(
        {L"Scanner FTP control", L"21", L"192.168.10.0/24", 7});
    evidence.firewallAllows.push_back(
        {L"Unrelated application", L"50000-50100", L"192.168.10.0/24", 7});
    const auto result = sr::AssessScanCompatibility(evidence);
    if (!Require(!result.ftpProtected && result.review &&
                     result.preserveDisabledFirewallProfiles,
                 L"unrelated passive range must not authorize FTP firewall changes"))
      return 1;
  }
  {
    auto evidence = CompleteEvidence();
    evidence.services.push_back(
        {L"FTPSVC", L"Microsoft FTP Service", L"C:\\Windows\\System32\\svchost.exe",
         true, 44});
    evidence.listeners.push_back({21, 44});
    evidence.firewallAllows.push_back(
        {L"Scanner FTP active ports", L"20-21", L"192.168.10.0/24", 7});
    const auto result = sr::AssessScanCompatibility(evidence);
    if (!Require(!result.ftpProtected && result.review &&
                     result.preserveDisabledFirewallProfiles,
                 L"active FTP ports must not be treated as a passive range"))
      return 1;
  }
  {
    auto evidence = CompleteEvidence();
    evidence.services.push_back(
        {L"FileZilla Server", L"FileZilla Server", L"C:\\Program Files\\FileZilla Server\\filezilla-server.exe",
         true, 88});
    evidence.listeners.push_back({2121, 88});
    evidence.firewallAllows.push_back(
        {L"FTP control only", L"2121", L"LocalSubnet", 7});
    const auto result = sr::AssessScanCompatibility(evidence);
    if (!Require(result.ftpDetected && !result.ftpProtected && result.review &&
                     result.preserveDisabledFirewallProfiles,
                 L"incomplete FTP rules must preserve disabled firewall profiles"))
      return 1;
  }
  {
    auto evidence = CompleteEvidence();
    evidence.nonAdministrativeShares.push_back(L"ScannerDrop");
    const auto result = sr::AssessScanCompatibility(evidence);
    if (!Require(result.smbConflict && result.review &&
                     !result.preserveDisabledFirewallProfiles,
                 L"SMB scan share must be reported without changing FTP firewall policy"))
      return 1;
  }
  return 0;
}
