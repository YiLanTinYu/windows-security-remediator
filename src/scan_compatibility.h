#pragma once
#include <string>
#include <vector>

namespace sr {
struct ScanServiceEvidence {
  std::wstring name;
  std::wstring displayName;
  std::wstring binaryPath;
  bool running = false;
  unsigned long processId = 0;
};

struct TcpListenerEvidence {
  unsigned short port = 0;
  unsigned long processId = 0;
};

struct FirewallAllowEvidence {
  std::wstring name;
  std::wstring localPorts;
  std::wstring remoteAddresses;
  long profiles = 0;
};

struct ScanCompatibilityEvidence {
  bool servicesReadable = false;
  bool listenersReadable = false;
  bool firewallReadable = false;
  bool sharesReadable = false;
  std::vector<ScanServiceEvidence> services;
  std::vector<TcpListenerEvidence> listeners;
  std::vector<FirewallAllowEvidence> firewallAllows;
  std::vector<std::wstring> nonAdministrativeShares;
};

struct ScanCompatibilityDetail {
  std::wstring category;
  std::wstring name;
  std::wstring value;
  std::wstring conclusion;
};

struct ScanCompatibilityAssessment {
  bool ftpDetected = false;
  bool ftpProtected = false;
  bool smbConflict = false;
  bool review = false;
  bool preserveDisabledFirewallProfiles = false;
  std::wstring actual;
  std::vector<ScanCompatibilityDetail> details;
};

ScanCompatibilityAssessment AssessScanCompatibility(
    const ScanCompatibilityEvidence &evidence);
ScanCompatibilityEvidence CollectScanCompatibilityEvidence();
ScanCompatibilityAssessment InspectScanCompatibility();
}
