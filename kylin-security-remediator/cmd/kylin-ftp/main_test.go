package main

import "testing"

func TestParseOptionsBuildsFTPConfigWithoutHardCodedServer(t *testing.T) {
	options, err := parseOptions([]string{
		"--ftp-host", "192.0.2.80", "--ftp-port", "2121",
		"--ftp-user", "synthetic-user", "--ftp-password", "synthetic-password",
		"--output", "/tmp/reports",
	})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if !options.upload || options.ftp.Address != "192.0.2.80:2121" || options.ftp.Username != "synthetic-user" || options.ftp.Password != "synthetic-password" {
		t.Fatalf("FTP options = %#v", options)
	}
	if len(options.appArgs) != 3 || options.appArgs[0] != "--repair" || options.appArgs[1] != "--output" || options.appArgs[2] != "/tmp/reports" {
		t.Fatalf("app args = %#v", options.appArgs)
	}
}

func TestParseOptionsAllowsLocalOnlyButRejectsPartialFTPConfiguration(t *testing.T) {
	options, err := parseOptions([]string{"--output", "/tmp/reports"})
	if err != nil || options.upload {
		t.Fatalf("local-only options = %#v, error = %v", options, err)
	}
	if _, err := parseOptions([]string{"--ftp-host", "192.0.2.80", "--ftp-user", "synthetic-user"}); err == nil {
		t.Fatal("partial FTP configuration error = nil")
	}
}
