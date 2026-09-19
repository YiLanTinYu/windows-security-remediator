package main

import "testing"

func TestParseOptionsRequiresExplicitReceiverConfiguration(t *testing.T) {
	options, err := parseOptions([]string{
		"--listen", "0.0.0.0:2121", "--passive-ip", "192.0.2.90",
		"--passive-start", "30000", "--passive-end", "30009",
		"--upload-dir", `C:\reports`, "--user", "report-uploader",
		"--password", "Strong-Test-Password-2026!",
	})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if options.listen != "0.0.0.0:2121" || options.server.PassiveIP != "192.0.2.90" || options.server.PassiveStart != 30000 || options.server.PassiveEnd != 30009 {
		t.Fatalf("options = %#v", options)
	}
	if options.server.UploadDir != `C:\reports` || options.server.Username != "report-uploader" {
		t.Fatalf("server options = %#v", options.server)
	}
}

func TestParseOptionsRejectsMissingAndWeakCredentials(t *testing.T) {
	if _, err := parseOptions(nil); err == nil {
		t.Fatal("missing configuration error = nil")
	}
	if _, err := parseOptions([]string{
		"--listen", "127.0.0.1:2121", "--passive-ip", "127.0.0.1",
		"--passive-start", "30000", "--passive-end", "30009",
		"--upload-dir", `C:\reports`, "--user", "admin", "--password", "123456",
	}); err == nil {
		t.Fatal("weak password error = nil")
	}
}

func TestParseOptionsReadsPasswordFromNamedEnvironmentVariable(t *testing.T) {
	t.Setenv("KYLIN_REPORT_FTP_PASSWORD", "Strong-Test-Password-2026!")
	options, err := parseOptions([]string{
		"--listen", "0.0.0.0:2121", "--passive-ip", "192.0.2.90",
		"--passive-start", "30000", "--passive-end", "30009",
		"--upload-dir", `C:\reports`, "--user", "report-uploader",
		"--password-env", "KYLIN_REPORT_FTP_PASSWORD",
	})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if options.server.Password != "Strong-Test-Password-2026!" {
		t.Fatal("password was not loaded from the named environment variable")
	}
}
