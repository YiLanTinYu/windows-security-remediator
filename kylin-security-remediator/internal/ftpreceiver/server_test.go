package ftpreceiver_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/ftpclient"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/ftpreceiver"
)

func TestServerReceivesReportFromPassiveClient(t *testing.T) {
	uploadDir := t.TempDir()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := ftpreceiver.New(ftpreceiver.Config{
		Username: "report-uploader", Password: "Strong-Test-Password-2026!",
		UploadDir: uploadDir, PassiveIP: "127.0.0.1", MaxFileSize: 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()

	client := ftpclient.New(ftpclient.Config{
		Address: listener.Addr().String(), Username: "report-uploader", Password: "Strong-Test-Password-2026!",
		Timeout: 2 * time.Second, Attempts: 1,
	})
	localReport := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(localReport, []byte("synthetic report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.UploadFile(context.Background(), localReport, "kylin-report_192.0.2.10_test.json"); err != nil {
		t.Fatalf("UploadFile() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(uploadDir, "kylin-report_192.0.2.10_test.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "synthetic report" {
		t.Fatalf("received contents = %q", data)
	}
	cancel()
	listener.Close()
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop")
	}
}

func TestServerRequiresDeclaredFileSizeBeforeUpload(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := ftpreceiver.New(ftpreceiver.Config{
		Username: "report-uploader", Password: "Strong-Test-Password-2026!",
		UploadDir: t.TempDir(), PassiveIP: "127.0.0.1", MaxFileSize: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx, listener) }()

	control, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	reader := textproto.NewReader(bufio.NewReader(control))
	writer := bufio.NewWriter(control)
	if _, _, err := reader.ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		command string
		code    int
	}{
		{"USER report-uploader", 331},
		{"PASS Strong-Test-Password-2026!", 230},
		{"STOR undeclared.json", 503},
	} {
		_, _ = writer.WriteString(step.command + "\r\n")
		_ = writer.Flush()
		if _, _, err := reader.ReadResponse(step.code); err != nil {
			t.Fatalf("%s: %v", step.command, err)
		}
	}
}

func TestServerRejectsWrongPasswordWithoutCreatingReportOrEchoingSecret(t *testing.T) {
	uploadDir := t.TempDir()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := ftpreceiver.New(ftpreceiver.Config{
		Username: "report-uploader", Password: "Strong-Test-Password-2026!",
		UploadDir: uploadDir, PassiveIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx, listener) }()
	wrongPassword := "Wrong-Secret-Password-2026!"
	client := ftpclient.New(ftpclient.Config{
		Address: listener.Addr().String(), Username: "report-uploader", Password: wrongPassword,
		Timeout: 2 * time.Second, Attempts: 1,
	})
	uploadErr := client.Upload(context.Background(), "kylin-report_test.json", strings.NewReader("synthetic report"))
	if uploadErr == nil {
		t.Fatal("Upload() error = nil, want authentication failure")
	}
	if strings.Contains(uploadErr.Error(), wrongPassword) {
		t.Fatalf("error exposed password: %v", uploadErr)
	}
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("files created after rejected login: %#v", entries)
	}
}

func TestServerRejectsPasswordContainingFTPCommandDelimiter(t *testing.T) {
	config := ftpreceiver.Config{
		Username:  "report-uploader",
		Password:  "Strong-Test\r\nPassword-2026!",
		UploadDir: t.TempDir(),
		PassiveIP: "127.0.0.1",
	}

	if err := ftpreceiver.Validate(config); err == nil {
		t.Fatal("Validate() error = nil, want password delimiter rejection")
	}
}

func TestServerDoesNotPublishUploadShorterThanDeclaredSize(t *testing.T) {
	assertRejectedRawUpload(t, 100, strings.Repeat("0", 64), "short", "interrupted.json")
}

func TestServerDoesNotPublishUploadWithWrongChecksum(t *testing.T) {
	assertRejectedRawUpload(t, 5, strings.Repeat("0", 64), "short", "corrupted.json")
}

func TestServerTimesOutStalledDataUploadWithoutPublishingReport(t *testing.T) {
	uploadDir := t.TempDir()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := ftpreceiver.New(ftpreceiver.Config{
		Username: "report-uploader", Password: "Strong-Test-Password-2026!",
		UploadDir: uploadDir, PassiveIP: "127.0.0.1", MaxFileSize: 1024,
		TransferTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx, listener) }()

	control, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(2 * time.Second))
	reader := textproto.NewReader(bufio.NewReader(control))
	writer := bufio.NewWriter(control)
	command := func(line string, want int) string {
		t.Helper()
		if line != "" {
			_, _ = writer.WriteString(line + "\r\n")
			_ = writer.Flush()
		}
		_, message, err := reader.ReadResponse(want)
		if err != nil {
			t.Fatalf("FTP response %d: %v", want, err)
		}
		return message
	}
	command("", 220)
	command("USER report-uploader", 331)
	command("PASS Strong-Test-Password-2026!", 230)
	command("SITE SHA256 "+strings.Repeat("0", 64), 200)
	command("ALLO 10", 200)
	message := command("PASV", 227)
	var a, b, c, d, high, low int
	if _, err := fmt.Sscanf(message, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", &a, &b, &c, &d, &high, &low); err != nil {
		t.Fatal(err)
	}
	dataConnection, err := net.DialTimeout("tcp", fmt.Sprintf("%d.%d.%d.%d:%d", a, b, c, d, high*256+low), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer dataConnection.Close()
	command("STOR stalled.json", 150)
	command("", 552)
	if _, err := os.Stat(filepath.Join(uploadDir, "stalled.json")); !os.IsNotExist(err) {
		t.Fatalf("stalled report was published, stat error = %v", err)
	}
}

func assertRejectedRawUpload(t *testing.T, declaredSize int64, declaredHash, payload, reportName string) {
	t.Helper()
	uploadDir := t.TempDir()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := ftpreceiver.New(ftpreceiver.Config{
		Username: "report-uploader", Password: "Strong-Test-Password-2026!",
		UploadDir: uploadDir, PassiveIP: "127.0.0.1", MaxFileSize: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx, listener) }()

	control, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	reader := textproto.NewReader(bufio.NewReader(control))
	writer := bufio.NewWriter(control)
	readCode := func(want int) string {
		t.Helper()
		_, message, err := reader.ReadResponse(want)
		if err != nil {
			t.Fatalf("FTP response %d: %v", want, err)
		}
		return message
	}
	send := func(command string, want int) string {
		t.Helper()
		_, _ = writer.WriteString(command + "\r\n")
		_ = writer.Flush()
		return readCode(want)
	}
	readCode(220)
	send("USER report-uploader", 331)
	send("PASS Strong-Test-Password-2026!", 230)
	send("TYPE I", 200)
	send("SITE SHA256 "+declaredHash, 200)
	send(fmt.Sprintf("ALLO %d", declaredSize), 200)
	message := send("PASV", 227)
	var a, b, c, d, high, low int
	if _, err := fmt.Sscanf(message, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", &a, &b, &c, &d, &high, &low); err != nil {
		t.Fatalf("parse PASV response %q: %v", message, err)
	}
	dataConnection, err := net.DialTimeout("tcp", fmt.Sprintf("%d.%d.%d.%d:%d", a, b, c, d, high*256+low), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.WriteString("STOR " + reportName + "\r\n")
	_ = writer.Flush()
	readCode(150)
	_, _ = dataConnection.Write([]byte(payload))
	dataConnection.Close()
	readCode(552)
	if _, err := os.Stat(filepath.Join(uploadDir, reportName)); !os.IsNotExist(err) {
		t.Fatalf("rejected report was published, stat error = %v", err)
	}
}
