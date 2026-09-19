package ftpclient_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/ftpclient"
)

type receivedFile struct {
	name         string
	data         string
	declaredSize int64
	declaredHash string
	err          error
}

func TestClientRejectsCredentialsContainingFTPCommandDelimiterBeforeConnecting(t *testing.T) {
	client := ftpclient.New(ftpclient.Config{
		Address: "127.0.0.1:1", Username: "test-user", Password: "test\r\nNOOP",
		Timeout: time.Second,
	})

	err := client.Upload(context.Background(), "report.json", strings.NewReader("{}"))
	if err == nil || !strings.Contains(err.Error(), "凭据") {
		t.Fatalf("Upload() error = %v, want credential rejection", err)
	}
}

func TestUploadUsesPassiveModeAndPreservesFileContents(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan receivedFile, 1)
	go serveOneUpload(listener, "test-user", "test-password", received)

	client := ftpclient.New(ftpclient.Config{
		Address: listener.Addr().String(), Username: "test-user", Password: "test-password", Timeout: 2 * time.Second,
	})
	err = client.Upload(context.Background(), "report_192.0.2.10.json", strings.NewReader("synthetic report contents"))
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	result := <-received
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.name != "report_192.0.2.10.json" || result.data != "synthetic report contents" {
		t.Fatalf("received = %#v", result)
	}
}

func TestUploadFileRetriesTemporaryConnectionFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan receivedFile, 1)
	go func() {
		first, acceptErr := listener.Accept()
		if acceptErr != nil {
			received <- receivedFile{err: acceptErr}
			return
		}
		_, _ = io.WriteString(first, "421 temporary unavailable\r\n")
		first.Close()
		serveOneUpload(listener, "test-user", "test-password", received)
	}()
	localPath := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(localPath, []byte("retry-safe contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := ftpclient.New(ftpclient.Config{
		Address: listener.Addr().String(), Username: "test-user", Password: "test-password",
		Timeout: 2 * time.Second, Attempts: 2,
	})
	if err := client.UploadFile(context.Background(), localPath, "report.html"); err != nil {
		t.Fatalf("UploadFile() error = %v", err)
	}
	result := <-received
	if result.err != nil || result.name != "report.html" || result.data != "retry-safe contents" {
		t.Fatalf("received = %#v", result)
	}
	if result.declaredSize != int64(len("retry-safe contents")) {
		t.Fatalf("declared size = %d, want %d", result.declaredSize, len("retry-safe contents"))
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte("retry-safe contents")))
	if result.declaredHash != wantHash {
		t.Fatalf("declared hash = %q, want %q", result.declaredHash, wantHash)
	}
}

func TestUploadStopsWhenServerDoesNotSendWelcomeMessage(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			close(accepted)
			return
		}
		close(accepted)
		defer connection.Close()
		time.Sleep(time.Second)
	}()

	client := ftpclient.New(ftpclient.Config{
		Address: listener.Addr().String(), Username: "test-user", Password: "test-password", Timeout: 100 * time.Millisecond,
	})
	started := time.Now()
	err = client.Upload(context.Background(), "report.json", strings.NewReader("synthetic report"))
	if err == nil {
		t.Fatal("Upload() error = nil, want timeout")
	}
	if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
		t.Fatalf("Upload() returned too late: %s", elapsed)
	}
	<-accepted
}

func serveOneUpload(listener net.Listener, username, password string, received chan<- receivedFile) {
	connection, err := listener.Accept()
	if err != nil {
		received <- receivedFile{err: err}
		return
	}
	defer connection.Close()
	writer := bufio.NewWriter(connection)
	reader := bufio.NewScanner(connection)
	writeReply := func(code int, message string) {
		_, _ = fmt.Fprintf(writer, "%d %s\r\n", code, message)
		_ = writer.Flush()
	}
	writeReply(220, "test server ready")
	var dataListener net.Listener
	var declaredSize int64 = -1
	var declaredHash string
	for reader.Scan() {
		line := reader.Text()
		command, argument, _ := strings.Cut(line, " ")
		switch strings.ToUpper(command) {
		case "USER":
			if argument != username {
				writeReply(530, "invalid user")
				continue
			}
			writeReply(331, "password required")
		case "PASS":
			if argument != password {
				writeReply(530, "invalid password")
				continue
			}
			writeReply(230, "logged in")
		case "TYPE":
			writeReply(200, "binary mode")
		case "ALLO":
			if _, scanErr := fmt.Sscan(argument, &declaredSize); scanErr != nil || declaredSize < 0 {
				writeReply(501, "invalid size")
				continue
			}
			writeReply(200, "size accepted")
		case "SITE":
			algorithm, value, found := strings.Cut(argument, " ")
			if !found || !strings.EqualFold(algorithm, "SHA256") || len(value) != 64 {
				writeReply(501, "invalid checksum")
				continue
			}
			declaredHash = strings.ToLower(value)
			writeReply(200, "checksum accepted")
		case "PASV":
			dataListener, err = net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				received <- receivedFileForTest("", "", err)
				return
			}
			port := dataListener.Addr().(*net.TCPAddr).Port
			writeReply(227, fmt.Sprintf("Entering Passive Mode (127,0,0,1,%d,%d)", port/256, port%256))
		case "STOR":
			if dataListener == nil {
				writeReply(425, "use PASV first")
				continue
			}
			writeReply(150, "opening data connection")
			dataConnection, acceptErr := dataListener.Accept()
			if acceptErr != nil {
				received <- receivedFileForTest("", "", acceptErr)
				return
			}
			data, readErr := io.ReadAll(dataConnection)
			dataConnection.Close()
			dataListener.Close()
			writeReply(226, "transfer complete")
			received <- receivedFile{name: argument, data: string(data), declaredSize: declaredSize, declaredHash: declaredHash, err: readErr}
		case "QUIT":
			writeReply(221, "goodbye")
			return
		default:
			writeReply(500, "unsupported command")
		}
	}
}

func receivedFileForTest(name, data string, err error) receivedFile {
	return receivedFile{name: name, data: data, err: err}
}
