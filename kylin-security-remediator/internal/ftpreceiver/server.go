package ftpreceiver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Config struct {
	Username        string
	Password        string
	UploadDir       string
	PassiveIP       string
	PassiveStart    int
	PassiveEnd      int
	MaxFileSize     int64
	TransferTimeout time.Duration
}

type Server struct{ config Config }

func New(config Config) (*Server, error) {
	if err := Validate(config); err != nil {
		return nil, err
	}
	if config.MaxFileSize <= 0 {
		config.MaxFileSize = 50 * 1024 * 1024
	}
	if config.TransferTimeout <= 0 {
		config.TransferTimeout = 2 * time.Minute
	}
	if err := os.MkdirAll(config.UploadDir, 0o750); err != nil {
		return nil, err
	}
	return &Server{config: config}, nil
}

func Validate(config Config) error {
	if config.Username == "" || strings.ContainsAny(config.Username, "\r\n") {
		return errors.New("FTP用户名无效")
	}
	if strings.ContainsAny(config.Password, "\r\n") {
		return errors.New("FTP密码不能包含回车或换行")
	}
	if !strongPassword(config.Password) {
		return errors.New("FTP密码必须至少15位，并包含大小写字母、数字和特殊字符")
	}
	ip := net.ParseIP(config.PassiveIP)
	if ip == nil || ip.To4() == nil {
		return errors.New("PASV地址必须是IPv4地址")
	}
	if config.UploadDir == "" {
		return errors.New("上传目录不能为空")
	}
	if (config.PassiveStart == 0) != (config.PassiveEnd == 0) || config.PassiveStart < 0 || config.PassiveEnd < config.PassiveStart || config.PassiveEnd > 65535 {
		return errors.New("PASV端口范围无效")
	}
	return nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleSession(ctx, connection)
	}
}

func (s *Server) handleSession(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))
	reader := bufio.NewScanner(connection)
	writer := bufio.NewWriter(connection)
	reply := func(code int, message string) {
		_, _ = fmt.Fprintf(writer, "%d %s\r\n", code, message)
		_ = writer.Flush()
	}
	reply(220, "report receiver ready")
	var suppliedUser string
	loggedIn := false
	expectedSize := int64(-1)
	var expectedHash string
	var passive net.Listener
	defer func() {
		if passive != nil {
			passive.Close()
		}
	}()
	for reader.Scan() {
		if ctx.Err() != nil {
			return
		}
		command, argument, _ := strings.Cut(reader.Text(), " ")
		switch strings.ToUpper(command) {
		case "USER":
			suppliedUser = argument
			loggedIn = false
			reply(331, "password required")
		case "PASS":
			userOK := subtle.ConstantTimeCompare([]byte(suppliedUser), []byte(s.config.Username)) == 1
			passwordOK := subtle.ConstantTimeCompare([]byte(argument), []byte(s.config.Password)) == 1
			loggedIn = userOK && passwordOK
			if loggedIn {
				reply(230, "logged in")
			} else {
				reply(530, "login incorrect")
			}
		case "TYPE":
			if !loggedIn {
				reply(530, "not logged in")
			} else {
				reply(200, "binary mode")
			}
		case "ALLO":
			if !loggedIn {
				reply(530, "not logged in")
				continue
			}
			size, err := strconv.ParseInt(strings.TrimSpace(argument), 10, 64)
			if err != nil || size < 0 {
				reply(501, "invalid size")
				continue
			}
			if size > s.config.MaxFileSize {
				reply(552, "file too large")
				continue
			}
			expectedSize = size
			reply(200, "size accepted")
		case "SITE":
			if !loggedIn {
				reply(530, "not logged in")
				continue
			}
			algorithm, value, found := strings.Cut(strings.TrimSpace(argument), " ")
			decoded, err := hex.DecodeString(value)
			if !found || !strings.EqualFold(algorithm, "SHA256") || err != nil || len(decoded) != sha256.Size {
				reply(501, "invalid checksum")
				continue
			}
			expectedHash = strings.ToLower(value)
			reply(200, "checksum accepted")
		case "PASV":
			if !loggedIn {
				reply(530, "not logged in")
				continue
			}
			if passive != nil {
				passive.Close()
			}
			var err error
			passive, err = s.openPassiveListener()
			if err != nil {
				reply(425, "cannot open passive connection")
				continue
			}
			port := passive.Addr().(*net.TCPAddr).Port
			ip := net.ParseIP(s.config.PassiveIP).To4()
			reply(227, fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip[0], ip[1], ip[2], ip[3], port/256, port%256))
		case "STOR":
			if !loggedIn {
				reply(530, "not logged in")
				continue
			}
			if expectedSize < 0 || expectedHash == "" {
				reply(503, "use SITE SHA256 and ALLO first")
				continue
			}
			if passive == nil {
				reply(425, "use PASV first")
				continue
			}
			if err := validReportName(argument); err != nil {
				reply(553, "invalid report name")
				continue
			}
			reply(150, "opening data connection")
			if tcpListener, ok := passive.(*net.TCPListener); ok {
				_ = tcpListener.SetDeadline(time.Now().Add(s.config.TransferTimeout))
			}
			dataConnection, err := passive.Accept()
			passive.Close()
			passive = nil
			if err != nil {
				reply(425, "data connection failed")
				continue
			}
			_ = dataConnection.SetDeadline(time.Now().Add(s.config.TransferTimeout))
			err = s.receiveFile(argument, dataConnection, expectedSize, expectedHash)
			expectedSize = -1
			expectedHash = ""
			dataConnection.Close()
			if err != nil {
				reply(552, "upload failed")
				continue
			}
			reply(226, "transfer complete")
		case "SYST":
			reply(215, "UNIX Type: L8")
		case "PWD":
			reply(257, `"/"`)
		case "NOOP":
			reply(200, "ok")
		case "RETR", "LIST", "NLST", "DELE", "RNFR", "RNTO", "MKD", "RMD":
			reply(550, "upload only")
		case "QUIT":
			reply(221, "goodbye")
			return
		default:
			reply(502, "command not implemented")
		}
	}
}

func (s *Server) openPassiveListener() (net.Listener, error) {
	if s.config.PassiveStart == 0 {
		return net.Listen("tcp4", net.JoinHostPort(s.config.PassiveIP, "0"))
	}
	for port := s.config.PassiveStart; port <= s.config.PassiveEnd; port++ {
		listener, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", s.config.PassiveIP, port))
		if err == nil {
			return listener, nil
		}
	}
	return nil, errors.New("没有可用的PASV端口")
}

func (s *Server) receiveFile(name string, source io.Reader, expectedSize int64, expectedHash string) error {
	temporary, err := os.CreateTemp(s.config.UploadDir, ".report-upload-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(source, s.config.MaxFileSize+1))
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if written > s.config.MaxFileSize {
		return errors.New("报告超过大小限制")
	}
	if expectedSize >= 0 && written != expectedSize {
		return errors.New("报告实际大小与声明大小不一致")
	}
	if fmt.Sprintf("%x", hasher.Sum(nil)) != expectedHash {
		return errors.New("报告SHA-256与声明值不一致")
	}
	destination := filepath.Join(s.config.UploadDir, name)
	_ = os.Remove(destination)
	return os.Rename(temporaryPath, destination)
}

func validReportName(name string) error {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, "\r\n") {
		return errors.New("报告文件名无效")
	}
	extension := strings.ToLower(filepath.Ext(name))
	if extension != ".html" && extension != ".json" {
		return errors.New("只允许HTML和JSON报告")
	}
	return nil
}

func strongPassword(password string) bool {
	if len([]rune(password)) < 15 {
		return false
	}
	var upper, lower, digit, special bool
	for _, character := range password {
		switch {
		case unicode.IsUpper(character):
			upper = true
		case unicode.IsLower(character):
			lower = true
		case unicode.IsDigit(character):
			digit = true
		default:
			special = true
		}
	}
	return upper && lower && digit && special
}
