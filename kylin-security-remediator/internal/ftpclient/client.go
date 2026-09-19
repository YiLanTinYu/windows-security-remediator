package ftpclient

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Address  string
	Username string
	Password string
	Timeout  time.Duration
	Attempts int
}

type Client struct{ config Config }

func New(config Config) *Client { return &Client{config: config} }

func (c *Client) UploadFile(ctx context.Context, localPath, remoteName string) error {
	attempts := c.config.Attempts
	if attempts <= 0 || attempts > 3 {
		attempts = 3
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := os.Open(localPath)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return statErr
		}
		hasher := sha256.New()
		if _, hashErr := io.Copy(hasher, file); hashErr != nil {
			file.Close()
			return hashErr
		}
		if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
			file.Close()
			return seekErr
		}
		err = c.upload(ctx, remoteName, file, info.Size(), fmt.Sprintf("%x", hasher.Sum(nil)))
		closeErr := file.Close()
		if err == nil && closeErr == nil {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = closeErr
		}
	}
	return fmt.Errorf("FTP上传尝试%d次仍失败: %w", attempts, lastErr)
}

func (c *Client) Upload(ctx context.Context, remoteName string, source io.Reader) error {
	return c.upload(ctx, remoteName, source, -1, "")
}

func (c *Client) upload(ctx context.Context, remoteName string, source io.Reader, expectedSize int64, expectedHash string) error {
	if c.config.Address == "" || c.config.Username == "" || c.config.Password == "" {
		return errors.New("FTP地址、用户名和密码不能为空")
	}
	if strings.ContainsAny(c.config.Username, "\r\n") || strings.ContainsAny(c.config.Password, "\r\n") {
		return errors.New("FTP凭据不能包含回车或换行")
	}
	if remoteName == "" || remoteName != path.Base(remoteName) || strings.ContainsAny(remoteName, "\r\n") {
		return errors.New("FTP远程文件名无效")
	}
	timeout := c.config.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	control, err := dialer.DialContext(ctx, "tcp", c.config.Address)
	if err != nil {
		return fmt.Errorf("连接FTP服务器: %w", err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(timeout))
	reader := textproto.NewReader(bufio.NewReader(control))
	writer := bufio.NewWriter(control)
	if _, _, err := reader.ReadResponse(220); err != nil {
		return fmt.Errorf("读取FTP欢迎信息: %w", err)
	}
	code, _, err := command(reader, writer, "USER "+c.config.Username)
	if err != nil {
		return err
	}
	if code == 331 {
		if _, _, err := commandExpected(reader, writer, 230, "PASS "+c.config.Password); err != nil {
			return fmt.Errorf("FTP登录失败: %w", err)
		}
	} else if code != 230 {
		return fmt.Errorf("FTP用户名被拒绝，响应码%d", code)
	}
	if _, _, err := commandExpected(reader, writer, 200, "TYPE I"); err != nil {
		return fmt.Errorf("设置FTP二进制模式: %w", err)
	}
	if expectedSize >= 0 {
		if _, _, err := commandExpected(reader, writer, 200, "SITE SHA256 "+expectedHash); err != nil {
			return fmt.Errorf("声明FTP文件校验和: %w", err)
		}
		code, message, err := command(reader, writer, "ALLO "+strconv.FormatInt(expectedSize, 10))
		if err != nil {
			return fmt.Errorf("声明FTP文件大小: %w", err)
		}
		if code != 200 && code != 202 {
			return fmt.Errorf("FTP服务器拒绝文件大小声明，响应码%d：%s", code, message)
		}
	}
	_, passiveMessage, err := commandExpected(reader, writer, 227, "PASV")
	if err != nil {
		return fmt.Errorf("进入FTP被动模式: %w", err)
	}
	passivePort, err := parsePassivePort(passiveMessage)
	if err != nil {
		return err
	}
	remoteAddress := control.RemoteAddr().(*net.TCPAddr)
	dataAddress := net.JoinHostPort(remoteAddress.IP.String(), strconv.Itoa(passivePort))
	dataConnection, err := dialer.DialContext(ctx, "tcp", dataAddress)
	if err != nil {
		return fmt.Errorf("连接FTP被动数据端口: %w", err)
	}
	_ = dataConnection.SetDeadline(time.Now().Add(timeout))
	code, _, err = command(reader, writer, "STOR "+remoteName)
	if err != nil {
		dataConnection.Close()
		return fmt.Errorf("开始FTP上传: %w", err)
	}
	if code != 125 && code != 150 {
		dataConnection.Close()
		return fmt.Errorf("FTP服务器拒绝上传，响应码%d", code)
	}
	if _, err := io.Copy(dataConnection, source); err != nil {
		dataConnection.Close()
		return fmt.Errorf("发送FTP文件内容: %w", err)
	}
	if err := dataConnection.Close(); err != nil {
		return fmt.Errorf("关闭FTP数据连接: %w", err)
	}
	code, message, err := reader.ReadResponse(0)
	if err != nil {
		return fmt.Errorf("读取FTP上传结果: %w", err)
	}
	if code != 226 && code != 250 {
		return fmt.Errorf("FTP上传未完成，响应码%d：%s", code, message)
	}
	_, _, _ = command(reader, writer, "QUIT")
	return nil
}

func command(reader *textproto.Reader, writer *bufio.Writer, line string) (int, string, error) {
	if _, err := writer.WriteString(line + "\r\n"); err != nil {
		return 0, "", err
	}
	if err := writer.Flush(); err != nil {
		return 0, "", err
	}
	return reader.ReadResponse(0)
}

func commandExpected(reader *textproto.Reader, writer *bufio.Writer, expected int, line string) (int, string, error) {
	code, message, err := command(reader, writer, line)
	if err != nil {
		return code, message, err
	}
	if code != expected {
		return code, message, fmt.Errorf("响应码%d：%s", code, message)
	}
	return code, message, nil
}

func parsePassivePort(message string) (int, error) {
	start := strings.LastIndex(message, "(")
	end := strings.LastIndex(message, ")")
	if start < 0 || end <= start {
		return 0, errors.New("FTP被动模式响应格式无效")
	}
	parts := strings.Split(message[start+1:end], ",")
	if len(parts) != 6 {
		return 0, errors.New("FTP被动模式响应格式无效")
	}
	high, err := strconv.Atoi(strings.TrimSpace(parts[4]))
	if err != nil || high < 0 || high > 255 {
		return 0, errors.New("FTP被动数据端口无效")
	}
	low, err := strconv.Atoi(strings.TrimSpace(parts[5]))
	if err != nil || low < 0 || low > 255 {
		return 0, errors.New("FTP被动数据端口无效")
	}
	port := high*256 + low
	if port == 0 {
		return 0, errors.New("FTP被动数据端口无效")
	}
	return port, nil
}
