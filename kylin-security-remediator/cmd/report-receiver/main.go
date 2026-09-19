package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/ftpreceiver"
)

type options struct {
	listen string
	server ftpreceiver.Config
}

func parseOptions(args []string) (options, error) {
	flags := flag.NewFlagSet("report-receiver", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", "", "FTP控制连接监听地址")
	passiveIP := flags.String("passive-ip", "", "客户端可访问的PASV IPv4地址")
	passiveStart := flags.Int("passive-start", 0, "PASV起始端口")
	passiveEnd := flags.Int("passive-end", 0, "PASV结束端口")
	uploadDir := flags.String("upload-dir", "", "报告保存目录")
	username := flags.String("user", "", "仅上传账号")
	password := flags.String("password", "", "强密码")
	passwordEnv := flags.String("password-env", "", "从指定环境变量读取强密码")
	maxFileSizeMB := flags.Int64("max-file-size-mb", 50, "单个报告最大MB")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 || *listen == "" {
		return options{}, errors.New("必须提供完整的接收服务参数")
	}
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		return options{}, errors.New("监听地址格式无效")
	}
	if *passiveStart == 0 || *passiveEnd == 0 || *maxFileSizeMB <= 0 {
		return options{}, errors.New("必须提供有效的PASV端口范围和文件大小")
	}
	if *password != "" && *passwordEnv != "" {
		return options{}, errors.New("密码参数和密码环境变量不能同时使用")
	}
	resolvedPassword := *password
	if *passwordEnv != "" {
		resolvedPassword = os.Getenv(*passwordEnv)
		if resolvedPassword == "" {
			return options{}, errors.New("指定的密码环境变量不存在或为空")
		}
	}
	result := options{
		listen: *listen,
		server: ftpreceiver.Config{
			Username: *username, Password: resolvedPassword, UploadDir: *uploadDir,
			PassiveIP: *passiveIP, PassiveStart: *passiveStart, PassiveEnd: *passiveEnd,
			MaxFileSize: *maxFileSizeMB * 1024 * 1024,
		},
	}
	if err := ftpreceiver.Validate(result.server); err != nil {
		return options{}, err
	}
	return result, nil
}

func main() {
	options, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	server, err := ftpreceiver.New(options.server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	listener, err := net.Listen("tcp4", options.listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Serve(ctx, listener); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
