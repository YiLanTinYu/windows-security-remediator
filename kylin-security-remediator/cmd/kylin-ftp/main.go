package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/app"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/ftpclient"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/program"
)

type options struct {
	upload  bool
	ftp     ftpclient.Config
	appArgs []string
}

func parseOptions(args []string) (options, error) {
	flags := flag.NewFlagSet("kylin-ftp", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	host := flags.String("ftp-host", "", "FTP服务器地址")
	port := flags.Int("ftp-port", 0, "FTP控制端口，省略时使用21")
	username := flags.String("ftp-user", "", "FTP用户名")
	password := flags.String("ftp-password", "", "FTP密码")
	output := flags.String("output", ".", "本地报告保存目录")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("存在无法识别的参数")
	}
	configured := *host != "" || *port != 0 || *username != "" || *password != ""
	result := options{appArgs: []string{"--repair", "--output", *output}}
	if !configured {
		return result, nil
	}
	if *host == "" || *username == "" || *password == "" {
		return options{}, errors.New("FTP地址、用户名和密码必须同时提供")
	}
	if *port == 0 {
		*port = 21
	}
	if *port < 1 || *port > 65535 {
		return options{}, errors.New("FTP端口必须在1到65535之间")
	}
	result.upload = true
	result.ftp = ftpclient.Config{
		Address: net.JoinHostPort(*host, strconv.Itoa(*port)), Username: *username, Password: *password,
		Timeout: 15 * time.Second, Attempts: 3,
	}
	return result, nil
}

func main() {
	fmt.Fprintln(os.Stdout, app.CopyrightNotice)
	options, err := parseOptions(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	engine := program.NewFullEngine()
	if options.upload {
		uploader := ftpclient.New(options.ftp)
		os.Exit(app.RunWithUploader(context.Background(), options.appArgs, engine, time.Now, uploader))
	}
	os.Exit(app.Run(context.Background(), options.appArgs, engine, time.Now))
}
