package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/app"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/program"
)

func main() {
	fmt.Fprintln(os.Stdout, app.CopyrightNotice)
	engine := program.NewFullEngine()
	os.Exit(runOnsite(context.Background(), os.Args[1:], os.Stdin, os.Stdout, engine, time.Now))
}

func runOnsite(ctx context.Context, args []string, input io.Reader, output io.Writer, runner app.Runner, now func() time.Time) int {
	effectiveArgs := append([]string(nil), args...)
	if !hasExplicitMode(args) {
		fmt.Fprintln(output, "即将执行终端安全检查。输入 yes 将检查、修复并复检；其他输入只检查：")
		scanner := bufio.NewScanner(input)
		if scanner.Scan() && strings.EqualFold(strings.TrimSpace(scanner.Text()), "yes") {
			effectiveArgs = append(effectiveArgs, "--repair")
		} else {
			effectiveArgs = append(effectiveArgs, "--audit")
		}
	}
	exitCode := app.Run(ctx, effectiveArgs, runner, now)
	if exitCode != 2 {
		directory, err := filepath.Abs(reportDirectory(args))
		if err != nil {
			directory = reportDirectory(args)
		}
		fmt.Fprintf(output, "报告目录：%s\n", filepath.Clean(directory))
	}
	return exitCode
}

func hasExplicitMode(args []string) bool {
	for _, argument := range args {
		name, _, _ := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		if name == "audit" || name == "repair" || name == "clean" {
			return true
		}
	}
	return false
}

func reportDirectory(args []string) string {
	for index, argument := range args {
		name, value, found := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		if name != "output" {
			continue
		}
		if found {
			return value
		}
		if index+1 < len(args) {
			return args[index+1]
		}
	}
	return "."
}
