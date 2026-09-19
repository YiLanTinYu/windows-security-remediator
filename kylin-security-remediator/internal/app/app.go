package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/report"
)

type Runner interface {
	Run(context.Context, core.Request) (core.Result, error)
}

type ReportUploader interface {
	UploadFile(context.Context, string, string) error
}

const CopyrightNotice = "Copyright (C) 2026 倚栏听雨. All rights reserved."

func Run(ctx context.Context, args []string, runner Runner, now func() time.Time) int {
	return run(ctx, args, runner, now, nil)
}

func RunWithUploader(ctx context.Context, args []string, runner Runner, now func() time.Time, uploader ReportUploader) int {
	return run(ctx, args, runner, now, uploader)
}

func run(ctx context.Context, args []string, runner Runner, now func() time.Time, uploader ReportUploader) int {
	flags := flag.NewFlagSet("kylin-security-remediator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	audit := flags.Bool("audit", false, "只检查，不修改")
	repair := flags.Bool("repair", false, "检查并修复")
	clean := flags.Bool("clean", false, "清理浏览器登录、无线配置和安全可清理的USB用户级记录")
	output := flags.String("output", ".", "报告保存目录")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	selectedModes := 0
	for _, selected := range []bool{*audit, *repair, *clean} {
		if selected {
			selectedModes++
		}
	}
	if selectedModes > 1 {
		return 2
	}
	mode := core.ModeAudit
	if *repair {
		mode = core.ModeRepair
	} else if *clean {
		mode = core.ModeClean
	}
	result, runErr := runner.Run(ctx, core.Request{Mode: mode})
	if runErr != nil {
		result.ExecutionError = runErr.Error()
	}
	if err := os.MkdirAll(*output, 0o750); err != nil {
		return 1
	}
	stamp := now()
	result.GeneratedAt = stamp.Format("2006-01-02 15:04:05")
	timestamp := stamp.Format("20060102-150405") + fmt.Sprintf("-%03d", stamp.Nanosecond()/int(time.Millisecond))
	prefix := "kylin-report_"
	if mode == core.ModeClean {
		prefix = "kylin-cleanup-report_"
	}
	base := prefix + safeName(result.Identity.IP) + "_" + safeName(result.Identity.MAC) + "_" + timestamp
	jsonPath := filepath.Join(*output, base+".json")
	htmlPath := filepath.Join(*output, base+".html")
	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return 1
	}
	htmlFile, err := os.Create(htmlPath)
	if err != nil {
		jsonFile.Close()
		return 1
	}
	if err := report.Write(jsonFile, htmlFile, result); err != nil {
		jsonFile.Close()
		htmlFile.Close()
		return 1
	}
	if err := jsonFile.Close(); err != nil {
		htmlFile.Close()
		return 1
	}
	if err := htmlFile.Close(); err != nil {
		return 1
	}
	if uploader != nil {
		if err := uploader.UploadFile(ctx, jsonPath, filepath.Base(jsonPath)); err != nil {
			_ = writeUploadStatus(filepath.Join(*output, base+".upload-status.json"), "failed", err)
			return 3
		}
		if err := uploader.UploadFile(ctx, htmlPath, filepath.Base(htmlPath)); err != nil {
			_ = writeUploadStatus(filepath.Join(*output, base+".upload-status.json"), "failed", err)
			return 3
		}
		if err := writeUploadStatus(filepath.Join(*output, base+".upload-status.json"), "uploaded", nil); err != nil {
			return 3
		}
	}
	if runErr != nil {
		return 1
	}
	return 0
}

func writeUploadStatus(path, status string, uploadErr error) error {
	payload := struct {
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}{Status: status}
	if uploadErr != nil {
		payload.Error = uploadErr.Error()
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func safeName(value string) string {
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-")
	return replacer.Replace(value)
}
