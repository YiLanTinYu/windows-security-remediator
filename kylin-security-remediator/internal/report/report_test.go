package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/report"
)

func TestWriteProducesMatchingJSONAndChineseHTML(t *testing.T) {
	result := core.Result{Scope: core.RuntimeScope, Identity: core.Identity{
		Hostname:      "kylin-test",
		OS:            "Kylin V10 SP1",
		Kernel:        "5.15.0-kylin",
		Arch:          "amd64",
		DesktopUser:   "zhangsan",
		EffectiveUser: "root",
		IP:            "192.0.2.10",
		MAC:           "02-00-00-00-00-10",
		NetworkStatus: "通过默认路由备用数据源识别",
		Interfaces: []core.NetworkInterface{
			{Name: "eno1", Kind: "有线", Up: true, IP: "192.0.2.10", MAC: "02-00-00-00-00-10"},
			{Name: "wlp2s0", Kind: "无线", Up: false, MAC: "02-00-00-00-00-20"},
		},
	}, Checks: []core.Check{{
		Category: "防火墙", Item: "TCP 445", Expected: "入站阻断",
		Actual: "未阻断", Conclusion: core.ConclusionFail,
		Details: []core.Detail{{Name: "数据来源", Value: "iptables-save"}, {Name: "规则位置", Value: "INPUT链第1条"}},
	}}}
	var jsonOut bytes.Buffer
	var htmlOut bytes.Buffer

	if err := report.Write(&jsonOut, &htmlOut, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	for _, want := range []string{`"hostname": "kylin-test"`, `"ip": "192.0.2.10"`, `"scope": "本报告仅反映本次运行及即时复检状态`} {
		if !strings.Contains(jsonOut.String(), want) {
			t.Errorf("JSON missing %q: %s", want, jsonOut.String())
		}
	}
	for _, want := range []string{`"details"`, `"name": "数据来源"`, `"value": "iptables-save"`} {
		if !strings.Contains(jsonOut.String(), want) {
			t.Errorf("JSON missing detail %q: %s", want, jsonOut.String())
		}
	}
	for _, want := range []string{"终端安全检查报告", core.RuntimeScope, "kylin-test", "5.15.0-kylin", "zhangsan", "root", "192.0.2.10", "02-00-00-00-00-10", "通过默认路由备用数据源识别", "eno1", "wlp2s0", "无线", "TCP 445", "未阻断", "防火墙规则逐项明细", "数据来源", "iptables-save", "规则位置", "INPUT链第1条", `class="fail"`} {
		if !strings.Contains(htmlOut.String(), want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestWriteShowsBeforeActionsAndAfterChecksInOrder(t *testing.T) {
	result := core.Result{
		BeforeChecks: []core.Check{{
			Category: "服务", Item: "SSH服务", Expected: "已停止、已禁用",
			Actual: "正在运行", Conclusion: core.ConclusionFail,
		}},
		Actions: []core.Action{{Kind: "service", Target: "ssh.service", Status: "已修复"}},
		AfterChecks: []core.Check{{
			Category: "服务", Item: "SSH服务", Expected: "已停止、已禁用",
			Actual: "已停止、已禁用", Conclusion: core.ConclusionPass,
		}},
		Checks: []core.Check{{
			Category: "服务", Item: "SSH服务", Expected: "已停止、已禁用",
			Actual: "已停止、已禁用", Conclusion: core.ConclusionPass,
		}},
	}
	var jsonOut bytes.Buffer
	var htmlOut bytes.Buffer

	if err := report.Write(&jsonOut, &htmlOut, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	html := htmlOut.String()
	before := strings.Index(html, "修复前检查")
	actions := strings.Index(html, "执行动作")
	after := strings.Index(html, "修复后复检")
	if before < 0 || actions <= before || after <= actions {
		t.Fatalf("sections are missing or out of order: before=%d actions=%d after=%d", before, actions, after)
	}
	if !strings.Contains(html, `class="fail">异常`) || !strings.Contains(html, `class="pass">通过`) {
		t.Fatalf("before/after colors missing: %s", html)
	}
	for _, want := range []string{
		"通过 0 项　异常 1 项　需复核 0 项　不适用 0 项",
		"通过 1 项　异常 0 项　需复核 0 项　不适用 0 项",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("summary missing %q: %s", want, html)
		}
	}
	if !strings.Contains(html, "ssh.service") || !strings.Contains(html, `class="pass">已修复`) {
		t.Fatalf("action details missing: %s", html)
	}
	for _, want := range []string{`"before_checks"`, `"after_checks"`, `"actions"`} {
		if !strings.Contains(jsonOut.String(), want) {
			t.Fatalf("JSON missing %s: %s", want, jsonOut.String())
		}
	}
}

func TestWriteEscapesTerminalControlledTextInHTML(t *testing.T) {
	result := core.Result{
		Identity: core.Identity{Hostname: `<script>alert("host")</script>`},
		Checks: []core.Check{{
			Category: "浏览器登录", Item: "Chromium",
			Actual: `<img src=x onerror="alert('account')">`, Conclusion: core.ConclusionFail,
		}},
	}
	var jsonOut bytes.Buffer
	var htmlOut bytes.Buffer

	if err := report.Write(&jsonOut, &htmlOut, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	html := htmlOut.String()
	for _, unsafe := range []string{"<script>", "<img src=x"} {
		if strings.Contains(html, unsafe) {
			t.Fatalf("HTML contains unescaped terminal text %q: %s", unsafe, html)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img src=x"} {
		if !strings.Contains(html, escaped) {
			t.Fatalf("HTML missing escaped terminal text %q: %s", escaped, html)
		}
	}
}

func TestWriteUsesWindowsReportReadingStructure(t *testing.T) {
	result := core.Result{
		GeneratedAt: "2026-09-15 20:00:00",
		Identity: core.Identity{
			Hostname: "kylin-test", EffectiveUser: "root", IP: "192.0.2.10", MAC: "02-00-00-00-00-10",
			OS: "Kylin V10 SP1", Arch: "amd64",
			Interfaces: []core.NetworkInterface{{Name: "eno1", Kind: "有线", Up: true, IP: "192.0.2.10"}},
		},
		Checks: []core.Check{
			{Category: "防火墙", Item: "高危端口入站阻断规则", Expected: "规则完整", Actual: "仍需1项调整", Conclusion: core.ConclusionFail, Details: []core.Detail{{Name: "待调整01", Value: "TCP-445"}}},
			{Category: "USB存储设备", Item: "数据源：内核日志（journal）", Expected: "能够读取", Actual: "找到1条", Conclusion: core.ConclusionReview, Details: []core.Detail{{Name: "证据01", Value: "2026-09-15T19:00:00 usb-storage 1-1:1.0"}}},
		},
	}
	var jsonOut bytes.Buffer
	var htmlOut bytes.Buffer
	if err := report.Write(&jsonOut, &htmlOut, result); err != nil {
		t.Fatal(err)
	}
	html := htmlOut.String()
	for _, want := range []string{
		"终端安全检查报告", `class="wrap"`, `class="card"`, "一、检查结果汇总",
		"<th>序号</th>", "主用网卡：eno1", "检查时间：2026-09-15 20:00:00",
		"防火墙规则逐项明细", "USB 存储设备记录逐项明细",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing Windows report structure %q", want)
		}
	}
	for _, unwanted := range []string{`class="detail-row"`, "银河麒麟终端安全检查报告"} {
		if strings.Contains(html, unwanted) {
			t.Errorf("HTML retains old Kylin-only structure %q", unwanted)
		}
	}
}
