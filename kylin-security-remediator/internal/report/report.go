package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type detailRow struct {
	Item       string
	Field      string
	Value      string
	Conclusion core.Conclusion
}

type detailSection struct {
	Title string
	Rows  []detailRow
}

type reportView struct {
	core.Result
	DisplayIP        string
	PrimaryInterface string
	SummaryChecks    []core.Check
	DetailSections   []detailSection
}

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"add": func(index int) int { return index + 1 },
	"class": func(conclusion core.Conclusion) string {
		switch conclusion {
		case core.ConclusionPass:
			return "pass"
		case core.ConclusionFail:
			return "fail"
		case core.ConclusionReview:
			return "review"
		default:
			return "na"
		}
	},
	"actionClass": func(status string) string {
		switch {
		case strings.Contains(status, "失败"):
			return "fail"
		case strings.Contains(status, "回滚"), strings.Contains(status, "未"), strings.Contains(status, "不可用"), strings.Contains(status, "需复核"):
			return "review"
		case strings.HasPrefix(status, "已"), strings.Contains(status, "成功"):
			return "pass"
		default:
			return "na"
		}
	},
	"summary": func(checks []core.Check) string {
		counts := map[core.Conclusion]int{}
		for _, check := range checks {
			counts[check.Conclusion]++
		}
		return fmt.Sprintf("通过 %d 项　异常 %d 项　需复核 %d 项　不适用 %d 项",
			counts[core.ConclusionPass], counts[core.ConclusionFail], counts[core.ConclusionReview], counts[core.ConclusionNA])
	},
}).Parse(`{{define "checks"}}<table><tr><th>序号</th><th>检查项目</th><th>预期结果</th><th>实际结果</th><th>结论</th></tr>
{{range $index, $check := .}}<tr><td>{{add $index}}</td><td>{{$check.Item}}</td><td>{{$check.Expected}}</td><td>{{$check.Actual}}</td><td class="{{class $check.Conclusion}}">{{$check.Conclusion}}</td></tr>{{else}}<tr><td colspan="5">尚无检查项目</td></tr>{{end}}</table>{{end}}
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>终端安全检查报告</title>
<style>body{margin:0;background:#f3f5f7;color:#202124;font-family:Microsoft YaHei,Arial,sans-serif}.wrap{max-width:1200px;margin:24px auto}.card{background:#fff;border:1px solid #dfe3e8;border-radius:7px;margin:16px;padding:20px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #d9dde2;padding:8px;text-align:left;word-break:break-all;vertical-align:top}th{background:#eef2f5}.pass{color:#1b5e20;font-weight:bold}.fail{color:#b71c1c;font-weight:bold}.review{color:#9a6700;font-weight:bold}.na{color:#687078}.info{color:#1565c0}.note{color:#59636e}</style></head><body><div class="wrap">
<div class="card"><h1>终端安全检查报告</h1>
<p>被检查终端IP地址:{{.DisplayIP}}　MAC地址：{{.Identity.MAC}}</p>
<p>主用网卡：{{.PrimaryInterface}}　计算机：{{.Identity.Hostname}}　执行身份：{{.Identity.EffectiveUser}}　检查时间：{{.GeneratedAt}}</p>
<p>操作系统：{{.Identity.OS}}　内核：{{.Identity.Kernel}}　CPU架构：{{.Identity.Arch}}　桌面用户：{{.Identity.DesktopUser}}</p>
{{if .Identity.NetworkStatus}}<p class="review">网络识别说明：{{.Identity.NetworkStatus}}</p>{{end}}
<p>{{summary .SummaryChecks}}</p>{{if .Scope}}<p class="note">{{.Scope}}</p>{{end}}</div>
{{if .ExecutionError}}<div class="card"><h2>执行错误</h2><p class="fail">{{.ExecutionError}}</p></div>{{end}}
{{if .BeforeChecks}}
<div class="card"><h2>一、修复前检查</h2><p>{{summary .BeforeChecks}}</p>{{template "checks" .BeforeChecks}}</div>
<div class="card"><h2>二、修复动作</h2><table><tr><th>序号</th><th>项目</th><th>执行动作</th><th>执行结果</th></tr>
{{range $index, $action := .Actions}}<tr><td>{{add $index}}</td><td>{{$action.Target}}</td><td>{{$action.Kind}}</td><td class="{{actionClass $action.Status}}">{{$action.Status}}</td></tr>{{else}}<tr><td colspan="4">没有执行修改动作</td></tr>{{end}}</table></div>
<div class="card"><h2>三、修复后复检</h2><p>{{summary .AfterChecks}}</p>{{template "checks" .AfterChecks}}<p class="note">说明：需复核不等于检查通过；外部连通性仍须从另一台终端验证。</p></div>
{{else}}
<div class="card"><h2>一、检查结果汇总</h2>{{template "checks" .Checks}}<p class="note">说明：需复核不等于检查通过；外部连通性仍须从另一台终端验证。</p></div>
{{end}}
<div class="card"><h2>网卡逐项明细</h2><table><tr><th>网卡</th><th>类型</th><th>状态</th><th>IP</th><th>MAC</th></tr>
{{range .Identity.Interfaces}}<tr><td>{{.Name}}</td><td>{{.Kind}}</td><td>{{if .Up}}启用{{else}}禁用{{end}}</td><td>{{.IP}}</td><td>{{.MAC}}</td></tr>{{else}}<tr><td colspan="5">未读取到网卡</td></tr>{{end}}</table></div>
{{range .DetailSections}}<div class="card"><h2>{{.Title}}</h2><table><tr><th>检查项目</th><th>核查字段</th><th>内容</th><th>结论</th></tr>
{{range .Rows}}<tr><td>{{.Item}}</td><td>{{.Field}}</td><td>{{.Value}}</td><td class="{{class .Conclusion}}">{{.Conclusion}}</td></tr>{{else}}<tr><td colspan="4">未发现记录</td></tr>{{end}}</table></div>{{end}}
</div></body></html>`))

func Write(jsonWriter, htmlWriter io.Writer, result core.Result) error {
	encoder := json.NewEncoder(jsonWriter)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	return page.Execute(htmlWriter, buildView(result))
}

func buildView(result core.Result) reportView {
	checks := result.Checks
	if len(result.AfterChecks) > 0 {
		checks = result.AfterChecks
	}
	displayIP := result.Identity.IP
	if displayIP == "" {
		displayIP = "未识别"
	}
	return reportView{
		Result:           result,
		DisplayIP:        displayIP,
		PrimaryInterface: primaryInterface(result.Identity),
		SummaryChecks:    checks,
		DetailSections:   buildDetailSections(checks),
	}
}

func primaryInterface(identity core.Identity) string {
	for _, item := range identity.Interfaces {
		if item.Name != "lo" && item.IP != "" && item.IP == identity.IP {
			return item.Name
		}
	}
	for _, item := range identity.Interfaces {
		if item.Name != "lo" && item.Up {
			return item.Name
		}
	}
	return "未识别"
}

func buildDetailSections(checks []core.Check) []detailSection {
	var sections []detailSection
	indexes := make(map[string]int)
	for _, check := range checks {
		title := detailTitle(check.Category)
		index, ok := indexes[title]
		if !ok {
			index = len(sections)
			indexes[title] = index
			sections = append(sections, detailSection{Title: title})
		}
		for _, detail := range check.Details {
			sections[index].Rows = append(sections[index].Rows, detailRow{
				Item: check.Item, Field: detail.Name, Value: detail.Value, Conclusion: check.Conclusion,
			})
		}
	}
	return sections
}

func detailTitle(category string) string {
	switch category {
	case "防火墙":
		return "防火墙规则逐项明细"
	case "SSH远程登录", "文件共享", "远程桌面":
		return "服务状态逐项明细"
	case "网络/无线":
		return "网络与无线逐项明细"
	case "USB存储设备":
		return "USB 存储设备记录逐项明细"
	case "浏览器登录":
		return "浏览器已保存密码逐项明细"
	default:
		return category + "逐项明细"
	}
}
