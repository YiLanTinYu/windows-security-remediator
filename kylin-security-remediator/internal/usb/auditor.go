package usb

import (
	"context"
	"fmt"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
)

type SourceStatus string

const (
	StatusFound            SourceStatus = "找到记录"
	StatusNone             SourceStatus = "确定无记录"
	StatusPermissionDenied SourceStatus = "权限不足"
	StatusUnavailable      SourceStatus = "数据源不存在"
	StatusRotated          SourceStatus = "日志已轮换"
	StatusParseFailed      SourceStatus = "解析失败"
)

type Record struct {
	Vendor    string
	Product   string
	Serial    string
	Detail    string
	Evidence  string
	Locator   string
	Cleanable bool
}

type SourceResult struct {
	Name    string
	Status  SourceStatus
	Detail  string
	Records []Record
}

type Backend interface {
	Scan(context.Context) ([]SourceResult, error)
}

type SafeCleaner interface {
	CleanSafe(context.Context, []Record) error
}

type Auditor struct{ backend Backend }

func NewAuditor(backend Backend) *Auditor { return &Auditor{backend: backend} }

func (a *Auditor) Evaluate(ctx context.Context, mode core.Mode) ([]core.Check, []core.Action, error) {
	results, err := a.backend.Scan(ctx)
	if err != nil {
		results = []SourceResult{{Name: "USB检查", Status: StatusUnavailable, Detail: err.Error()}}
	}
	var checks []core.Check
	var foundSources []string
	limited := false
	sysfsFound := false
	sysfsBlockFound := false
	udevNone := false
	for _, result := range results {
		lowerName := strings.ToLower(result.Name)
		if strings.Contains(lowerName, "sysfs") && result.Status == StatusFound {
			sysfsFound = true
		}
		if strings.Contains(lowerName, "sysfs") && strings.Contains(lowerName, "块设备") && result.Status == StatusFound {
			sysfsBlockFound = true
		}
		if strings.Contains(lowerName, "udev") && result.Status == StatusNone {
			udevNone = true
		}
	}
	for _, result := range results {
		check := core.Check{
			Category: "USB存储设备", Item: "数据源：" + result.Name,
			Expected: "能够读取并区分无记录与读取失败",
			Actual:   sourceActual(result), Conclusion: core.ConclusionPass,
			Details: sourceDetails(result),
		}
		switch result.Status {
		case StatusFound:
			foundSources = append(foundSources, fmt.Sprintf("%s%d条", evidenceLabel(result.Name), len(result.Records)))
			check.Conclusion = core.ConclusionReview
		case StatusNone:
		default:
			limited = true
			check.Conclusion = core.ConclusionReview
		}
		lowerName := strings.ToLower(result.Name)
		if sysfsFound && result.Status == StatusNone && strings.Contains(lowerName, "udev") {
			check.Actual = "未识别到当前USB存储设备；与sysfs已发现当前设备的结果不一致"
			check.Conclusion = core.ConclusionReview
			check.Details = append(check.Details, core.Detail{Name: "一致性核查", Value: "sysfs已发现当前USB存储设备，udev未返回对应设备节点，需复核udev属性"})
		}
		if sysfsFound && !sysfsBlockFound && udevNone && result.Status == StatusNone && strings.Contains(lowerName, "mountinfo") {
			check.Actual = "无法确认当前USB存储设备是否已挂载：udev未识别到设备节点，无法与mountinfo交叉匹配"
			check.Conclusion = core.ConclusionReview
			check.Details = append(check.Details, core.Detail{Name: "一致性核查", Value: "sysfs已发现当前USB存储设备，但缺少udev设备节点，不能把mountinfo未匹配解释为确定未挂载"})
		}
		checks = append(checks, check)
	}
	summary := core.Check{
		Category: "USB存储设备", Item: "USB存储设备记录汇总",
		Expected: "没有USB存储设备记录；受限数据源必须明确说明",
		Actual:   "确定未发现USB存储设备记录", Conclusion: core.ConclusionPass,
		Details: summaryDetails(results),
	}
	if len(foundSources) > 0 {
		summary.Actual = "发现USB相关证据：" + strings.Join(foundSources, "、") + "；不同数据源可能指向同一设备，不按设备数量合计，需现场核查"
		summary.Conclusion = core.ConclusionReview
	} else if limited || len(results) == 0 {
		summary.Actual = "未找到记录，但存在权限不足、数据源缺失、日志轮换或解析失败，不能判定为无记录"
		summary.Conclusion = core.ConclusionReview
	}
	checks = append(checks, summary)
	if mode == core.ModeClean {
		var cleanable []Record
		for _, result := range results {
			for _, record := range result.Records {
				if record.Cleanable {
					cleanable = append(cleanable, record)
				}
			}
		}
		if len(cleanable) == 0 {
			return checks, []core.Action{{
				Kind: "usb-records", Target: "USB用户级记录",
				Status: "无可安全单独清理项，系统证据已保留",
			}}, nil
		}
		cleaner, ok := a.backend.(SafeCleaner)
		if !ok {
			return checks, []core.Action{{
				Kind: "usb-records", Target: "USB用户级记录", Status: "清理接口不可用，未修改",
			}}, nil
		}
		if cleanErr := cleaner.CleanSafe(ctx, cleanable); cleanErr != nil {
			return checks, []core.Action{{
				Kind: "usb-records", Target: "USB用户级记录", Status: "清理失败，未确认修改",
			}}, cleanErr
		}
		actions := make([]core.Action, 0, len(cleanable))
		for _, record := range cleanable {
			actions = append(actions, core.Action{
				Kind: "usb-records", Target: recordName(record), Status: "已清理",
			})
		}
		return checks, actions, nil
	}
	return checks, nil, nil
}

func sourceDetails(result SourceResult) []core.Detail {
	details := []core.Detail{{Name: "数据来源", Value: result.Name}, {Name: "读取状态", Value: string(result.Status)}}
	if result.Detail != "" {
		details = append(details, core.Detail{Name: "数据源说明", Value: result.Detail})
	}
	for index, record := range result.Records {
		value := recordName(record)
		if record.Evidence != "" {
			value = record.Evidence
		} else if isJournalSource(result.Name) {
			value = "检测到USB存储相关内核日志事件"
		} else if isRecentFileSource(result.Name) {
			value = "检测到USB存储路径的最近文件访问记录（具体文件名已隐藏）"
		}
		details = append(details, core.Detail{Name: fmt.Sprintf("证据%02d", index+1), Value: value})
	}
	if len(result.Records) == 0 {
		details = append(details, core.Detail{Name: "证据记录", Value: "0条"})
	}
	return details
}

func summaryDetails(results []SourceResult) []core.Detail {
	details := []core.Detail{{Name: "判定说明", Value: "各数据源独立计数，同一设备可能在多个来源出现，不合并为设备总数"}}
	for _, result := range results {
		details = append(details, core.Detail{Name: result.Name, Value: fmt.Sprintf("%s，记录%d条", result.Status, len(result.Records))})
	}
	if len(results) == 0 {
		details = append(details, core.Detail{Name: "数据源", Value: "未返回任何检查结果"})
	}
	return details
}

func sourceActual(result SourceResult) string {
	if result.Status == StatusFound {
		if isJournalSource(result.Name) {
			return fmt.Sprintf("找到%d条相关日志事件（不等于%d台设备）", len(result.Records), len(result.Records))
		}
		if isRecentFileSource(result.Name) {
			return fmt.Sprintf("找到%d条USB文件访问记录（不等于%d台设备）", len(result.Records), len(result.Records))
		}
		var records []string
		for _, record := range result.Records {
			records = append(records, recordName(record))
		}
		return fmt.Sprintf("找到%d条：%s", len(result.Records), strings.Join(records, "、"))
	}
	actual := string(result.Status)
	if result.Detail != "" {
		actual += "：" + result.Detail
	}
	return actual
}

func evidenceLabel(name string) string {
	if isJournalSource(name) {
		return "内核日志事件"
	}
	if isRecentFileSource(name) {
		return "用户级最近文件记录"
	}
	return name
}

func isJournalSource(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(name, "内核日志") || strings.Contains(lower, "journal")
}

func isRecentFileSource(name string) bool {
	return strings.Contains(name, "最近文件")
}

func recordName(record Record) string {
	name := strings.TrimSpace(record.Vendor + " " + record.Product)
	if name == "" {
		name = "USB存储设备"
	}
	if record.Serial != "" {
		name += "（序列号 " + record.Serial + "）"
	}
	if record.Detail != "" && !record.Cleanable {
		name += "［" + record.Detail + "］"
	}
	return name
}
