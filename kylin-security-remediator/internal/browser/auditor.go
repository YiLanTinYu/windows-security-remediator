package browser

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	_ "modernc.org/sqlite"
)

type Home struct {
	User string
	Path string
}

type Login struct {
	Site    string
	Account string
}

type ProfileResult struct {
	Browser string
	User    string
	Profile string
	Logins  []Login
	Issue   string
	Source  string
}

type Backend interface {
	Scan(context.Context) ([]ProfileResult, error)
}

type Cleaner interface {
	CleanSavedLogins(context.Context, []ProfileResult) error
}

type Auditor struct{ backend Backend }

func NewAuditor(backend Backend) *Auditor { return &Auditor{backend: backend} }

func (a *Auditor) Evaluate(ctx context.Context, mode core.Mode) ([]core.Check, []core.Action, error) {
	results, err := a.backend.Scan(ctx)
	if err != nil {
		return []core.Check{{
			Category: "浏览器登录", Item: "浏览器保存密码数据源", Expected: "能够读取",
			Actual: "数据源不可用：" + err.Error(), Conclusion: core.ConclusionReview,
			Details: []core.Detail{{Name: "扫描范围", Value: "/home下普通用户浏览器配置"}, {Name: "读取错误", Value: err.Error()}},
		}}, nil, nil
	}
	checks := buildChecks(results)
	if mode != core.ModeClean {
		return checks, nil, nil
	}
	var targets []ProfileResult
	for _, result := range results {
		if result.Issue == "" && len(result.Logins) > 0 {
			targets = append(targets, result)
		}
	}
	if len(targets) == 0 {
		return checks, []core.Action{{Kind: "browser-logins", Target: "浏览器保存密码", Status: "没有需要清理的有效条目"}}, nil
	}
	cleaner, ok := a.backend.(Cleaner)
	if !ok {
		return checks, []core.Action{{Kind: "browser-logins", Target: "浏览器保存密码", Status: "清理接口不可用，未修改"}}, nil
	}
	if err := cleaner.CleanSavedLogins(ctx, targets); err != nil {
		return checks, []core.Action{{Kind: "browser-logins", Target: "浏览器保存密码", Status: "清理失败，已尝试回滚"}}, err
	}
	after, err := a.backend.Scan(ctx)
	if err != nil {
		return checks, []core.Action{{Kind: "browser-logins", Target: "浏览器保存密码", Status: "清理后复检失败"}}, err
	}
	actions := make([]core.Action, 0, len(targets))
	for _, target := range targets {
		actions = append(actions, core.Action{
			Kind: "browser-logins", Target: target.Browser + " / " + target.User + " / " + target.Profile, Status: "已清理",
		})
	}
	return buildChecks(after), actions, nil
}

func buildChecks(results []ProfileResult) []core.Check {
	var checks []core.Check
	total := 0
	hasIssue := false
	for _, result := range results {
		check := core.Check{
			Category: "浏览器登录", Item: result.Browser + " / " + result.User + " / " + result.Profile,
			Expected: "没有保存密码的有效登录条目", Conclusion: core.ConclusionPass,
			Details: browserDetails(result),
		}
		if result.Issue != "" {
			check.Actual = "无法确认：" + result.Issue
			check.Conclusion = core.ConclusionReview
			hasIssue = true
		} else if len(result.Logins) == 0 {
			check.Actual = "登录数据库存在，但没有保存密码的有效条目"
		} else {
			total += len(result.Logins)
			check.Actual = formatLogins(result.Logins)
			check.Conclusion = core.ConclusionFail
		}
		checks = append(checks, check)
	}
	summary := core.Check{
		Category: "浏览器登录", Item: "浏览器已保存密码汇总",
		Expected: "所有普通用户浏览器均无保存密码条目",
		Actual:   "未发现保存密码的有效登录条目", Conclusion: core.ConclusionPass,
		Details: []core.Detail{{Name: "扫描配置数", Value: fmt.Sprintf("%d个", len(results))}, {Name: "有效保存密码记录", Value: fmt.Sprintf("%d条", total)}},
	}
	if total > 0 {
		summary.Actual = fmt.Sprintf("共发现%d条保存密码的有效登录记录", total)
		summary.Conclusion = core.ConclusionFail
	} else if hasIssue {
		summary.Actual = "未发现有效条目，但存在无法读取或无法确认的浏览器配置"
		summary.Conclusion = core.ConclusionReview
	}
	checks = append(checks, summary)
	return checks
}

func browserDetails(result ProfileResult) []core.Detail {
	details := []core.Detail{
		{Name: "浏览器", Value: result.Browser},
		{Name: "普通用户", Value: result.User},
		{Name: "配置目录", Value: result.Profile},
	}
	if result.Source != "" {
		details = append(details, core.Detail{Name: "登录数据文件", Value: filepath.Base(result.Source)})
	}
	if result.Issue != "" {
		return append(details, core.Detail{Name: "无法确认原因", Value: result.Issue})
	}
	if len(result.Logins) == 0 {
		return append(details, core.Detail{Name: "有效保存密码记录", Value: "0条"})
	}
	for index, login := range result.Logins {
		account := login.Account
		if account == "" {
			account = "账号字段为空"
		}
		details = append(details, core.Detail{Name: fmt.Sprintf("登录记录%02d", index+1), Value: login.Site + "（账号 " + account + "）"})
	}
	return details
}

type Scanner struct{ homes []Home }

func NewScanner(homes []Home) *Scanner { return &Scanner{homes: homes} }

func NewSystemScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Scan(ctx context.Context) ([]ProfileResult, error) {
	var results []ProfileResult
	homes := s.homes
	if homes == nil {
		var err error
		homes, err = systemHomes()
		if err != nil {
			return nil, err
		}
	}
	for _, home := range homes {
		results = append(results, scanFirefoxProfiles(home)...)
		configRoot := filepath.Join(home.Path, ".config")
		walkErr := filepath.WalkDir(configRoot, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				if errorsIsPermission(err) {
					results = append(results, ProfileResult{Browser: "未知浏览器", User: home.User, Profile: filepath.Base(path), Issue: "权限不足"})
					return fs.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				relative, _ := filepath.Rel(configRoot, path)
				if strings.Count(relative, string(filepath.Separator)) >= 3 || entry.Name() == "Cache" || entry.Name() == "Code Cache" {
					return fs.SkipDir
				}
				return nil
			}
			if entry.Name() != "Login Data" {
				return nil
			}
			result := scanChromiumDatabase(ctx, home, path)
			results = append(results, result)
			return nil
		})
		if walkErr != nil && !os.IsNotExist(walkErr) {
			return results, walkErr
		}
	}
	sort.Slice(results, func(i, j int) bool {
		left := results[i].User + "\x00" + results[i].Browser + "\x00" + results[i].Profile
		right := results[j].User + "\x00" + results[j].Browser + "\x00" + results[j].Profile
		return left < right
	})
	return results, nil
}

func (s *Scanner) CleanSavedLogins(ctx context.Context, targets []ProfileResult) error {
	var backups [][]fileSnapshot
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			restoreSnapshots(backups)
			return err
		}
		if target.Source == "" {
			restoreSnapshots(backups)
			return errors.New("浏览器配置缺少数据源路径")
		}
		snapshots, err := snapshotBrowserFiles(target.Source)
		if err != nil {
			restoreSnapshots(backups)
			return err
		}
		if target.Browser == "Mozilla Firefox" {
			err = cleanFirefoxLogins(target.Source)
		} else {
			err = cleanChromiumLogins(ctx, target.Source)
		}
		if err != nil {
			restoreFileSnapshots(snapshots)
			restoreSnapshots(backups)
			return err
		}
		backups = append(backups, snapshots)
	}
	return nil
}

func systemHomes() ([]Home, error) {
	entries, err := os.ReadDir("/home")
	if err != nil {
		return nil, fmt.Errorf("读取普通用户目录: %w", err)
	}
	var homes []Home
	for _, entry := range entries {
		if entry.IsDir() {
			homes = append(homes, Home{User: entry.Name(), Path: filepath.Join("/home", entry.Name())})
		}
	}
	return homes, nil
}

func scanFirefoxProfiles(home Home) []ProfileResult {
	root := filepath.Join(home.Path, ".mozilla", "firefox")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []ProfileResult{{Browser: "Mozilla Firefox", User: home.User, Profile: "用户配置", Issue: err.Error()}}
	}
	var results []ProfileResult
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name(), "logins.json")
		data, readErr := os.ReadFile(path)
		if os.IsNotExist(readErr) {
			continue
		}
		result := ProfileResult{Browser: "Mozilla Firefox", User: home.User, Profile: entry.Name(), Source: path}
		if readErr != nil {
			result.Issue = readErr.Error()
			results = append(results, result)
			continue
		}
		var document struct {
			Logins []struct {
				Hostname          string `json:"hostname"`
				EncryptedPassword string `json:"encryptedPassword"`
			} `json:"logins"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			result.Issue = "解析logins.json失败: " + err.Error()
			results = append(results, result)
			continue
		}
		for _, login := range document.Logins {
			if login.EncryptedPassword == "" {
				continue
			}
			result.Logins = append(result.Logins, Login{
				Site: siteOrigin(login.Hostname), Account: "账号已加密，无法直接读取",
			})
		}
		results = append(results, result)
	}
	return results
}

func scanChromiumDatabase(ctx context.Context, home Home, source string) ProfileResult {
	result := ProfileResult{
		Browser: browserName(source), User: home.User, Profile: filepath.Base(filepath.Dir(source)), Source: source,
	}
	tempDir, err := os.MkdirTemp("", "kylin-browser-audit-*")
	if err != nil {
		result.Issue = err.Error()
		return result
	}
	defer os.RemoveAll(tempDir)
	copyPath := filepath.Join(tempDir, "Login Data")
	if err := copyFile(source, copyPath); err != nil {
		result.Issue = err.Error()
		return result
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(source + suffix); err == nil {
			if err := copyFile(source+suffix, copyPath+suffix); err != nil {
				result.Issue = err.Error()
				return result
			}
		}
	}
	sqliteFormat, err := hasSQLiteHeader(copyPath)
	if err != nil {
		result.Issue = err.Error()
		return result
	}
	if !sqliteFormat {
		result.Issue = "数据库格式不受支持（可能为浏览器加密或定制格式）"
		return result
	}
	db, err := sql.Open("sqlite", copyPath)
	if err != nil {
		result.Issue = err.Error()
		return result
	}
	defer db.Close()
	columns, err := loginColumns(ctx, db)
	if err != nil {
		result.Issue = err.Error()
		return result
	}
	if !columns["origin_url"] || !columns["username_value"] || !columns["password_value"] {
		result.Issue = "登录数据库结构不受支持"
		return result
	}
	query := "SELECT origin_url, username_value FROM logins WHERE length(password_value) > 0"
	if columns["blacklisted_by_user"] {
		query += " AND COALESCE(blacklisted_by_user, 0) = 0"
	} else if columns["blocked_by_user"] {
		query += " AND COALESCE(blocked_by_user, 0) = 0"
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		result.Issue = err.Error()
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var site, account string
		if err := rows.Scan(&site, &account); err != nil {
			result.Issue = err.Error()
			return result
		}
		result.Logins = append(result.Logins, Login{Site: siteOrigin(site), Account: account})
	}
	if err := rows.Err(); err != nil {
		result.Issue = err.Error()
	}
	return result
}

func hasSQLiteHeader(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	header := make([]byte, 16)
	if _, err := io.ReadFull(file, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, err
	}
	return string(header) == "SQLite format 3\x00", nil
}

func cleanChromiumLogins(ctx context.Context, source string) error {
	db, err := sql.Open("sqlite", source)
	if err != nil {
		return err
	}
	columns, err := loginColumns(ctx, db)
	if err != nil {
		db.Close()
		return err
	}
	if !columns["password_value"] {
		db.Close()
		return errors.New("登录数据库结构不受支持")
	}
	statement := "DELETE FROM logins WHERE length(password_value) > 0"
	if columns["blacklisted_by_user"] {
		statement += " AND COALESCE(blacklisted_by_user, 0) = 0"
	} else if columns["blocked_by_user"] {
		statement += " AND COALESCE(blocked_by_user, 0) = 0"
	}
	if _, err := db.ExecContext(ctx, statement); err != nil {
		db.Close()
		return err
	}
	return db.Close()
}

func cleanFirefoxLogins(source string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	var document struct {
		Logins []json.RawMessage `json:"logins"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	kept := make([]json.RawMessage, 0, len(document.Logins))
	for _, raw := range document.Logins {
		var login struct {
			EncryptedPassword string `json:"encryptedPassword"`
		}
		if err := json.Unmarshal(raw, &login); err != nil {
			return err
		}
		if login.EncryptedPassword == "" {
			kept = append(kept, raw)
		}
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal(data, &full); err != nil {
		return err
	}
	encodedLogins, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	full["logins"] = encodedLogins
	updated, err := json.Marshal(full)
	if err != nil {
		return err
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	return os.WriteFile(source, updated, info.Mode().Perm())
}

type fileSnapshot struct {
	path   string
	exists bool
	data   []byte
	mode   fs.FileMode
}

func snapshotBrowserFiles(source string) ([]fileSnapshot, error) {
	paths := []string{source}
	if filepath.Base(source) == "Login Data" {
		paths = append(paths, source+"-wal", source+"-shm")
	}
	snapshots := make([]fileSnapshot, 0, len(paths))
	for _, path := range paths {
		snapshot := fileSnapshot{path: path}
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		snapshot.exists = true
		snapshot.data = data
		snapshot.mode = info.Mode().Perm()
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func restoreSnapshots(groups [][]fileSnapshot) {
	for index := len(groups) - 1; index >= 0; index-- {
		restoreFileSnapshots(groups[index])
	}
}

func restoreFileSnapshots(snapshots []fileSnapshot) {
	for _, snapshot := range snapshots {
		if snapshot.exists {
			_ = os.WriteFile(snapshot.path, snapshot.data, snapshot.mode)
		} else {
			_ = os.Remove(snapshot.path)
		}
	}
}

func loginColumns(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(logins)")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var index int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func browserName(path string) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.Contains(lower, "/google-chrome/"):
		return "Google Chrome"
	case strings.Contains(lower, "/chromium/"):
		return "Chromium"
	case strings.Contains(lower, "/microsoft-edge/"):
		return "Microsoft Edge"
	case strings.Contains(lower, "kylin"):
		return "银河麒麟浏览器"
	default:
		return filepath.Base(filepath.Dir(filepath.Dir(path))) + "（Chromium内核）"
	}
}

func siteOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host
	}
	return value
}

func formatLogins(logins []Login) string {
	parts := make([]string, 0, len(logins))
	for _, login := range logins {
		account := login.Account
		if account == "" {
			account = "账号字段为空"
		}
		parts = append(parts, login.Site+"（账号 "+account+"）")
	}
	return fmt.Sprintf("发现%d条：%s", len(logins), strings.Join(parts, "；"))
}

func errorsIsPermission(err error) bool {
	return os.IsPermission(err)
}
