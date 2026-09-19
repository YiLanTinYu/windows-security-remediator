package browser_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/browser"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	_ "modernc.org/sqlite"
)

func TestChromiumAuditCountsOnlyRowsWithSavedPasswordData(t *testing.T) {
	home := t.TempDir()
	databasePath := filepath.Join(home, ".config", "chromium", "Default", "Login Data")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, blacklisted_by_user INTEGER DEFAULT 0)`,
		`INSERT INTO logins VALUES ('https://empty.example', 'empty-user', X'', 0)`,
		`INSERT INTO logins VALUES ('https://blocked.example', 'blocked-user', X'0102', 1)`,
		`INSERT INTO logins VALUES ('https://saved.example/login', 'test-user', X'736563726574', 0)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "zhangsan", Path: home}}))
	checks, actions, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(actions) != 0 || len(checks) != 2 {
		t.Fatalf("checks=%#v actions=%#v", checks, actions)
	}
	if checks[0].Conclusion != core.ConclusionFail || checks[1].Conclusion != core.ConclusionFail {
		t.Fatalf("checks = %#v", checks)
	}
	if !strings.Contains(checks[0].Actual, "https://saved.example") || !strings.Contains(checks[0].Actual, "test-user") {
		t.Fatalf("actual = %q", checks[0].Actual)
	}
	for _, forbidden := range []string{"empty.example", "blocked.example", "secret", "736563726574"} {
		if strings.Contains(checks[0].Actual, forbidden) {
			t.Fatalf("actual exposes or misclassifies %q: %s", forbidden, checks[0].Actual)
		}
	}
}

func TestChromiumCleanRemovesOnlySavedLoginRows(t *testing.T) {
	home := t.TempDir()
	databasePath := filepath.Join(home, ".config", "chromium", "Default", "Login Data")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, blacklisted_by_user INTEGER DEFAULT 0)`,
		`INSERT INTO logins VALUES ('https://saved.example', 'saved-user', X'0102', 0)`,
		`INSERT INTO logins VALUES ('https://empty.example', 'empty-user', X'', 0)`,
		`INSERT INTO logins VALUES ('https://blocked.example', 'blocked-user', X'0304', 1)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "zhangsan", Path: home}}))
	checks, actions, err := auditor.Evaluate(context.Background(), core.ModeClean)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(checks) != 2 || checks[0].Conclusion != core.ConclusionPass || checks[1].Conclusion != core.ConclusionPass {
		t.Fatalf("checks = %#v", checks)
	}
	if len(actions) != 1 || actions[0].Status != "已清理" {
		t.Fatalf("actions = %#v", actions)
	}

	db, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT origin_url FROM logins ORDER BY origin_url`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var sites []string
	for rows.Next() {
		var site string
		if err := rows.Scan(&site); err != nil {
			t.Fatal(err)
		}
		sites = append(sites, site)
	}
	if strings.Join(sites, ",") != "https://blocked.example,https://empty.example" {
		t.Fatalf("remaining rows = %#v", sites)
	}
}

func TestChromiumCleanReportsLockedDatabaseAndKeepsSavedLogin(t *testing.T) {
	home := t.TempDir()
	databasePath := filepath.Join(home, ".config", "chromium", "Default", "Login Data")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, blacklisted_by_user INTEGER DEFAULT 0)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO logins VALUES ('https://locked.example', 'locked-user', X'0102', 0)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	connection, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := connection.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		connection.Close()
		db.Close()
		t.Fatal(err)
	}

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "zhangsan", Path: home}}))
	checks, actions, cleanErr := auditor.Evaluate(context.Background(), core.ModeClean)
	if cleanErr == nil {
		t.Fatal("Evaluate() error = nil, want locked database failure")
	}
	if len(checks) != 2 || checks[0].Conclusion != core.ConclusionFail {
		t.Fatalf("checks = %#v", checks)
	}
	if len(actions) != 1 || actions[0].Status != "清理失败，已尝试回滚" {
		t.Fatalf("actions = %#v", actions)
	}
	_, _ = connection.ExecContext(context.Background(), "ROLLBACK")
	connection.Close()
	db.Close()

	checks, _, err = auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("audit after lock release error = %v", err)
	}
	if len(checks) != 2 || checks[0].Conclusion != core.ConclusionFail || !strings.Contains(checks[0].Actual, "locked.example") {
		t.Fatalf("saved login was lost after failed clean: %#v", checks)
	}
}

func TestChromiumCleanRollsBackEarlierProfileWhenLaterProfileIsLocked(t *testing.T) {
	home := t.TempDir()
	createLoginDatabase := func(profile, site string) *sql.DB {
		t.Helper()
		path := filepath.Join(home, ".config", "chromium", profile, "Login Data")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, blacklisted_by_user INTEGER DEFAULT 0)`); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO logins VALUES (?, 'user', X'0102', 0)`, site); err != nil {
			db.Close()
			t.Fatal(err)
		}
		return db
	}
	firstDB := createLoginDatabase("Default", "https://first.example")
	firstDB.Close()
	secondDB := createLoginDatabase("Profile 2", "https://second.example")
	connection, err := secondDB.Conn(context.Background())
	if err != nil {
		secondDB.Close()
		t.Fatal(err)
	}
	if _, err := connection.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		connection.Close()
		secondDB.Close()
		t.Fatal(err)
	}

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "zhangsan", Path: home}}))
	_, _, cleanErr := auditor.Evaluate(context.Background(), core.ModeClean)
	if cleanErr == nil {
		t.Fatal("Evaluate() error = nil, want second profile lock failure")
	}
	_, _ = connection.ExecContext(context.Background(), "ROLLBACK")
	connection.Close()
	secondDB.Close()

	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("audit after rollback error = %v", err)
	}
	if len(checks) != 3 || checks[0].Conclusion != core.ConclusionFail || checks[1].Conclusion != core.ConclusionFail {
		t.Fatalf("profiles were not both restored: %#v", checks)
	}
	actual := checks[0].Actual + checks[1].Actual
	if !strings.Contains(actual, "first.example") || !strings.Contains(actual, "second.example") {
		t.Fatalf("profiles were not both restored: %s", actual)
	}
}

func TestChromiumAuditTreatsExistingEmptyLoginDatabaseAsPass(t *testing.T) {
	home := t.TempDir()
	databasePath := filepath.Join(home, ".config", "google-chrome", "Default", "Login Data")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, blacklisted_by_user INTEGER DEFAULT 0)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "zhangsan", Path: home}}))
	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(checks) != 2 || checks[0].Conclusion != core.ConclusionPass || checks[1].Conclusion != core.ConclusionPass {
		t.Fatalf("checks = %#v", checks)
	}
}

func TestChromiumAuditIdentifiesNonSQLiteBrowserDatabaseWithoutRawDriverError(t *testing.T) {
	home := t.TempDir()
	databasePath := filepath.Join(home, ".config", "qaxbrowser", "Default", "Login Data")
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(databasePath, []byte("QAX encrypted browser data"), 0o600); err != nil {
		t.Fatal(err)
	}

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "test", Path: home}}))
	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(checks) != 2 || checks[0].Conclusion != core.ConclusionReview {
		t.Fatalf("checks = %#v", checks)
	}
	if checks[0].Actual != "无法确认：数据库格式不受支持（可能为浏览器加密或定制格式）" {
		t.Fatalf("actual = %q", checks[0].Actual)
	}
}

func TestFirefoxAuditReportsSiteButNeverEncryptedCredentialMaterial(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".mozilla", "firefox", "abcd.default-release")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	content := `{"logins":[{"hostname":"https://firefox.example/login","encryptedUsername":"ENCRYPTED-USER-TOKEN","encryptedPassword":"ENCRYPTED-PASSWORD-TOKEN"}]}`
	if err := os.WriteFile(filepath.Join(profile, "logins.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "zhangsan", Path: home}}))
	checks, _, err := auditor.Evaluate(context.Background(), core.ModeAudit)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(checks) != 2 || checks[0].Conclusion != core.ConclusionFail {
		t.Fatalf("checks = %#v", checks)
	}
	if !strings.Contains(checks[0].Actual, "https://firefox.example") || !strings.Contains(checks[0].Actual, "账号已加密，无法直接读取") {
		t.Fatalf("actual = %q", checks[0].Actual)
	}
	for _, secret := range []string{"ENCRYPTED-USER-TOKEN", "ENCRYPTED-PASSWORD-TOKEN"} {
		if strings.Contains(checks[0].Actual, secret) {
			t.Fatalf("actual exposes %q: %s", secret, checks[0].Actual)
		}
	}
}

func TestFirefoxCleanRemovesSavedLoginsAndKeepsOtherDocumentFields(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".mozilla", "firefox", "abcd.default-release")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	loginPath := filepath.Join(profile, "logins.json")
	content := `{"nextId":7,"version":3,"logins":[{"id":1,"hostname":"https://saved.example","encryptedUsername":"USER-TOKEN","encryptedPassword":"PASSWORD-TOKEN"},{"id":2,"hostname":"https://empty.example","encryptedPassword":""}],"potentiallyVulnerablePasswords":[]}`
	if err := os.WriteFile(loginPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	auditor := browser.NewAuditor(browser.NewScanner([]browser.Home{{User: "zhangsan", Path: home}}))
	checks, actions, err := auditor.Evaluate(context.Background(), core.ModeClean)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(checks) != 2 || checks[0].Conclusion != core.ConclusionPass || checks[1].Conclusion != core.ConclusionPass {
		t.Fatalf("checks = %#v", checks)
	}
	if len(actions) != 1 || actions[0].Status != "已清理" {
		t.Fatalf("actions = %#v", actions)
	}
	after, err := os.ReadFile(loginPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"saved.example", "USER-TOKEN", "PASSWORD-TOKEN"} {
		if strings.Contains(string(after), forbidden) {
			t.Fatalf("saved credential remains in logins.json: %s", after)
		}
	}
	for _, required := range []string{`"nextId":7`, `"version":3`, "empty.example", "potentiallyVulnerablePasswords"} {
		if !strings.Contains(string(after), required) {
			t.Fatalf("unrelated field %q was not preserved: %s", required, after)
		}
	}
}
