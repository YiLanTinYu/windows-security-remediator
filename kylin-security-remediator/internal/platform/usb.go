package platform

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/usb"
)

type USBProbe struct {
	Root        fs.FS
	RootPath    string
	Journal     func(context.Context) ([]byte, error)
	GVFSEntries func(context.Context, string, string) ([]string, error)
}

func NewUSBProbe() USBProbe {
	return USBProbe{Root: os.DirFS("/"), RootPath: "/", Journal: readKernelJournal, GVFSEntries: systemGVFSEntries}
}

func (p USBProbe) Scan(ctx context.Context) ([]usb.SourceResult, error) {
	sysfs := p.scanSysfs()
	blocks := p.scanSysfsBlockDevices()
	udev := p.scanUdev()
	return []usb.SourceResult{sysfs, blocks, udev, p.scanMountInfo(udev, blocks), p.scanGVFS(ctx), p.scanJournal(ctx), p.scanUserRecentFiles()}, nil
}

func (p USBProbe) scanUdev() usb.SourceResult {
	result := usb.SourceResult{Name: "当前设备（udev）", Status: usb.StatusNone, Detail: "udev数据库中未发现当前USB存储设备"}
	entries, err := fs.ReadDir(p.Root, "run/udev/data")
	if err != nil {
		result.Status = sourceErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, readErr := fs.ReadFile(p.Root, "run/udev/data/"+entry.Name())
		if readErr != nil {
			result.Status = sourceErrorStatus(readErr)
			result.Detail = readErr.Error()
			return result
		}
		properties, parseErr := parseUdevProperties(data)
		if parseErr != nil {
			result.Status = usb.StatusParseFailed
			result.Detail = entry.Name() + "：" + parseErr.Error()
			return result
		}
		deviceType := properties["DEVTYPE"]
		if properties["ID_BUS"] != "usb" || (deviceType != "disk" && deviceType != "partition" && properties["ID_TYPE"] != "disk") {
			continue
		}
		device := properties["DEVNAME"]
		if device == "" || seen[device] {
			continue
		}
		seen[device] = true
		result.Records = append(result.Records, usb.Record{
			Vendor: properties["ID_VENDOR"], Product: properties["ID_MODEL"],
			Serial: properties["ID_SERIAL_SHORT"], Detail: device,
		})
	}
	if len(result.Records) > 0 {
		result.Status = usb.StatusFound
		result.Detail = ""
	}
	return result
}

func (p USBProbe) scanMountInfo(udev, blocks usb.SourceResult) usb.SourceResult {
	result := usb.SourceResult{Name: "当前挂载（mountinfo）", Status: usb.StatusNone, Detail: "未发现当前挂载的USB存储设备"}
	data, err := fs.ReadFile(p.Root, "proc/self/mountinfo")
	if err != nil {
		result.Status = sourceErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	udevUsable := udev.Status == usb.StatusFound || udev.Status == usb.StatusNone
	blocksUsable := blocks.Status == usb.StatusFound || blocks.Status == usb.StatusNone
	if !udevUsable && !blocksUsable {
		result.Status = udev.Status
		result.Detail = "udev和sysfs块设备映射均不可用，无法确认挂载是否属于USB存储设备"
		return result
	}
	devicesByPath := make(map[string]usb.Record)
	devicesByNumber := make(map[string]usb.Record)
	for _, record := range append(append([]usb.Record(nil), udev.Records...), blocks.Records...) {
		if record.Detail != "" {
			devicesByPath[record.Detail] = record
		}
		if record.Locator != "" {
			devicesByNumber[record.Locator] = record
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		before, after, found := strings.Cut(line, " - ")
		beforeFields := strings.Fields(before)
		afterFields := strings.Fields(after)
		if !found || len(beforeFields) < 6 || len(afterFields) < 3 {
			result.Status = usb.StatusParseFailed
			result.Detail = "mountinfo记录格式无效"
			result.Records = nil
			return result
		}
		source := unescapeMountInfo(afterFields[1])
		record, isUSB := devicesByPath[source]
		if !isUSB {
			record, isUSB = devicesByNumber[beforeFields[2]]
		}
		if !isUSB {
			continue
		}
		mountPoint := unescapeMountInfo(beforeFields[4])
		devicePath := record.Detail
		if devicePath == "" {
			devicePath = source
		}
		record.Detail = devicePath + " → " + mountPoint
		result.Records = append(result.Records, record)
	}
	if len(result.Records) > 0 {
		result.Status = usb.StatusFound
		result.Detail = ""
	}
	return result
}

func (p USBProbe) scanGVFS(ctx context.Context) usb.SourceResult {
	result := usb.SourceResult{Name: "当前用户设备（GVFS）", Status: usb.StatusNone, Detail: "未发现当前挂载的MTP或相机移动设备"}
	users, err := fs.ReadDir(p.Root, "run/user")
	if err != nil {
		result.Status = sourceErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	for _, user := range users {
		if !user.IsDir() {
			continue
		}
		base := "run/user/" + user.Name() + "/gvfs"
		var names []string
		if p.GVFSEntries != nil {
			var readErr error
			names, readErr = p.GVFSEntries(ctx, user.Name(), "/"+base)
			if errors.Is(readErr, fs.ErrNotExist) {
				continue
			}
			if readErr != nil {
				result.Status = sourceErrorStatus(readErr)
				result.Detail = readErr.Error()
				return result
			}
		} else {
			entries, readErr := fs.ReadDir(p.Root, base)
			if errors.Is(readErr, fs.ErrNotExist) {
				continue
			}
			if readErr != nil {
				result.Status = sourceErrorStatus(readErr)
				result.Detail = readErr.Error()
				return result
			}
			for _, entry := range entries {
				if entry.IsDir() {
					names = append(names, entry.Name())
				}
			}
		}
		for _, name := range names {
			lower := strings.ToLower(name)
			product := ""
			switch {
			case strings.HasPrefix(lower, "mtp:"):
				product = "MTP移动设备"
			case strings.HasPrefix(lower, "gphoto2:"):
				product = "相机或移动设备"
			default:
				continue
			}
			result.Records = append(result.Records, usb.Record{
				Product: product, Detail: "/" + base + "/" + name,
			})
		}
	}
	if len(result.Records) > 0 {
		result.Status = usb.StatusFound
		result.Detail = ""
	}
	return result
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

func parseUdevProperties(data []byte) (map[string]string, error) {
	properties := make(map[string]string)
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(line, "E:") {
			continue
		}
		key, value, found := strings.Cut(strings.TrimPrefix(line, "E:"), "=")
		if !found || key == "" {
			return nil, errors.New("udev属性格式无效")
		}
		properties[key] = value
	}
	return properties, nil
}

func (p USBProbe) scanUserRecentFiles() usb.SourceResult {
	result := usb.SourceResult{Name: "用户级最近文件记录", Status: usb.StatusNone, Detail: "未发现明确位于可移动介质挂载目录的最近文件记录"}
	mountPoints := p.mediaMountPoints()
	users, err := fs.ReadDir(p.Root, "home")
	if err != nil {
		result.Status = sourceErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	for _, user := range users {
		if !user.IsDir() {
			continue
		}
		relativePath := filepath.ToSlash(filepath.Join("home", user.Name(), ".local", "share", "recently-used.xbel"))
		data, readErr := fs.ReadFile(p.Root, relativePath)
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			result.Status = sourceErrorStatus(readErr)
			result.Detail = readErr.Error()
			return result
		}
		bookmarks, parseErr := removableBookmarks(data)
		if parseErr != nil {
			result.Status = usb.StatusParseFailed
			result.Detail = relativePath + "：" + parseErr.Error()
			return result
		}
		for _, bookmark := range bookmarks {
			result.Records = append(result.Records, usb.Record{
				Product: "最近访问的USB文件", Detail: bookmark.Href,
				Evidence: recentFileEvidence(user.Name(), bookmark, mountPoints),
				Locator:  relativePath, Cleanable: true,
			})
		}
	}
	if len(result.Records) > 0 {
		result.Status = usb.StatusFound
		result.Detail = ""
	}
	return result
}

func (p USBProbe) mediaMountPoints() []string {
	data, err := fs.ReadFile(p.Root, "proc/self/mountinfo")
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var mountPoints []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		before, _, found := strings.Cut(line, " - ")
		fields := strings.Fields(before)
		if !found || len(fields) < 5 {
			continue
		}
		mountPoint := strings.TrimSuffix(unescapeMountInfo(fields[4]), "/")
		if mountPoint == "" || (!strings.HasPrefix(mountPoint, "/media/") && !strings.HasPrefix(mountPoint, "/run/media/")) || seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true
		mountPoints = append(mountPoints, mountPoint)
	}
	sort.Slice(mountPoints, func(i, j int) bool { return len(mountPoints[i]) > len(mountPoints[j]) })
	return mountPoints
}

func (p USBProbe) CleanSafe(ctx context.Context, records []usb.Record) error {
	if p.RootPath == "" {
		return errors.New("未配置可写根目录")
	}
	grouped := make(map[string]map[string]bool)
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !record.Cleanable || !isRemovableFileURL(record.Detail) {
			return errors.New("拒绝清理未明确标记为安全的USB记录")
		}
		path, err := p.safeWritablePath(record.Locator)
		if err != nil {
			return err
		}
		if grouped[path] == nil {
			grouped[path] = make(map[string]bool)
		}
		grouped[path][record.Detail] = true
	}

	paths := make([]string, 0, len(grouped))
	for path := range grouped {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var backups []fileBackup
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			rollbackFiles(backups)
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			rollbackFiles(backups)
			return errors.New("拒绝清理符号链接文件")
		}
		before, err := os.ReadFile(path)
		if err != nil {
			rollbackFiles(backups)
			return err
		}
		after, err := removeBookmarkHrefs(before, grouped[path])
		if err != nil {
			rollbackFiles(backups)
			return err
		}
		backup, err := replaceWithBackup(path, after, info.Mode().Perm())
		if err != nil {
			rollbackFiles(backups)
			return err
		}
		backups = append(backups, backup)
	}
	for _, backup := range backups {
		_ = os.Remove(backup.backupPath)
	}
	return nil
}

func (p USBProbe) safeWritablePath(locator string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(locator))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("USB记录路径超出允许范围")
	}
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) != 5 || parts[0] != "home" || parts[1] == "" || parts[2] != ".local" || parts[3] != "share" || parts[4] != "recently-used.xbel" {
		return "", errors.New("USB记录路径不是允许清理的用户最近文件")
	}
	root, err := filepath.Abs(p.RootPath)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, clean)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("USB记录路径超出允许范围")
	}
	return path, nil
}

type byteRange struct{ start, end int64 }

type recentBookmark struct {
	Href     string
	Added    string
	Modified string
	Visited  string
}

func removableBookmarks(data []byte) ([]recentBookmark, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var bookmarks []recentBookmark
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return bookmarks, nil
			}
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "bookmark" {
			continue
		}
		bookmark := recentBookmark{}
		for _, attribute := range start.Attr {
			switch attribute.Name.Local {
			case "href":
				bookmark.Href = attribute.Value
			case "added":
				bookmark.Added = attribute.Value
			case "modified":
				bookmark.Modified = attribute.Value
			case "visited":
				bookmark.Visited = attribute.Value
			}
		}
		if isRemovableFileURL(bookmark.Href) && !isGeneratedReportURL(bookmark.Href) {
			bookmarks = append(bookmarks, bookmark)
		}
	}
}

func isGeneratedReportURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	path, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	if filepath.Ext(name) != ".html" && filepath.Ext(name) != ".json" {
		return false
	}
	return strings.HasPrefix(name, "verification-report_") || strings.HasPrefix(name, "kylin-report_") || strings.HasPrefix(name, "kylin-cleanup-report_")
}

func recentFileEvidence(user string, bookmark recentBookmark, mountPoints []string) string {
	parsed, _ := url.Parse(bookmark.Href)
	path, _ := url.PathUnescape(parsed.EscapedPath())
	mountPoint := recentMountPoint(path, user, mountPoints)
	fileName := "***" + filepath.Ext(path)
	when := recentBookmarkTime(bookmark)
	evidence := "用户=" + user + "；挂载点=" + mountPoint + "；文件=" + fileName + "；最后访问=" + when
	return evidence
}

func recentBookmarkTime(bookmark recentBookmark) string {
	when := bookmark.Visited
	if when == "" {
		when = bookmark.Modified
	}
	if when == "" {
		when = bookmark.Added
	}
	parsed, err := time.Parse(time.RFC3339, when)
	if err != nil || parsed.Year() < 2000 {
		return "时间未知"
	}
	return when
}

func recentMountPoint(path, user string, mountPoints []string) string {
	for _, mountPoint := range mountPoints {
		if path == mountPoint || strings.HasPrefix(path, mountPoint+"/") {
			return mountPoint
		}
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	mountParts := 0
	if len(parts) >= 2 && parts[0] == "media" {
		mountParts = 2
		if len(parts) >= 3 && parts[1] == user {
			mountParts = 3
		}
	} else if len(parts) >= 3 && parts[0] == "run" && parts[1] == "media" {
		mountParts = 3
		if len(parts) >= 4 && parts[2] == user {
			mountParts = 4
		}
	}
	if mountParts == 0 {
		return "无法确认"
	}
	return "/" + strings.Join(parts[:mountParts], "/")
}

func isRemovableFileURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "file" || (parsed.Host != "" && parsed.Host != "localhost") {
		return false
	}
	path, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return false
	}
	return strings.HasPrefix(path, "/media/") || strings.HasPrefix(path, "/run/media/")
}

func removeBookmarkHrefs(data []byte, targets map[string]bool) ([]byte, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var ranges []byteRange
	for {
		before := decoder.InputOffset()
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "bookmark" {
			continue
		}
		matched := false
		for _, attribute := range start.Attr {
			if attribute.Name.Local == "href" && targets[attribute.Value] {
				matched = true
			}
		}
		if !matched {
			continue
		}
		depth := 1
		for depth > 0 {
			nested, nestedErr := decoder.Token()
			if nestedErr != nil {
				return nil, nestedErr
			}
			switch nested.(type) {
			case xml.StartElement:
				depth++
			case xml.EndElement:
				depth--
			}
		}
		ranges = append(ranges, byteRange{start: before, end: decoder.InputOffset()})
	}
	var output []byte
	var cursor int64
	for _, item := range ranges {
		output = append(output, data[cursor:item.start]...)
		cursor = item.end
	}
	output = append(output, data[cursor:]...)
	return output, nil
}

type fileBackup struct {
	originalPath string
	backupPath   string
}

func replaceWithBackup(path string, data []byte, mode fs.FileMode) (fileBackup, error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".usb-remediator-new-*")
	if err != nil {
		return fileBackup{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return fileBackup{}, err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fileBackup{}, err
	}
	if err := temporary.Close(); err != nil {
		return fileBackup{}, err
	}
	backupFile, err := os.CreateTemp(directory, ".usb-remediator-backup-*")
	if err != nil {
		return fileBackup{}, err
	}
	backupPath := backupFile.Name()
	if err := backupFile.Close(); err != nil {
		return fileBackup{}, err
	}
	if err := os.Remove(backupPath); err != nil {
		return fileBackup{}, err
	}
	if err := os.Rename(path, backupPath); err != nil {
		return fileBackup{}, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Rename(backupPath, path)
		return fileBackup{}, err
	}
	return fileBackup{originalPath: path, backupPath: backupPath}, nil
}

func rollbackFiles(backups []fileBackup) {
	for index := len(backups) - 1; index >= 0; index-- {
		_ = os.Remove(backups[index].originalPath)
		_ = os.Rename(backups[index].backupPath, backups[index].originalPath)
	}
}

func (p USBProbe) scanSysfs() usb.SourceResult {
	result := usb.SourceResult{Name: "当前设备（sysfs）", Status: usb.StatusNone, Detail: "未发现当前连接的USB存储设备"}
	entries, err := fs.ReadDir(p.Root, "sys/bus/usb/devices")
	if err != nil {
		result.Status = sourceErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() && entry.Type()&fs.ModeSymlink == 0 {
			continue
		}
		classPath := "sys/bus/usb/devices/" + entry.Name() + "/bInterfaceClass"
		classData, readErr := fs.ReadFile(p.Root, classPath)
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			result.Status = sourceErrorStatus(readErr)
			result.Detail = readErr.Error()
			return result
		}
		if strings.TrimSpace(string(classData)) != "08" {
			continue
		}
		deviceName := strings.SplitN(entry.Name(), ":", 2)[0]
		if seen[deviceName] {
			continue
		}
		seen[deviceName] = true
		base := "sys/bus/usb/devices/" + deviceName + "/"
		result.Records = append(result.Records, usb.Record{
			Vendor:  readOptional(p.Root, base+"manufacturer"),
			Product: readOptional(p.Root, base+"product"),
			Serial:  readOptional(p.Root, base+"serial"),
		})
	}
	if len(result.Records) > 0 {
		result.Status = usb.StatusFound
		result.Detail = ""
	}
	return result
}

func (p USBProbe) scanSysfsBlockDevices() usb.SourceResult {
	result := usb.SourceResult{Name: "当前块设备（sysfs）", Status: usb.StatusNone, Detail: "未发现与USB存储接口关联的块设备"}
	interfaces, err := p.usbStorageInterfaces()
	if err != nil {
		result.Status = sourceErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	entries, err := fs.ReadDir(p.Root, "sys/class/block")
	if err != nil {
		result.Status = sourceErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	for _, entry := range entries {
		if entry.Type()&fs.ModeSymlink == 0 {
			continue
		}
		classPath := "sys/class/block/" + entry.Name()
		target, readErr := fs.ReadLink(p.Root, classPath)
		if readErr != nil {
			result.Status = sourceErrorStatus(readErr)
			result.Detail = readErr.Error()
			return result
		}
		if !pathContainsAnySegment(target, interfaces) {
			continue
		}
		deviceNumber := readOptional(p.Root, classPath+"/dev")
		if deviceNumber == "" {
			continue
		}
		product := readOptional(p.Root, classPath+"/device/model")
		if product == "" {
			product = "USB块设备"
		}
		result.Records = append(result.Records, usb.Record{
			Vendor:  readOptional(p.Root, classPath+"/device/vendor"),
			Product: product,
			Detail:  "/dev/" + entry.Name(),
			Locator: deviceNumber,
		})
	}
	if len(result.Records) > 0 {
		result.Status = usb.StatusFound
		result.Detail = ""
	}
	return result
}

func (p USBProbe) usbStorageInterfaces() (map[string]bool, error) {
	entries, err := fs.ReadDir(p.Root, "sys/bus/usb/devices")
	if err != nil {
		return nil, err
	}
	interfaces := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() && entry.Type()&fs.ModeSymlink == 0 {
			continue
		}
		classData, readErr := fs.ReadFile(p.Root, "sys/bus/usb/devices/"+entry.Name()+"/bInterfaceClass")
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		if strings.TrimSpace(string(classData)) == "08" {
			interfaces[entry.Name()] = true
		}
	}
	return interfaces, nil
}

func pathContainsAnySegment(path string, segments map[string]bool) bool {
	for _, segment := range strings.Split(strings.ReplaceAll(path, "\\", "/"), "/") {
		if segments[segment] {
			return true
		}
	}
	return false
}

func (p USBProbe) scanJournal(ctx context.Context) usb.SourceResult {
	result := usb.SourceResult{Name: "内核日志（journal）", Status: usb.StatusNone, Detail: "可读取日志范围内未发现USB存储事件"}
	if p.Journal == nil {
		result.Status = usb.StatusUnavailable
		result.Detail = "未配置日志读取器"
		return result
	}
	output, err := p.Journal(ctx)
	if err != nil {
		result.Status = journalErrorStatus(err)
		result.Detail = err.Error()
		return result
	}
	if len(strings.TrimSpace(string(output))) == 0 {
		result.Status = usb.StatusRotated
		result.Detail = "内核日志为空，无法确认历史记录"
		return result
	}
	for _, line := range usbStorageJournalLines(string(output)) {
		result.Records = append(result.Records, usb.Record{Product: "历史USB存储事件", Evidence: sanitizedJournalEvidence(line)})
	}
	if len(result.Records) > 0 {
		result.Status = usb.StatusFound
		result.Detail = ""
	}
	return result
}

var (
	directAccessTargetPattern = regexp.MustCompile(`(?i)\bscsi\s+(\d+:\d+:\d+:\d+):\s+direct-access\b`)
	removableTargetPattern    = regexp.MustCompile(`(?i)\bsd\s+(\d+:\d+:\d+:\d+):.*\battached scsi removable disk\b`)
	usbStorageHostPattern     = regexp.MustCompile(`(?i)\bscsi host(\d+):.*\busb-storage\b`)
)

func usbStorageJournalLines(output string) []string {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	removableTargets := make(map[string]bool)
	usbHosts := make(map[string]bool)
	for _, line := range lines {
		if match := removableTargetPattern.FindStringSubmatch(line); len(match) == 2 {
			removableTargets[match[1]] = true
		}
		if match := usbStorageHostPattern.FindStringSubmatch(line); len(match) == 2 {
			usbHosts[match[1]] = true
		}
	}

	var matched []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "registered new interface driver usb-storage") {
			continue
		}
		include := strings.Contains(lower, "usb-storage") || strings.Contains(lower, "mass storage") || removableTargetPattern.MatchString(line)
		if target := directAccessTargetPattern.FindStringSubmatch(line); len(target) == 2 {
			host := strings.SplitN(target[1], ":", 2)[0]
			include = include || removableTargets[target[1]] || usbHosts[host] || strings.Contains(lower, " usb ")
		}
		if include {
			matched = append(matched, line)
		}
	}
	return matched
}

func readKernelJournal(ctx context.Context) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/journalctl", "-k", "--no-pager", "--output=short-iso")
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, errors.New(strings.TrimSpace(string(output)))
	}
	return output, nil
}

func sanitizedJournalEvidence(line string) string {
	line = strings.Join(strings.Fields(line), " ")
	runes := []rune(line)
	if len(runes) > 500 {
		return string(runes[:500]) + "…"
	}
	return line
}

func readOptional(root fs.FS, path string) string {
	data, err := fs.ReadFile(root, path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func sourceErrorStatus(err error) usb.SourceStatus {
	if errors.Is(err, fs.ErrPermission) {
		return usb.StatusPermissionDenied
	}
	if errors.Is(err, fs.ErrNotExist) {
		return usb.StatusUnavailable
	}
	return usb.StatusParseFailed
}

func journalErrorStatus(err error) usb.SourceStatus {
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "not permitted") {
		return usb.StatusPermissionDenied
	}
	if strings.Contains(lower, "no journal files") || strings.Contains(lower, "not found") {
		return usb.StatusUnavailable
	}
	if strings.Contains(lower, "corrupt") || strings.Contains(lower, "failed to open") {
		return usb.StatusParseFailed
	}
	return usb.StatusUnavailable
}
