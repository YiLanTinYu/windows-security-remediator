package program

import (
	"github.com/YiLanTinYu/kylin-security-remediator/internal/browser"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/core"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/firewall"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/platform"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/services"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/usb"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/wireless"
)

func NewFullEngine() *core.Engine {
	return core.NewEngine(
		platform.NewIdentityProbe(),
		firewall.NewRemediator(platform.NewIPTablesBackend()),
		services.NewRemediator(platform.SystemdBackend{}),
		wireless.NewRemediator(platform.NewNMCLIBackend()),
		usb.NewAuditor(platform.NewUSBProbe()),
		browser.NewAuditor(browser.NewSystemScanner()),
	)
}

func NewCleanupEngine() *core.Engine {
	return core.NewEngine(
		platform.NewIdentityProbe(),
		wireless.NewRemediator(platform.NewNMCLIBackend()),
		usb.NewAuditor(platform.NewUSBProbe()),
		browser.NewAuditor(browser.NewSystemScanner()),
	)
}
