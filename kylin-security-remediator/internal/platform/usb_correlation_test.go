package platform

import (
	"testing"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/usb"
)

func TestMatchUdevBlockWithoutDeviceName(t *testing.T) {
	block := usb.Record{Detail: "/dev/sda1", Locator: "8:1"}
	matched, err := matchUdevBlock(block, map[string]string{"ID_BUS": "usb"})
	if err != nil || matched.Detail != block.Detail || matched.Locator != block.Locator {
		t.Fatalf("matched=%#v err=%v", matched, err)
	}
	if _, err := matchUdevBlock(block, map[string]string{"ID_BUS": "usb", "DEVNAME": "/dev/sdb1"}); err == nil {
		t.Fatal("conflicting device name accepted")
	}
}
