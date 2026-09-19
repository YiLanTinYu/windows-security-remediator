package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/YiLanTinYu/kylin-security-remediator/internal/app"
	"github.com/YiLanTinYu/kylin-security-remediator/internal/program"
)

func main() {
	fmt.Fprintln(os.Stdout, app.CopyrightNotice)
	engine := program.NewCleanupEngine()
	args := append([]string{"--clean"}, os.Args[1:]...)
	os.Exit(app.Run(context.Background(), args, engine, time.Now))
}
