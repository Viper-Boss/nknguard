//go:build windows

package main

import (
	"context"
	"fmt"
	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
	"github.com/lxn/walk"
	"time"
)

func (u *clientUI) checkUpdate() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		r, err := releaseupdate.Check(ctx, app.Version, "windows-installer", "amd64")
		u.mw.Synchronize(func() {
			if err != nil {
				walk.MsgBox(u.mw, "检查更新失败", "无法连接 GitHub，请稍后重试。\n"+err.Error(), walk.MsgBoxIconWarning)
				return
			}
			if !r.Available {
				walk.MsgBox(u.mw, "应用更新", "当前已是最新发布版本："+app.Version, walk.MsgBoxIconInformation)
				return
			}
			if walk.MsgBox(u.mw, "发现新版本", fmt.Sprintf("当前：%s\n最新：%s\n\n打开官方发布页下载 Windows 安装包？\n更新前请从托盘退出 NKNGuard，配对和配置会保留。", app.Version, r.Latest), walk.MsgBoxYesNo|walk.MsgBoxIconInformation) == walk.DlgCmdYes {
				openURL(r.ReleaseURL)
			}
		})
	}()
}
