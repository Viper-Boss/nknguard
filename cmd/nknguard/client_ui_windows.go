//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"math"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
	ui "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"github.com/Viper-Boss/nknguard/pkg/usagestats"
)

// The Windows client is a native Win32 window (walk) with a notification
// area icon. Closing the window hides it to the tray and keeps the tunnel;
// "退出" in the tray menu disconnects and quits.
//
// Look: light page, white cards, a painted gradient banner that shows the
// connection state, and painted rounded buttons. Everything else is a
// standard control, so text input, selection and accessibility behave as
// Windows users expect.

const (
	windowTitle      = "NKNGuard"
	singleInstanceID = `Local\NKNGuardClient`
	sourceURL        = "https://github.com/Viper-Boss/nknguard"
	uiFont           = "Microsoft YaHei UI" // on every Windows 10/11, renders Chinese well
	// containerPt is the font size of containers. Every control sets its own
	// 10 pt font, so a label never relies on inheriting its parent's font
	// (the inner static control of a walk label can otherwise end up with the
	// System font, which has no Chinese glyphs).
	containerPt = 9
)

var (
	colorPage    = walk.RGB(0xf2, 0xf5, 0xf9)
	colorCard    = walk.RGB(0xff, 0xff, 0xff)
	colorText    = walk.RGB(0x16, 0x23, 0x39)
	colorMuted   = walk.RGB(0x6f, 0x81, 0x96)
	colorBorder  = walk.RGB(0xd8, 0xe2, 0xec)
	colorAccent  = walk.RGB(0x1f, 0x6f, 0xeb)
	colorPressed = walk.RGB(0x17, 0x57, 0xbd)
	colorGood    = walk.RGB(0x1f, 0xa2, 0x6b)
	colorWarn    = walk.RGB(0xd2, 0x8f, 0x12)
	colorBad     = walk.RGB(0xcf, 0x2e, 0x2e)
	colorIdle    = walk.RGB(0x9a, 0xa7, 0xb6)
	colorTeal    = walk.RGB(0x14, 0x6f, 0x78)
)

type clientUI struct {
	w  *clientWindow
	mw *walk.MainWindow

	tray           *walk.NotifyIcon
	trayConnect    *walk.Action
	trayDisconnect *walk.Action
	trayHinted     bool
	quitting       bool

	banner      *walk.CustomWidget
	bannerIcon  *walk.Bitmap
	bannerBack  *walk.Bitmap
	bannerSize  walk.Size
	bannerState string
	bannerTone  walk.Color

	statusDot  *walk.Label
	stateTitle *walk.Label
	stateCopy  *walk.Label
	pathLabel  *walk.Label
	errText    *walk.TextEdit
	connect    *flatButton
	disconnect *flatButton

	nasAddress   *walk.LineEdit
	localAddress *walk.LineEdit
	virtualIP    *walk.Label
	nasIP        *walk.Label

	pairCard     *walk.Composite
	deviceName   *walk.LineEdit
	invitation   *walk.TextEdit
	pairButton   *flatButton
	pairProgress *walk.Label
	pairCode     *walk.Label

	usageDay     *walk.Label
	usageMonth   *walk.Label
	usageQuarter *walk.Label
	usageNote    *walk.Label
	usageCheck   *walk.CheckBox
	usageLoading bool

	buttons []*flatButton
}

func cmdClient(g globals, _ io.Writer) error {
	// One window per user session: a second start shows the first one.
	name, _ := windows.UTF16PtrFromString(singleInstanceID)
	mutex, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		showExistingWindow()
		return nil
	}
	if err == nil {
		defer windows.CloseHandle(mutex)
	}

	window := &clientWindow{globals: g, usage: clientUsageReporter(g)}
	usageCtx, stopUsage := context.WithCancel(context.Background())
	defer stopUsage()
	if window.usage != nil {
		go window.usage.Run(usageCtx)
	}

	u := &clientUI{w: window, bannerState: "正在检查…", bannerTone: colorIdle}
	if err := u.create(); err != nil {
		return fmt.Errorf("无法创建窗口: %w", err)
	}
	defer u.tray.Dispose()

	stop := make(chan struct{})
	defer close(stop)
	go u.poll(stop)
	go u.refreshUsage(false)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				u.refreshUsage(false)
			}
		}
	}()

	u.mw.Run()
	return nil
}

func showExistingWindow() {
	title, _ := syscall.UTF16PtrFromString(windowTitle)
	if hwnd := win.FindWindow(nil, title); hwnd != 0 {
		win.ShowWindow(hwnd, win.SW_SHOW)
		win.ShowWindow(hwnd, win.SW_RESTORE)
		win.SetForegroundWindow(hwnd)
	}
}

// ---- layout helpers ---------------------------------------------------------------

func font(size int, bold bool) ui.Font {
	return ui.Font{Family: uiFont, PointSize: size, Bold: bold}
}

func card(title string, children ...ui.Widget) ui.Composite {
	return cardWith(nil, title, children...)
}

func cardWith(assign **walk.Composite, title string, children ...ui.Widget) ui.Composite {
	head := []ui.Widget{ui.Label{Text: title, Font: font(11, true), TextColor: colorText}}
	return ui.Composite{
		AssignTo:   assign,
		Font:       font(containerPt, false),
		Background: ui.SolidColorBrush{Color: colorCard},
		Layout:     ui.VBox{Margins: ui.Margins{Left: 20, Top: 16, Right: 20, Bottom: 18}, Spacing: 8, Alignment: ui.AlignHNearVCenter},
		Children:   append(head, children...),
	}
}

func muted(text string) ui.Label {
	return ui.Label{Text: text, Font: font(10, false), TextColor: colorMuted}
}

func row(children ...ui.Widget) ui.Composite {
	return ui.Composite{Font: font(containerPt, false), Layout: ui.HBox{MarginsZero: true, Spacing: 10}, Children: children}
}

// usageColumn is one count: a caption over a large coloured number.
func usageColumn(caption string, value **walk.Label, tone walk.Color) ui.Composite {
	return ui.Composite{
		MinSize: ui.Size{Width: 150},
		Layout:  ui.VBox{MarginsZero: true, SpacingZero: true, Alignment: ui.AlignHNearVCenter},
		Children: []ui.Widget{
			muted(caption),
			ui.Label{AssignTo: value, Text: "—", Font: font(20, true), TextColor: tone},
		},
	}
}

func (u *clientUI) create() error {
	icon, iconErr := walk.NewIconFromImageForDPI(appIconImage(64), 96)
	var windowIcon ui.Property
	if iconErr == nil {
		windowIcon = icon
	}
	u.connect = u.newButton("连接 NAS", true, 132, u.onConnect)
	u.disconnect = u.newButton("断开", false, 96, u.onDisconnect)
	u.pairButton = u.newButton("请求 NAS 配对", true, 148, u.onPair)
	copyNAS := u.newButton("复制", false, 68, func() { u.copyText(u.nasAddress.Text()) })
	copyLocal := u.newButton("复制", false, 68, func() { u.copyText(u.localAddress.Text()) })
	refresh := u.newButton("刷新人数", false, 96, func() { go u.refreshUsage(true) })

	err := ui.MainWindow{
		AssignTo:   &u.mw,
		Title:      windowTitle,
		Icon:       windowIcon,
		Font:       font(containerPt, false),
		Background: ui.SolidColorBrush{Color: colorPage},
		MinSize:    ui.Size{Width: 600, Height: 560},
		Size:       ui.Size{Width: 660, Height: 880},
		Layout:     ui.VBox{MarginsZero: true},
		Children: []ui.Widget{
			ui.ScrollView{
				HorizontalFixed: true,
				Font:            font(containerPt, false),
				Background:      ui.SolidColorBrush{Color: colorPage},
				Layout:          ui.VBox{Margins: ui.Margins{Left: 18, Top: 18, Right: 18, Bottom: 14}, Spacing: 14},
				Children: []ui.Widget{
					ui.CustomWidget{
						AssignTo:            &u.banner,
						MinSize:             ui.Size{Height: 128},
						MaxSize:             ui.Size{Height: 128},
						InvalidatesOnResize: true,
						PaintMode:           ui.PaintBuffered,
						PaintPixels:         u.paintBanner,
					},
					card("连接状态",
						row(
							ui.Label{AssignTo: &u.statusDot, Text: "●", Font: font(14, false), TextColor: colorIdle},
							ui.Label{AssignTo: &u.stateTitle, Text: "正在检查…", Font: font(15, true), TextColor: colorText},
							ui.HSpacer{},
							ui.Label{Font: font(10, false), AssignTo: &u.pathLabel, Text: "尚未连接", TextColor: colorMuted},
						),
						ui.Label{Font: font(10, false), AssignTo: &u.stateCopy, Text: "正在读取这台电脑的连接信息。", TextColor: colorMuted, EllipsisMode: ui.EllipsisEnd},
						ui.VSpacer{Size: 4},
						row(u.connect.decl(), u.disconnect.decl(), ui.HSpacer{}),
						ui.TextEdit{AssignTo: &u.errText, Font: font(10, false), ReadOnly: true, Visible: false, VScroll: true, MinSize: ui.Size{Height: 44}, TextColor: colorBad},
					),
					card("设备身份",
						muted("核对 NKN 地址的首尾字符，确认连接的是自己的 NAS。"),
						ui.Composite{
							Layout: ui.Grid{Columns: 3, MarginsZero: true, Spacing: 8},
							Children: []ui.Widget{
								ui.Label{Font: font(10, false), Text: "NAS 的 NKN 地址", TextColor: colorText},
								ui.LineEdit{AssignTo: &u.nasAddress, ReadOnly: true, Text: "未配对", Font: font(10, false)},
								copyNAS.decl(),
								ui.Label{Font: font(10, false), Text: "本机 NKN 地址", TextColor: colorText},
								ui.LineEdit{AssignTo: &u.localAddress, ReadOnly: true, Text: "连接后显示", Font: font(10, false)},
								copyLocal.decl(),
								ui.Label{Font: font(10, false), Text: "本机虚拟 IP", TextColor: colorText},
								ui.Label{AssignTo: &u.virtualIP, Text: "—", Font: font(10, true), TextColor: colorText, ColumnSpan: 2},
								ui.Label{Font: font(10, false), Text: "NAS 虚拟 IP", TextColor: colorText},
								ui.Label{AssignTo: &u.nasIP, Text: "—", Font: font(10, true), TextColor: colorText, ColumnSpan: 2},
							},
						},
					),
					cardWith(&u.pairCard, "首次配对",
						muted("在 NAS 面板“配对与授权”生成二维码，点“复制配对链接”，\n把 nknguard://pair/… 粘贴到下面，再到 NAS 面板核对六位码并批准。"),
						ui.Composite{
							Layout: ui.Grid{Columns: 2, MarginsZero: true, Spacing: 8},
							Children: []ui.Widget{
								ui.Label{Font: font(10, false), Text: "这台电脑的名称", TextColor: colorText},
								ui.LineEdit{AssignTo: &u.deviceName, Font: font(10, false), CueBanner: "例如：我的工作电脑", MaxLength: 80},
								ui.Label{Font: font(10, false), Text: "配对链接", TextColor: colorText},
								ui.TextEdit{AssignTo: &u.invitation, Font: font(10, false), VScroll: true, MinSize: ui.Size{Height: 64}},
							},
						},
						row(
							u.pairButton.decl(),
							ui.Label{Font: font(10, false), AssignTo: &u.pairProgress, Text: "配对链接只用于发起申请，必须由 NAS 主人批准。", TextColor: colorMuted, EllipsisMode: ui.EllipsisEnd},
							ui.HSpacer{},
						),
						ui.Label{AssignTo: &u.pairCode, Font: font(18, true), TextColor: colorGood},
					),
					card("NKNGuard 使用人数",
						muted("最近运行过 NKNGuard 的设备数，来自 NKN 链上的匿名订阅。"),
						row(
							usageColumn("24 小时", &u.usageDay, colorAccent),
							usageColumn("30 天", &u.usageMonth, colorTeal),
							usageColumn("90 天", &u.usageQuarter, walk.RGB(0x7a, 0x4d, 0xd8)),
							ui.HSpacer{},
						),
						ui.CheckBox{
							AssignTo:         &u.usageCheck,
							Font:             font(10, false),
							Text:             "参与匿名使用人数统计",
							Enabled:          false,
							OnCheckedChanged: u.onUsageToggled,
						},
						muted("开启后每天最多提交 3 个零手续费 NKN 链上订阅，只公开一个与本机 NKN 地址\n无关的匿名公钥，不含设备名、配对或流量信息。关闭后退订。"),
						row(
							ui.Label{Font: font(10, false), AssignTo: &u.usageNote, Text: "正在读取…", TextColor: colorMuted, EllipsisMode: ui.EllipsisEnd},
							ui.HSpacer{},
							refresh.decl(),
						),
					),
					muted("关闭窗口后 NKNGuard 缩到右下角托盘，连接保持；在托盘菜单中选“退出”才会断开。\n连接后只路由到 NAS 的虚拟地址，普通上网不受影响。"),
					row(
						muted("© 2026 NKNGuard Authors · AGPL-3.0-only · 无担保，可依许可再发布。"),
						ui.Label{
							Text:        "许可证与完整源码",
							TextColor:   colorAccent,
							Font:        ui.Font{Family: uiFont, PointSize: 10, Underline: true},
							ToolTipText: sourceURL,
							OnMouseUp:   func(_, _ int, _ walk.MouseButton) { openURL(sourceURL) },
						},
						ui.HSpacer{},
					),
				},
			},
		},
	}.Create()
	if err != nil {
		return err
	}
	for _, button := range u.buttons {
		button.widget.SetCursor(walk.CursorHand())
	}
	if bitmap, err := walk.NewBitmapFromImageForDPI(appIconImage(128), 96); err == nil {
		u.bannerIcon = bitmap
	}
	u.mw.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
		if u.quitting {
			return
		}
		*canceled = true
		u.mw.Hide()
		if !u.trayHinted {
			u.trayHinted = true
			_ = u.tray.ShowInfo("NKNGuard 仍在运行", "连接保持中。在托盘图标的菜单中选择“退出”可断开并关闭。")
		}
	})
	return u.createTray(icon)
}

func (u *clientUI) createTray(icon *walk.Icon) error {
	tray, err := walk.NewNotifyIcon(u.mw)
	if err != nil {
		return err
	}
	u.tray = tray
	if icon != nil {
		_ = tray.SetIcon(icon)
	}
	_ = tray.SetToolTip("NKNGuard")
	tray.MouseDown().Attach(func(_, _ int, button walk.MouseButton) {
		if button == walk.LeftButton {
			u.showWindow()
		}
	})
	tray.MessageClicked().Attach(u.showWindow)

	actions := tray.ContextMenu().Actions()
	add := func(text string, handler func()) *walk.Action {
		action := walk.NewAction()
		_ = action.SetText(text)
		action.Triggered().Attach(handler)
		_ = actions.Add(action)
		return action
	}
	add("打开 NKNGuard", u.showWindow)
	_ = actions.Add(walk.NewSeparatorAction())
	u.trayConnect = add("连接 NAS", u.onConnect)
	u.trayDisconnect = add("断开", u.onDisconnect)
	_ = actions.Add(walk.NewSeparatorAction())
	add("退出", u.quit)
	_ = u.trayConnect.SetEnabled(false)
	_ = u.trayDisconnect.SetEnabled(false)
	return tray.SetVisible(true)
}

func (u *clientUI) showWindow() {
	u.mw.Show()
	win.ShowWindow(u.mw.Handle(), win.SW_RESTORE)
	win.SetForegroundWindow(u.mw.Handle())
}

func (u *clientUI) quit() {
	u.quitting = true
	_ = u.w.disconnect()
	_ = u.tray.SetVisible(false)
	_ = u.mw.Close()
}

// ---- painted parts ---------------------------------------------------------------------

// paintBanner draws the header: a navy-to-teal rounded panel with the app
// mark, a headline and a pill showing the connection state.
func (u *clientUI) paintBanner(canvas *walk.Canvas, _ walk.Rectangle) error {
	b := u.banner.ClientBoundsPixels()
	px := u.banner.IntFrom96DPI
	// The rounded gradient panel is rendered as an anti-aliased image; GDI
	// can neither round a gradient fill nor smooth its edges.
	if u.bannerBack == nil || u.bannerSize.Width != b.Width || u.bannerSize.Height != b.Height {
		if u.bannerBack != nil {
			u.bannerBack.Dispose()
		}
		back, err := walk.NewBitmapFromImageForDPI(bannerImage(b.Width, b.Height, float64(px(20))), 96)
		if err != nil {
			return err
		}
		u.bannerBack, u.bannerSize = back, walk.Size{Width: b.Width, Height: b.Height}
	}
	_ = canvas.DrawImageStretchedPixels(u.bannerBack, b)

	iconSize := px(60)
	iconTop := b.Y + (b.Height-iconSize)/2
	if u.bannerIcon != nil {
		_ = canvas.DrawImageStretchedPixels(u.bannerIcon, walk.Rectangle{X: b.X + px(24), Y: iconTop, Width: iconSize, Height: iconSize})
	}
	textLeft := b.X + px(24) + iconSize + px(18)
	pillWidth := px(104)
	textWidth := b.Width - (textLeft - b.X) - pillWidth - px(36)

	headline, _ := walk.NewFont(uiFont, 14, walk.FontBold)
	sub, _ := walk.NewFont(uiFont, 9, 0)
	kicker, _ := walk.NewFont(uiFont, 8, walk.FontBold)
	for _, f := range []*walk.Font{headline, sub, kicker} {
		if f != nil {
			defer f.Dispose()
		}
	}
	single := walk.TextLeft | walk.TextSingleLine | walk.TextVCenter | walk.TextEndEllipsis
	_ = canvas.DrawTextPixels("NKN · WIREGUARD", kicker, walk.RGB(0x7f, 0xe3, 0xd2), walk.Rectangle{X: textLeft, Y: iconTop - px(8), Width: textWidth, Height: px(20)}, single)
	_ = canvas.DrawTextPixels("回到你的 NAS，只需一次点击", headline, walk.RGB(0xff, 0xff, 0xff), walk.Rectangle{X: textLeft, Y: iconTop + px(12), Width: textWidth, Height: px(32)}, single)
	_ = canvas.DrawTextPixels("直连优先 · 受阻时自动走 NKN 加密中继", sub, walk.RGB(0xb8, 0xd3, 0xe6), walk.Rectangle{X: textLeft, Y: iconTop + px(44), Width: textWidth, Height: px(22)}, single)

	pill := walk.Rectangle{X: b.X + b.Width - pillWidth - px(22), Y: b.Y + (b.Height-px(32))/2, Width: pillWidth, Height: px(32)}
	if pillBrush, err := walk.NewSolidColorBrush(walk.RGB(0xff, 0xff, 0xff)); err == nil {
		defer pillBrush.Dispose()
		_ = canvas.FillRoundedRectanglePixels(pillBrush, pill, walk.Size{Width: px(32), Height: px(32)})
	}
	if dotBrush, err := walk.NewSolidColorBrush(u.bannerTone); err == nil {
		defer dotBrush.Dispose()
		dot := px(10)
		_ = canvas.FillEllipsePixels(dotBrush, walk.Rectangle{X: pill.X + px(14), Y: pill.Y + (pill.Height-dot)/2, Width: dot, Height: dot})
	}
	pillFont, _ := walk.NewFont(uiFont, 9, walk.FontBold)
	if pillFont != nil {
		defer pillFont.Dispose()
	}
	_ = canvas.DrawTextPixels(u.bannerState, pillFont, colorText, walk.Rectangle{X: pill.X + px(30), Y: pill.Y, Width: pill.Width - px(36), Height: pill.Height}, single)
	return nil
}

// bannerImage renders the banner panel: a navy-to-teal diagonal gradient with
// anti-aliased rounded corners on the page colour.
func bannerImage(width, height int, radius float64) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	pageR, pageG, pageB := float64(colorPage.R()), float64(colorPage.G()), float64(colorPage.B())
	w, h := float64(width), float64(height)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			// Coverage of the rounded rectangle, one pixel of smoothing.
			cx := math.Min(math.Max(fx, radius), w-radius)
			cy := math.Min(math.Max(fy, radius), h-radius)
			distance := math.Hypot(fx-cx, fy-cy) - radius
			coverage := math.Max(0, math.Min(1, 0.5-distance))
			t := 0.75*fx/w + 0.25*fy/h
			r := 0x10*(1-t) + 0x16*t
			g := 0x1c*(1-t) + 0x7a*t
			b := 0x32*(1-t) + 0x82*t
			img.Set(x, y, color.RGBA{
				R: uint8(r*coverage + pageR*(1-coverage)),
				G: uint8(g*coverage + pageG*(1-coverage)),
				B: uint8(b*coverage + pageB*(1-coverage)),
				A: 0xff,
			})
		}
	}
	return img
}

// flatButton is a painted rounded button: filled blue for the main action,
// outlined for the others, grey when disabled.
type flatButton struct {
	widget  *walk.CustomWidget
	text    string
	primary bool
	width   int
	enabled bool
	pressed bool
	onClick func()
}

func (u *clientUI) newButton(text string, primary bool, width int, onClick func()) *flatButton {
	button := &flatButton{text: text, primary: primary, width: width, enabled: true, onClick: onClick}
	u.buttons = append(u.buttons, button)
	return button
}

func (b *flatButton) decl() ui.CustomWidget {
	return ui.CustomWidget{
		AssignTo:            &b.widget,
		MinSize:             ui.Size{Width: b.width, Height: 36},
		MaxSize:             ui.Size{Width: b.width, Height: 36},
		InvalidatesOnResize: true,
		PaintMode:           ui.PaintBuffered,
		PaintPixels:         b.paint,
		OnMouseDown: func(_, _ int, button walk.MouseButton) {
			if button == walk.LeftButton && b.enabled {
				b.pressed = true
				_ = b.widget.Invalidate()
			}
		},
		OnMouseUp: func(x, y int, button walk.MouseButton) {
			if button != walk.LeftButton || !b.pressed {
				return
			}
			b.pressed = false
			_ = b.widget.Invalidate()
			size := b.widget.ClientBoundsPixels()
			inside := x >= 0 && y >= 0 && x < size.Width && y < size.Height
			if inside && b.enabled && b.onClick != nil {
				b.onClick()
			}
		},
	}
}

func (b *flatButton) SetEnabled(enabled bool) {
	if b.enabled == enabled || b.widget == nil {
		b.enabled = enabled
		return
	}
	b.enabled = enabled
	if enabled {
		b.widget.SetCursor(walk.CursorHand())
	} else {
		b.widget.SetCursor(walk.CursorArrow())
	}
	_ = b.widget.Invalidate()
}

func (b *flatButton) paint(canvas *walk.Canvas, _ walk.Rectangle) error {
	bounds := b.widget.ClientBoundsPixels()
	px := b.widget.IntFrom96DPI
	background, err := walk.NewSolidColorBrush(colorCard)
	if err != nil {
		return err
	}
	defer background.Dispose()
	_ = canvas.FillRectanglePixels(background, bounds)

	fill, edge, label := colorCard, colorBorder, colorText
	switch {
	case !b.enabled && b.primary:
		fill, edge, label = walk.RGB(0xc9, 0xd6, 0xe6), walk.RGB(0xc9, 0xd6, 0xe6), walk.RGB(0xff, 0xff, 0xff)
	case !b.enabled:
		label = colorIdle
	case b.primary && b.pressed:
		fill, edge, label = colorPressed, colorPressed, walk.RGB(0xff, 0xff, 0xff)
	case b.primary:
		fill, edge, label = colorAccent, colorAccent, walk.RGB(0xff, 0xff, 0xff)
	case b.pressed:
		fill = walk.RGB(0xea, 0xf1, 0xfb)
	}
	radius := walk.Size{Width: px(12), Height: px(12)}
	shape := walk.Rectangle{X: bounds.X, Y: bounds.Y, Width: bounds.Width - 1, Height: bounds.Height - 1}
	brush, err := walk.NewSolidColorBrush(fill)
	if err != nil {
		return err
	}
	defer brush.Dispose()
	_ = canvas.FillRoundedRectanglePixels(brush, shape, radius)
	if pen, err := walk.NewCosmeticPen(walk.PenSolid, edge); err == nil {
		defer pen.Dispose()
		_ = canvas.DrawRoundedRectanglePixels(pen, shape, radius)
	}
	textFont, _ := walk.NewFont(uiFont, 9, walk.FontBold)
	if textFont != nil {
		defer textFont.Dispose()
	}
	return canvas.DrawTextPixels(b.text, textFont, label, bounds, walk.TextCenter|walk.TextVCenter|walk.TextSingleLine)
}

// ---- actions ------------------------------------------------------------------

func (u *clientUI) onConnect() {
	u.connect.SetEnabled(false)
	go func() {
		err := u.w.connect()
		u.keepError(err)
		u.mw.Synchronize(func() { u.render(u.w.snapshot()) })
	}()
}

func (u *clientUI) onDisconnect() {
	u.disconnect.SetEnabled(false)
	go func() {
		err := u.w.disconnect()
		u.keepError(err)
		u.mw.Synchronize(func() { u.render(u.w.snapshot()) })
	}()
}

func (u *clientUI) onPair() {
	invitation := strings.TrimSpace(u.invitation.Text())
	name := strings.TrimSpace(u.deviceName.Text())
	if invitation == "" {
		u.keepError(errors.New("请先粘贴 NAS 面板上的配对链接"))
		u.render(u.w.snapshot())
		return
	}
	u.pairButton.SetEnabled(false)
	go func() {
		err := u.w.pair(invitation, name)
		u.keepError(err)
		u.mw.Synchronize(func() { u.render(u.w.snapshot()) })
	}()
}

// keepError shows err until the next action; the periodic refresh would
// otherwise clear a message set directly on a control.
func (u *clientUI) keepError(err error) {
	if err != nil {
		u.w.update(func() { u.w.errorMessage = err.Error() })
	}
}

func (u *clientUI) copyText(text string) {
	if text == "" || text == "未配对" || text == "连接后显示" {
		return
	}
	if err := walk.Clipboard().SetText(text); err == nil {
		_ = u.tray.ShowInfo("已复制", text)
	}
}

func openURL(url string) {
	verb, _ := syscall.UTF16PtrFromString("open")
	target, err := syscall.UTF16PtrFromString(url)
	if err != nil {
		return
	}
	win.ShellExecute(0, verb, target, nil, nil, win.SW_SHOWNORMAL)
}

// ---- state --------------------------------------------------------------------

func (u *clientUI) poll(stop <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		snapshot := u.w.snapshot()
		u.mw.Synchronize(func() { u.render(snapshot) })
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func stateText(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func stateFlag(values map[string]any, key string) bool {
	value, _ := values[key].(bool)
	return value
}

func pathText(path string) string {
	switch path {
	case "direct-wg":
		return "WireGuard 直连"
	case "nkn-relay":
		return "NKN 加密中继"
	}
	return "正在寻找链路"
}

type textControl interface {
	Text() string
	SetText(string) error
}

func setText(control textControl, value string) {
	if control.Text() != value {
		_ = control.SetText(value)
	}
}

func (u *clientUI) render(state map[string]any) {
	paired, connected := stateFlag(state, "paired"), stateFlag(state, "connected")
	connecting, pairing := stateFlag(state, "connecting"), stateFlag(state, "pairing")
	path := stateText(state, "path")

	var title, short string
	tone := colorIdle
	switch {
	case !paired:
		title, short = "请先配对 NAS", "尚未配对"
	case !connected && connecting:
		title, short, tone = "正在建立连接", "连接中", colorWarn
	case !connected:
		title, short = "已断开", "未连接"
	case path == "direct-wg":
		title, short, tone = "已安全直连", "已直连", colorGood
	case path == "nkn-relay":
		title, short, tone = "已通过 NKN 中继", "已中继", colorGood
	default:
		title, short, tone = "正在建立安全链路", "连接中", colorWarn
	}
	setText(u.stateTitle, title)
	u.statusDot.SetTextColor(tone)
	if u.bannerState != short || u.bannerTone != tone {
		u.bannerState, u.bannerTone = short, tone
		_ = u.banner.Invalidate()
	}
	message := stateText(state, "message")
	if message == "" {
		switch {
		case connected:
			message = "现在可以用 NAS 的虚拟 IP 访问飞牛。"
		case paired:
			message = "点击“连接 NAS”，先尝试上次的直连路径，同时获取最新信标。"
		default:
			message = "把 NAS 面板上的配对链接粘贴到下方“首次配对”。"
		}
	}
	setText(u.stateCopy, message)
	if connected {
		setText(u.pathLabel, "链路 · "+pathText(path))
	} else {
		setText(u.pathLabel, "尚未连接")
	}
	errorText := stateText(state, "error")
	if u.errText.Text() != errorText {
		_ = u.errText.SetText(errorText)
	}
	u.errText.SetVisible(errorText != "")

	canConnect := paired && !connected && !connecting
	u.connect.SetEnabled(canConnect)
	u.disconnect.SetEnabled(connected)
	_ = u.trayConnect.SetEnabled(canConnect)
	_ = u.trayDisconnect.SetEnabled(connected)

	setText(u.nasAddress, orDefault(stateText(state, "nas_address"), "未配对"))
	setText(u.localAddress, orDefault(stateText(state, "local_nkn_address"), "连接后显示"))
	setText(u.virtualIP, orDash(stateText(state, "virtual_ip")))
	setText(u.nasIP, orDash(stateText(state, "nas_ip")))

	u.pairCard.SetVisible(!paired)
	u.pairButton.SetEnabled(!paired && !pairing)
	if pairing {
		setText(u.pairProgress, orDefault(message, "等待 NAS 批准…"))
	} else {
		setText(u.pairProgress, "配对链接只用于发起申请，必须由 NAS 主人批准。")
	}
	if code := stateText(state, "pair_code"); code != "" {
		setText(u.pairCode, "请在 NAS 面板核对六位码："+code)
	} else {
		setText(u.pairCode, "")
	}

	_ = u.tray.SetToolTip("NKNGuard · " + title)
}

func orDash(value string) string { return orDefault(value, "—") }

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// ---- usage statistics -----------------------------------------------------------------

func (u *clientUI) refreshUsage(force bool) {
	if u.w.usage == nil {
		u.mw.Synchronize(func() { setText(u.usageNote, usagestats.ErrUnavailable.Error()) })
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	status := u.w.usage.Status(ctx, force)
	u.mw.Synchronize(func() { u.renderUsage(status) })
}

func (u *clientUI) onUsageToggled() {
	if u.usageLoading || u.w.usage == nil {
		return
	}
	enabled := u.usageCheck.Checked()
	u.usageCheck.SetEnabled(false)
	if enabled {
		setText(u.usageNote, "正在开启…")
	} else {
		setText(u.usageNote, "正在关闭并退订…")
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := u.w.usage.SetEnabled(ctx, enabled)
		status := u.w.usage.Status(ctx, false)
		u.mw.Synchronize(func() {
			u.renderUsage(status)
			if err != nil {
				setText(u.usageNote, "操作失败："+err.Error())
			}
		})
	}()
}

func (u *clientUI) renderUsage(status usagestats.Status) {
	count := func(value *int) string {
		if value == nil {
			return "—"
		}
		return groupDigits(*value)
	}
	setText(u.usageDay, count(status.Counts.Day))
	setText(u.usageMonth, count(status.Counts.Month))
	setText(u.usageQuarter, count(status.Counts.Quarter))
	u.usageLoading = true
	u.usageCheck.SetChecked(status.Enabled)
	u.usageLoading = false
	u.usageCheck.SetEnabled(true)
	var note string
	switch {
	case !status.Enabled:
		note = "本机未参与统计，人数仍可查看。"
	case !status.LastCheckIn.IsZero():
		note = "本机已参与统计 · 上次签到 " + status.LastCheckIn.Local().Format("2006-01-02 15:04")
	default:
		note = "本机已参与统计 · 等待首次签到"
	}
	if status.Counts.Error != "" {
		note += " · 读取失败：" + status.Counts.Error
	} else if status.LastError != "" {
		note += " · 签到失败，稍后重试"
	}
	setText(u.usageNote, note)
}

// groupDigits writes 12345 as 12,345.
func groupDigits(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 0 || len(s) <= 3 {
		return s
	}
	var out strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(r)
	}
	return out.String()
}

// ---- icon ---------------------------------------------------------------------------

// appIconImage draws the NKNGuard mark: a rounded blue-to-teal square with a
// white "N" made of three strokes. The executable's icon (winres/icon.png)
// is the same design.
func appIconImage(size int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	radius := s * 0.22
	top := color.RGBA{0x3f, 0x8b, 0xff, 0xff}
	bottom := color.RGBA{0x2f, 0xc4, 0xb2, 0xff}
	inside := func(x, y float64) bool {
		cx := math.Min(math.Max(x, radius), s-radius)
		cy := math.Min(math.Max(y, radius), s-radius)
		return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= radius*radius
	}
	stroke := s * 0.11
	segments := [][4]float64{
		{0.30, 0.72, 0.30, 0.28},
		{0.30, 0.28, 0.70, 0.72},
		{0.70, 0.72, 0.70, 0.28},
	}
	nearStroke := func(x, y float64) bool {
		for _, seg := range segments {
			x1, y1, x2, y2 := seg[0]*s, seg[1]*s, seg[2]*s, seg[3]*s
			dx, dy := x2-x1, y2-y1
			t := ((x-x1)*dx + (y-y1)*dy) / (dx*dx + dy*dy)
			t = math.Max(0, math.Min(1, t))
			px, py := x1+t*dx, y1+t*dy
			if (x-px)*(x-px)+(y-py)*(y-py) <= (stroke/2)*(stroke/2) {
				return true
			}
		}
		return false
	}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			if !inside(fx, fy) {
				continue
			}
			if nearStroke(fx, fy) {
				img.Set(x, y, color.RGBA{0xff, 0xff, 0xff, 0xff})
				continue
			}
			t := (fx + fy) / (2 * s)
			img.Set(x, y, color.RGBA{
				R: uint8(float64(top.R)*(1-t) + float64(bottom.R)*t),
				G: uint8(float64(top.G)*(1-t) + float64(bottom.G)*t),
				B: uint8(float64(top.B)*(1-t) + float64(bottom.B)*t),
				A: 0xff,
			})
		}
	}
	return img
}
