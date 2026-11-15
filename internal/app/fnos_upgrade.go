package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const fnosCenterSocket = "/var/run/com.trim.app.center.sock"

// Only the already verified nknguard FPK reaches this root-local transport.
// install-fpk is deliberately not a fallback: it can return success without
// upgrading an installed application. install-local can uninstall user data.
type fnosUpgradeClient struct {
	http      *http.Client
	interval  time.Duration
	installed func() (string, error)
	running   func(context.Context) (string, error)
}
type fnosRPCError struct {
	code    int
	message string
}

func (e *fnosRPCError) Error() string {
	return fmt.Sprintf("飞牛应用中心错误 %d: %s", e.code, e.message)
}
func newFnosUpgradeClient(socket string, cfgSocket string) *fnosUpgradeClient {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &fnosUpgradeClient{http: &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("应用中心接口不能重定向") }}, interval: time.Second,
		installed: func() (string, error) {
			raw, err := os.ReadFile("/var/apps/nknguard/manifest")
			if err != nil {
				return "", err
			}
			var name, version string
			for _, line := range strings.Split(string(raw), "\n") {
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				switch strings.TrimSpace(k) {
				case "appname":
					name = strings.TrimSpace(v)
				case "version":
					version = strings.TrimSpace(v)
				}
			}
			if name != "nknguard" || version == "" {
				return "", errors.New("已安装应用清单无效")
			}
			return version, nil
		},
		running: func(ctx context.Context) (string, error) {
			cl := NewClient(cfgSocket)
			req, err := http.NewRequestWithContext(ctx, "GET", "http://nknguard/v1/status", nil)
			if err != nil {
				return "", err
			}
			res, err := cl.http.Do(req)
			if err != nil {
				return "", err
			}
			defer res.Body.Close()
			if res.StatusCode != 200 {
				return "", fmt.Errorf("后台状态 HTTP %d", res.StatusCode)
			}
			var status struct {
				Version string `json:"version"`
			}
			err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&status)
			return status.Version, err
		},
	}
}
func (c *fnosUpgradeClient) call(ctx context.Context, route string, input, output any) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/rpc/v1/"+route, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("飞牛应用中心 HTTP %d", res.StatusCode)
	}
	var body struct {
		Code    *int            `json:"code"`
		Message string          `json:"msg"`
		Data    json.RawMessage `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
		return err
	}
	if body.Code == nil {
		return errors.New("应用中心未返回业务状态码")
	}
	if *body.Code != 0 {
		return &fnosRPCError{*body.Code, body.Message}
	}
	if output != nil {
		if len(body.Data) == 0 || string(body.Data) == "null" {
			return errors.New("应用中心未返回任务信息")
		}
		return json.Unmarshal(body.Data, output)
	}
	return nil
}
func (c *fnosUpgradeClient) pause(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.interval):
		return nil
	}
}
func sameUpdateVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}
func (c *fnosUpgradeClient) upgrade(ctx context.Context, path, target string, record func(string)) error {
	// A validation-only request confirms the native upgrade route exists.
	var validation *fnosRPCError
	if err := c.call(ctx, "update/info", map[string]any{}, nil); !errors.As(err, &validation) || validation.code != 10030 {
		return fmt.Errorf("本机升级接口不可用，请从飞牛应用中心手动升级（%v）", err)
	}
	var submitted struct {
		ID string `json:"downloadTaskId"`
	}
	if err := c.call(ctx, "download/task", map[string]any{"packageSourceType": "file", "path": path}, &submitted); err != nil {
		return err
	}
	if submitted.ID == "" {
		return errors.New("应用中心未返回暂存任务 ID")
	}
	var staged struct {
		Status    int    `json:"status"`
		Name      string `json:"appName"`
		Version   string `json:"version"`
		Kind      string `json:"packageType"`
		Installed bool   `json:"installed"`
		Message   string `json:"message"`
	}
	staging, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	failures := 0
	for {
		if err := c.call(staging, "download/status", map[string]string{"downloadTaskId": submitted.ID}, &staged); err != nil {
			var rpc *fnosRPCError
			if errors.As(err, &rpc) && rpc.code != 10050 {
				return err
			}
			failures++
			if failures >= 5 {
				return fmt.Errorf("无法确认暂存任务: %w", err)
			}
			if e := c.pause(staging); e != nil {
				return e
			}
			continue
		}
		failures = 0
		if staged.Status == 2 {
			break
		}
		if staged.Status != 1 {
			return fmt.Errorf("更新包暂存失败: %s", staged.Message)
		}
		if err := c.pause(staging); err != nil {
			return err
		}
	}
	if staged.Name != "nknguard" || !sameUpdateVersion(staged.Version, target) || !staged.Installed || staged.Kind != "path" {
		return errors.New("暂存更新包的应用、版本、类型或安装状态不匹配，已停止")
	}
	args := map[string]any{"appName": "nknguard", "updateVersion": strings.TrimPrefix(target, "v"), "packageType": staged.Kind, "language": "zh-CN"}
	var info struct {
		Wizard struct {
			Volume   int  `json:"installedVolumeID"`
			Required bool `json:"hasWizard"`
		} `json:"wizardInfo"`
	}
	if err := c.call(ctx, "update/info", args, &info); err != nil {
		return err
	}
	if info.Wizard.Volume <= 0 || info.Wizard.Required {
		return errors.New("升级需要向导或无法确认原存储卷，请从飞牛应用中心手动升级")
	}
	args["systemParameters"] = map[string]any{"agreedToProtocol": true, "installVolumeID": info.Wizard.Volume, "dataVolumeId": info.Wizard.Volume, "immediateStart": true}
	args["customParameters"] = []any{}
	var accepted struct {
		ID string `json:"taskId"`
	}
	if err := c.call(ctx, "update/task", args, &accepted); err != nil {
		return fmt.Errorf("提交升级后无法确认结果，请在飞牛应用中心查看，勿重复提交: %w", err)
	}
	if accepted.ID == "" {
		return errors.New("应用中心未返回升级任务 ID，请检查应用中心任务，勿重复提交")
	}
	record(accepted.ID)
	var outage time.Time
	for {
		var task struct {
			Status  int    `json:"status"`
			Message string `json:"message"`
			Output  string `json:"outputText"`
		}
		if err := c.call(ctx, "common/status", map[string]string{"taskId": accepted.ID}, &task); err != nil {
			if outage.IsZero() {
				outage = time.Now()
			}
			if ctx.Err() != nil || time.Since(outage) > 90*time.Second {
				return fmt.Errorf("升级结果尚未确认，请检查应用中心任务，勿重复提交: %w", err)
			}
			if err = c.pause(ctx); err != nil {
				return err
			}
			continue
		}
		outage = time.Time{}
		switch task.Status {
		case 1:
		case 2, 5:
			installed, e1 := c.installed()
			running, e2 := c.running(ctx)
			if e1 == nil && e2 == nil && sameUpdateVersion(installed, target) && sameUpdateVersion(running, target) {
				return nil
			}
			if task.Status == 5 {
				return fmt.Errorf("升级任务已不可查询，实际安装版本 %s，运行版本 %s，目标 %s；请检查应用中心", installed, running, target)
			}
			// A completed installer may precede the daemon's readiness by a few seconds.
		default:
			return fmt.Errorf("飞牛升级任务失败（状态 %d）: %s %s", task.Status, task.Message, task.Output)
		}
		if err := c.pause(ctx); err != nil {
			return fmt.Errorf("升级后版本核验超时，未确认已运行 %s: %w", target, err)
		}
	}
}
