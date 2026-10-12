package releaseupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func downloadRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil {
		return errors.New("unsafe update redirect")
	}
	if !allowedURL(req.URL) && req.URL.Host != "release-assets.githubusercontent.com" && req.URL.Host != "objects.githubusercontent.com" {
		return errors.New("untrusted update redirect")
	}
	return nil
}

type progressWriter struct {
	writer       io.Writer
	count, total int64
	report       func(int64, int64)
}

func (p *progressWriter) Write(raw []byte) (int, error) {
	n, err := p.writer.Write(raw)
	p.count += int64(n)
	if p.report != nil {
		p.report(p.count, p.total)
	}
	return n, err
}

// DownloadBundle streams to a private temporary file. StageBundle must still
// verify its embedded catalogue signature, architecture and payload digest.
func DownloadBundle(ctx context.Context, client *http.Client, location, destination string, progress func(int64, int64)) (resultErr error) {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || u.User != nil || !allowedURL(u) {
		return errors.New("untrusted update URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute, CheckRedirect: downloadRedirect}
	} else {
		copy := *client
		copy.CheckRedirect = downloadRedirect
		client = &copy
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NKNGuard-update-download")
	if u.Host == "api.github.com" {
		req.Header.Set("Accept", "application/octet-stream")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub download returned %d", resp.StatusCode)
	}
	if resp.ContentLength > MaxPackageSize {
		return errors.New("update exceeds 160 MB")
	}
	part := destination + ".part"
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(part) }()
	p := &progressWriter{writer: f, total: resp.ContentLength, report: progress}
	n, err := io.Copy(p, io.LimitReader(resp.Body, MaxPackageSize+1))
	if err != nil {
		return err
	}
	if n == 0 || n > MaxPackageSize || (resp.ContentLength >= 0 && n != resp.ContentLength) {
		return errors.New("incomplete or oversized update")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(part, destination)
}
