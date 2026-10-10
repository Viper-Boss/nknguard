package main

import (
	"context"
	"encoding/json"
	"io"
	"runtime"
	"time"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
)

func cmdUpdateCheck(out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	kind := "linux"
	if runtime.GOOS == "windows" {
		kind = "windows-installer"
	}
	r, err := releaseupdate.Check(ctx, app.Version, kind, runtime.GOARCH)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(r)
}
