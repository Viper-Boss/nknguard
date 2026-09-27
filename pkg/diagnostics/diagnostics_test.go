package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	inputs := []string{
		"PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
		"join_secret: abcdefghijklmnopqrstuvwxyz",
		"wallet_seed=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"token: Bearer.eyJhbGciOi",
	}
	for _, input := range inputs {
		out := Redact(input)
		if !strings.Contains(out, "[redacted]") {
			t.Errorf("not redacted: %q -> %q", input, out)
		}
	}
	if Redact("peer=nkg_abc state=DIRECT") != "peer=nkg_abc state=DIRECT" {
		t.Fatal("redactor mangled ordinary text")
	}
}

func TestBundleIsRedacted(t *testing.T) {
	var buffer bytes.Buffer
	err := WriteBundle(&buffer, BundleInput{
		Config: "device:\n  name: x\n",
		Logs:   []string{"debug private_key=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="},
	})
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(archive)
		if strings.Contains(string(body), "yAnz5TF") {
			t.Fatalf("%s leaked a key", header.Name)
		}
	}
}
