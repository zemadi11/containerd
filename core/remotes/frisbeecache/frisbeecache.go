package frisbeecache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	defaultRoot = "/var/lib/frisbee-blobs"
)

type controlResp struct {
	Mcast string `json:"mcast"`
	Port  string `json:"port"`
	Iface string `json:"iface"`
	Hex   string `json:"hex"`
}

// TryOpenOrFetch tries to serve a layer blob from local cache.
// If missing, it fetches via Frisbee multicast and then opens it.
// ok==false means "ignore me and continue normal fetch path".
func TryOpenOrFetch(ctx context.Context, desc ocispec.Descriptor) (rc *os.File, ok bool, err error) {
	// Gate: only layers
	if !images.IsLayerType(desc.MediaType) {
		return nil, false, nil
	}

	// Gate: allow turning off without code changes
	if os.Getenv("FRISBEE_CACHE") == "0" {
		return nil, false, nil
	}

	// parse sha256:<hex>
	parts := strings.SplitN(desc.Digest.String(), ":", 2)
	if len(parts) != 2 {
		return nil, false, nil
	}
	algo, hex64 := parts[0], parts[1]
	if algo != "sha256" {
		return nil, false, nil
	}
	if len(hex64) != 64 {
		return nil, false, nil
	}

	path := filepath.Join(defaultRoot, algo, hex64)

	// HIT
	if f, e := os.Open(path); e == nil {
		log.G(ctx).Infof("FRISBEE-HIT path=%s", path)
		return f, true, nil
	}

	log.G(ctx).Infof("FRISBEE-MISS path=%s", path)

	// Ensure dir exists
	_ = os.MkdirAll(filepath.Dir(path), 0755)

	// BLOCK until fetch completes
	if e := runHelper(ctx, hex64, path); e != nil {
		log.G(ctx).Warnf("FRISBEE-FETCH-FAIL hex=%s path=%s err=%v", hex64, path, e)
		return nil, true, e
	}

	// Open after fetch
	f, e := os.Open(path)
	if e != nil {
		return nil, true, fmt.Errorf("frisbee fetch ok but open failed: %w", e)
	}
	log.G(ctx).Infof("FRISBEE-HIT-AFTER-FETCH path=%s", path)
	return f, true, nil
}

func runHelper(ctx context.Context, hex64, outPath string) error {
	// Keep the existing long timeout behavior (fetch+verify may take time).
	tctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Control plane: ask node0 to start frisbeed for this digest
	ctrlURL := os.Getenv("FRISBEE_CONTROL_URL") // e.g. http://10.10.1.1:9876
	if ctrlURL == "" {
		return fmt.Errorf("frisbee: FRISBEE_CONTROL_URL not set")
	}
	cr, err := startServer(tctx, ctrlURL, hex64)
	if err != nil {
		return err
	}

	// Data plane: receive via multicast on this node’s interface IP
	ifIP := os.Getenv("FRISBEE_IFIP") // e.g. 10.10.1.2
	if ifIP == "" {
		return fmt.Errorf("frisbee: FRISBEE_IFIP not set (example: 10.10.1.2)")
	}

	frisbeeBin := getenv("FRISBEE_BIN", "/usr/local/bin/frisbee")
	timeout := getenvDuration("FRISBEE_TIMEOUT", 120*time.Second)

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.tmp.%d.%d", outPath, time.Now().UnixNano(), rand.Intn(1_000_000))
	_ = os.Remove(tmp)

	// Real multicast receive (based on your `frisbee -h`)
	args := []string{"-N", "-m", cr.Mcast, "-p", cr.Port, "-i", ifIP, tmp}

	log.G(ctx).Infof("FRISBEE-MCAST-START hex=%s mcast=%s port=%s ifip=%s tmp=%s",
		hex64, cr.Mcast, cr.Port, ifIP, tmp)

	cctx, ccancel := context.WithTimeout(tctx, timeout)
	defer ccancel()

	cmd := exec.CommandContext(cctx, frisbeeBin, args...)
	out, runErr := cmd.CombinedOutput()

	if cctx.Err() == context.DeadlineExceeded {
		_ = os.Remove(tmp)
		return fmt.Errorf("frisbee: timeout after %s (out=%s)", timeout, string(out))
	}
	if runErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("frisbee: client failed: %v (out=%s)", runErr, string(out))
	}

	if err := verifySHA256(tmp, hex64); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	log.G(ctx).Infof("FRISBEE-MCAST-OK hex=%s out=%s", hex64, outPath)
	return nil
}

func startServer(ctx context.Context, base, hex64 string) (*controlResp, error) {
	u := strings.TrimRight(base, "/") + "/start?hex=" + hex64
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("frisbee: control request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("frisbee: control status=%d body=%s", resp.StatusCode, string(b))
	}

	var cr controlResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("frisbee: control decode failed: %w", err)
	}
	if cr.Mcast == "" || cr.Port == "" {
		return nil, fmt.Errorf("frisbee: bad control response: %+v", cr)
	}
	return &cr, nil
}

func verifySHA256(path, wantHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantHex {
		return fmt.Errorf("frisbee: sha256 mismatch: got=%s want=%s", got, wantHex)
	}
	return nil
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func getenvDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
