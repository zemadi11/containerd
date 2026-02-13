package docker

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
	"strconv"
	"strings"
	"time"

	"github.com/containerd/log"
)

type frisbeeTransfer struct{}
var _ = (frisbeeTransfer{}).FetchBlob

type controlResp struct {
	Mcast string `json:"mcast"`
	Port  string `json:"port"`
	Iface string `json:"iface"`
	Hex   string `json:"hex"`
}

func (frisbeeTransfer) FetchBlob(ctx context.Context, digestStr, outPath string) error {
	hex64 := strings.TrimPrefix(digestStr, "sha256:")
	if len(hex64) != 64 {
		return fmt.Errorf("frisbee: unexpected digest %q", digestStr)
	}

	ctrlURL := os.Getenv("FRISBEE_CONTROL_URL") // e.g. http://10.10.1.1:9876
	if ctrlURL == "" {
		return fmt.Errorf("frisbee: FRISBEE_CONTROL_URL not set")
	}

	cr, err := startServer(ctx, ctrlURL, hex64)
	if err != nil {
		return err
	}

	ifIP := os.Getenv("FRISBEE_IFIP") // client IP on 10.10.1.0/24, e.g. 10.10.1.2
	if ifIP == "" {
		return fmt.Errorf("frisbee: FRISBEE_IFIP not set (example: 10.10.1.2)")
	}

	frisbeeBin := getenv("FRISBEE_BIN", "/usr/local/bin/frisbee")
	timeout := getenvDuration("FRISBEE_TIMEOUT", 180*time.Second)

	// frisbee -k expects KB. "0" may be treated as invalid/clamped.
	// Default 256MB socket buffer (in KB).
	sockbufKB := getenvInt("FRISBEE_SOCKBUF_KB", 262144)
	if sockbufKB < 1024 {
		sockbufKB = 1024
	}

	// frisbee -M is total buffering in MB. Default 4GB.
	totalBufMB := getenvInt("FRISBEE_TOTALBUF_MB", 4096)
	if totalBufMB < 64 {
		totalBufMB = 64
	}

	// Optional booleans
	useInOrder := getenvBool("FRISBEE_INORDER", true) // adds -O if true
	useNoDecomp := getenvBool("FRISBEE_NODECOMP", true) // adds -N if true

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.tmp.%d.%d", outPath, time.Now().UnixNano(), rand.Intn(1_000_000))
	_ = os.Remove(tmp)

	args := []string{}
	if useNoDecomp {
		args = append(args, "-N")
	}
	if useInOrder {
		args = append(args, "-O")
	}
	args = append(args,
		"-k", strconv.Itoa(sockbufKB),
		"-M", strconv.Itoa(totalBufMB),
		"-m", cr.Mcast,
		"-p", cr.Port,
		"-i", ifIP,
		tmp,
	)

	log.G(ctx).Infof(
		"FRISBEE-MCAST-START hex=%s mcast=%s port=%s ifip=%s tmp=%s sockbuf_kb=%d totalbuf_mb=%d inorder=%v nodecomp=%v",
		hex64, cr.Mcast, cr.Port, ifIP, tmp, sockbufKB, totalBufMB, useInOrder, useNoDecomp,
	)
	log.G(ctx).Infof("FRISBEE-CMD: %s %s", frisbeeBin, strings.Join(args, " "))

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

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

func getenvInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getenvBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		return def
	}
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
