package docker

import (
	"bytes"
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

	// MATCH ADVISOR CLIENT FLAGS:
	// client: frisbee -M 256 -k 1024 -N -i 10.10.1.2 -m 239.192.0.1 -p 6001 /dev/null
	// NOTE: containerd needs a real output file (blob), so we cannot use /dev/null in normal operation.
	// We'll still use the exact flags, but write to a temp file -> verify -> rename.

	sockbufKB := getenvInt("FRISBEE_SOCKBUF_KB", 1024)   // -k 1024
	totalBufMB := getenvInt("FRISBEE_TOTALBUF_MB", 256)  // -M 256
	useNoDecomp := getenvBool("FRISBEE_NODECOMP", true)  // -N
	useInOrder := getenvBool("FRISBEE_INORDER", false)   // advisor does NOT use -O
	benchNull := getenvBool("FRISBEE_BENCH_NULL", false) // if true, use /dev/null and skip verify/rename

	// Hard clamp to keep arguments sane
	if sockbufKB < 1 {
		sockbufKB = 1024
	}
	if totalBufMB < 1 {
		totalBufMB = 256
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.tmp.%d.%d", outPath, time.Now().UnixNano(), rand.Intn(1_000_000))
	_ = os.Remove(tmp)

	// Choose output path for frisbee:
	outArg := tmp
	if benchNull {
		outArg = "/dev/null"
	}

	args := []string{}
	if useNoDecomp {
		args = append(args, "-N")
	}
	if useInOrder {
		args = append(args, "-O")
	}
	args = append(args,
		"-M", strconv.Itoa(totalBufMB),
		"-k", strconv.Itoa(sockbufKB),
		"-i", ifIP,
		"-m", cr.Mcast,
		"-p", cr.Port,
		outArg,
	)

	// Client log file (stdout/stderr from frisbee binary)
	clientLogDir := getenv("FRISBEE_CLIENT_LOG_DIR", "/tmp")
	_ = os.MkdirAll(clientLogDir, 0755)
	clientLogPath := filepath.Join(clientLogDir, fmt.Sprintf("frisbee_client_%s_p%s.log", hex64, cr.Port))

	log.G(ctx).Infof(
		"FRISBEE-MCAST-START hex=%s mcast=%s port=%s ifip=%s out=%s sockbuf_kb=%d totalbuf_mb=%d inorder=%v nodecomp=%v bench_null=%v client_log=%s",
		hex64, cr.Mcast, cr.Port, ifIP, outArg, sockbufKB, totalBufMB, useInOrder, useNoDecomp, benchNull, clientLogPath,
	)
	log.G(ctx).Infof("FRISBEE-CMD: %s %s", frisbeeBin, strings.Join(args, " "))

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, frisbeeBin, args...)

	// Write stdout/stderr to BOTH memory and file
	var buf bytes.Buffer
	logf, err := os.OpenFile(clientLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		// still run; just won't have a file
		log.G(ctx).Warnf("FRISBEE: could not open client log %s: %v", clientLogPath, err)
		cmd.Stdout = &buf
		cmd.Stderr = &buf
	} else {
		defer logf.Close()
		mw := io.MultiWriter(&buf, logf)
		cmd.Stdout = mw
		cmd.Stderr = mw
	}

	runErr := cmd.Run()
	out := buf.Bytes()

	if cctx.Err() == context.DeadlineExceeded {
		_ = os.Remove(tmp)
		return fmt.Errorf("frisbee: timeout after %s (client_log=%s)", timeout, clientLogPath)
	}
	if runErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("frisbee: client failed: %v (client_log=%s out=%s)", runErr, clientLogPath, string(out))
	}

	// Bench mode: mimic /dev/null behavior; containerd integration should NOT use this.
	if benchNull {
		log.G(ctx).Infof("FRISBEE-MCAST-OK (bench null) hex=%s", hex64)
		return nil
	}

	if err := verifySHA256(tmp, hex64); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	log.G(ctx).Infof("FRISBEE-MCAST-OK hex=%s out=%s client_log=%s", hex64, outPath, clientLogPath)
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
