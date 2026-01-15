package docker

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"

    "github.com/containerd/log"
)
func fetchViaFrisbee(ctx context.Context, digestStr string, cachePath string) error {
    // Ensure parent dir exists
    if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
        return err
    }

    cmdStr := os.Getenv("FRISBEE_CMD")
    if cmdStr == "" {
        return fmt.Errorf("FRISBEE_ENABLE=1 but FRISBEE_CMD not set")
    }

    // Run command (your Frisbee client command should write the blob to cachePath)
    cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
    out, err := cmd.CombinedOutput()
    log.G(ctx).Infof("FRISBEE-CMD out=%s err=%v", string(out), err)
    if err != nil {
        return err
    }

    // Wait for file to appear
    deadline := time.Now().Add(60 * time.Second)
    for time.Now().Before(deadline) {
        if _, err := os.Stat(cachePath); err == nil {
            break
        }
        time.Sleep(200 * time.Millisecond)
    }
    if _, err := os.Stat(cachePath); err != nil {
        return fmt.Errorf("frisbee did not produce cache file: %s", cachePath)
    }

    // Verify sha256 matches expected digest (important)
    // digestStr is like "sha256:abcd..."
    parts := strings.SplitN(digestStr, ":", 2)
    if len(parts) != 2 || parts[0] != "sha256" {
        return fmt.Errorf("unsupported digest: %s", digestStr)
    }
    expectedHex := parts[1]

    f, err := os.Open(cachePath)
    if err != nil {
        return err
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return err
    }
    gotHex := hex.EncodeToString(h.Sum(nil))

    if gotHex != expectedHex {
        return fmt.Errorf("sha256 mismatch for %s: expected=%s got=%s", cachePath, expectedHex, gotHex)
    }

    return nil
}
