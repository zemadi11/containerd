package frisbeecache

import (
    "bytes"
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"

    "github.com/containerd/containerd/v2/core/images"
    ocispec "github.com/opencontainers/image-spec/specs-go/v1"
    "github.com/containerd/log"
)

const (
    defaultRoot = "/var/lib/frisbee-blobs"
)

// TryOpenOrFetch tries to serve a layer blob from local cache.
// If missing, runs: frisbee-fetch <hex> <path> and then opens it.
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
    algo, hex := parts[0], parts[1]
    if algo != "sha256" {
        // if you only want sha256
        return nil, false, nil
    }

    path := filepath.Join(defaultRoot, algo, hex)

    // HIT
    if f, e := os.Open(path); e == nil {
        log.G(ctx).Infof("FRISBEE-HIT path=%s", path)
        return f, true, nil
    }

    log.G(ctx).Infof("FRISBEE-MISS path=%s", path)

    // Ensure dir exists
    _ = os.MkdirAll(filepath.Dir(path), 0755)

    // BLOCK until helper completes
    if e := runHelper(ctx, hex, path); e != nil {
        log.G(ctx).Warnf("FRISBEE-FETCH-FAIL hex=%s path=%s err=%v", hex, path, e)
        return nil, true, e
    }

    // Open after fetch
    f, e := os.Open(path)
    if e != nil {
        return nil, true, fmt.Errorf("frisbee-fetch ok but open failed: %w", e)
    }
    log.G(ctx).Infof("FRISBEE-HIT-AFTER-FETCH path=%s", path)
    return f, true, nil
}

func runHelper(ctx context.Context, hex, outPath string) error {
    tctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(tctx, "frisbee-fetch", hex, outPath)

    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out

    if err := cmd.Run(); err != nil {
        return fmt.Errorf("frisbee-fetch failed: %w; output=%s",
            err, strings.TrimSpace(out.String()))
    }
    log.G(ctx).Infof("FRISBEE-FETCH-OK hex=%s path=%s output=%s",
        hex, outPath, strings.TrimSpace(out.String()))
    return nil
}

