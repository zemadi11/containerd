package docker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/containerd/log"
)

type frisbeeTransfer struct{}

func (frisbeeTransfer) FetchBlob(ctx context.Context, digestStr, outPath string) error {
	cmdTmpl := os.Getenv("FRISBEE_CMD")
	if cmdTmpl == "" {
		return fmt.Errorf("FRISBEE_ENABLE=1 but FRISBEE_CMD not set")
	}

	cmdStr := strings.NewReplacer(
		"{DIGEST}", digestStr,
		"{OUT}", outPath,
	).Replace(cmdTmpl)

	log.G(ctx).Infof("FRISBEE-CMD start: %s", cmdStr)
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	out, err := cmd.CombinedOutput()
	log.G(ctx).Infof("FRISBEE-CMD done err=%v out=%s", err, string(out))
	if err != nil {
		return err
	}
	return nil
}

