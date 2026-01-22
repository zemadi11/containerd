package docker

import (
	"context"

	"github.com/containerd/log"
)

func fetchViaFrisbee(ctx context.Context, digestStr string, cachePath string) error {
	// This is the central hook that other code calls on a cache MISS.
	// Route it to the native multicast implementation in transfer_frisbee.go.
	log.G(ctx).Infof("FRISBEE-DISPATCH digest=%s out=%s", digestStr, cachePath)
	return (frisbeeTransfer{}).FetchBlob(ctx, digestStr, cachePath)
}
