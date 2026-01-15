package docker

import (
	"context"
	"fmt"
	"os"
)

type blobTransfer interface {
	FetchBlob(ctx context.Context, digestStr, outPath string) error
}

func newBlobTransfer() blobTransfer {
	if os.Getenv("FRISBEE_ENABLE") == "1" {
		return frisbeeTransfer{}
	}
	return httpTransfer{} // no-op in your case; you’ll fall through to existing code anyway
}

type httpTransfer struct{}
func (httpTransfer) FetchBlob(ctx context.Context, digestStr, outPath string) error {
	return fmt.Errorf("httpTransfer should not be called; fall through to existing fetcher")
}

