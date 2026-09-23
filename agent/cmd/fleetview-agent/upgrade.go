package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"fleetview-agent/internal/client"
)

// maxAgentBinarySize is a generous bound on a stripped Go binary; real
// builds are a few tens of MiB.
const maxAgentBinarySize = 200 * 1024 * 1024

// stageUpgrade downloads and verifies a published agent binary. It
// deliberately returns the bytes rather than a temp file path: where the
// bytes get written (and how the swap is performed) is platform-specific
// and handled by applyUpgrade.
func stageUpgrade(ctx context.Context, api *client.Client, downloadURL, expectedSHA string) ([]byte, error) {
	data, err := api.DownloadFile(ctx, downloadURL, maxAgentBinarySize)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expectedSHA {
		return nil, fmt.Errorf("downloaded agent binary checksum mismatch")
	}
	return data, nil
}
