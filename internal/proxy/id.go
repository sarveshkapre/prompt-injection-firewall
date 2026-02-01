package proxy

import (
	"crypto/rand"
	"encoding/hex"
)

func newID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
