package store

import "petris.dev/pds/internal/config"

// Commit is a synchronous convenience wrapper that pushes a complete in-memory
// payload, validating and placing it without the queue. It exists only for tests;
// production code uses the Pusher/Committer path, so keeping it here keeps it out of
// the shipped binaries.
func Commit(b config.Bucket, host string, data []byte) (string, error) {
	p, err := NewPusher(nil, b, host)
	if err != nil {
		return "", err
	}
	if _, err := p.WriteAt(data, 0); err != nil {
		_ = p.Abort()
		return "", err
	}
	tmpName, err := p.seal()
	if err != nil {
		return "", err
	}
	return finalize(b, tmpName)
}
