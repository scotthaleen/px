//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type stateFileLock struct {
	file *os.File
}

func acquireStateFileLock(statePath string, timeout time.Duration) (*stateFileLock, error) {
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &stateFileLock{file: file}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			file.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, errors.New("adapter fixture state is busy")
			}
			return nil, fmt.Errorf("lock adapter fixture state: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (l *stateFileLock) Close() error {
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
