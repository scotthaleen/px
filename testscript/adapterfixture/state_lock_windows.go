package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

type stateFileLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireStateFileLock(statePath string, timeout time.Duration) (*stateFileLock, error) {
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	lock := &stateFileLock{file: file}
	deadline := time.Now().Add(timeout)
	for {
		err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) || time.Now().After(deadline) {
			file.Close()
			if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
				return nil, errors.New("adapter fixture state is busy")
			}
			return nil, fmt.Errorf("lock adapter fixture state: %w", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (l *stateFileLock) Close() error {
	unlockErr := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
