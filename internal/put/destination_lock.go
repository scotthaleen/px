package put

import (
	"context"
	"sync"
)

var putDestinationLocks = struct {
	sync.Mutex
	entries map[string]*destinationLock
}{entries: make(map[string]*destinationLock)}

type destinationLock struct {
	gate chan struct{}
	refs int
}

func lockPutDestination(ctx context.Context, parentIdentity string) (func(), error) {
	key := parentIdentity
	putDestinationLocks.Lock()
	entry := putDestinationLocks.entries[key]
	if entry == nil {
		entry = &destinationLock{gate: make(chan struct{}, 1)}
		entry.gate <- struct{}{}
		putDestinationLocks.entries[key] = entry
	}
	entry.refs++
	putDestinationLocks.Unlock()

	select {
	case <-ctx.Done():
		putDestinationLocks.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(putDestinationLocks.entries, key)
		}
		putDestinationLocks.Unlock()
		return nil, ctx.Err()
	case <-entry.gate:
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			putDestinationLocks.Lock()
			entry.refs--
			entry.gate <- struct{}{}
			if entry.refs == 0 {
				delete(putDestinationLocks.entries, key)
			}
			putDestinationLocks.Unlock()
		})
	}, nil
}
