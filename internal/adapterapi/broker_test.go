package adapterapi

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/scotthaleen/go-app"
)

func TestBrokerLifecycleFanoutAndStalledIsolation(t *testing.T) {
	input := make(chan struct{}, MaxDoorbellSubscribers)
	broker := NewBroker(input)
	ctx, cancel := context.WithCancel(context.Background())
	application := app.New(ctx, app.WithSignalHandling(false), app.WithSequentialStartup(app.Managed(broker)))
	done := make(chan error, 1)
	go func() { done <- application.Run() }()

	var fast, stalled <-chan struct{}
	var cancelFast, cancelStalled func()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var err error
		fast, cancelFast, err = broker.Subscribe("fast")
		if err == nil {
			stalled, cancelStalled, err = broker.Subscribe("stalled")
			if err != nil {
				cancelFast()
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	if fast == nil || stalled == nil {
		t.Fatal("broker did not start")
	}
	defer cancelFast()
	defer cancelStalled()
	replacement, cancelReplacement, err := broker.Subscribe("fast")
	if err != nil {
		t.Fatal(err)
	}
	defer cancelReplacement()
	select {
	case _, ok := <-fast:
		if ok {
			t.Fatal("replaced subscriber received a marker")
		}
	case <-time.After(time.Second):
		t.Fatal("replaced subscriber was not closed")
	}
	fast, cancelFast = replacement, cancelReplacement

	input <- struct{}{}
	select {
	case <-fast:
	case <-time.After(time.Second):
		t.Fatal("fast subscriber missed first marker")
	}
	input <- struct{}{}
	select {
	case <-fast:
	case <-time.After(time.Second):
		t.Fatal("fast subscriber missed second marker")
	}
	select {
	case _, ok := <-stalled:
		if !ok {
			t.Fatal("stalled subscriber closed before its queued marker was observed")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled subscriber had no queued marker")
	}
	select {
	case _, ok := <-stalled:
		if ok {
			t.Fatal("stalled subscriber was not disconnected on overflow")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled subscriber remained connected")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop")
	}
	if err := broker.Stop(context.Background()); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
}

func TestBrokerCancelNotifyRace(t *testing.T) {
	broker := NewBroker(nil)
	broker.cancel = func() {}
	var wait sync.WaitGroup
	for index := range MaxDoorbellSubscribers {
		id := string(rune(index + 1))
		_, cancel, err := broker.Subscribe(id)
		if err != nil {
			t.Fatal(err)
		}
		wait.Add(2)
		go func() { defer wait.Done(); broker.fanout() }()
		go func() { defer wait.Done(); cancel() }()
	}
	wait.Wait()
	if err := broker.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
