package adapterapi

import (
	"context"
	"errors"
	"sync"

	"github.com/scotthaleen/go-app"
)

const MaxDoorbellSubscribers = 64

type Broker struct {
	input       <-chan struct{}
	mu          sync.Mutex
	subscribers map[string]chan struct{}
	cancel      context.CancelFunc
	done        chan struct{}
}

func NewBroker(input <-chan struct{}) *Broker {
	return &Broker{input: input, subscribers: make(map[string]chan struct{})}
}

func (b *Broker) Component() *app.Component {
	return app.NewComponent(
		app.WithName("enrollment adapter doorbell broker"),
		app.WithOnStart(b.Start),
		app.WithOnStop(b.Stop),
	)
}

func (b *Broker) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		return errors.New("enrollment adapter doorbell broker already started")
	}
	runtimeContext := app.MustGet[app.RuntimeContext](ctx)
	runContext, cancel := context.WithCancel(runtimeContext)
	b.cancel = cancel
	b.done = make(chan struct{})
	go b.run(runContext)
	return nil
}

func (b *Broker) run(ctx context.Context) {
	defer close(b.done)
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-b.input:
			if !ok {
				return
			}
			b.fanout()
		}
	}
}

func (b *Broker) fanout() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, subscriber := range b.subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
			close(subscriber)
			delete(b.subscribers, id)
		}
	}
}

func (b *Broker) Subscribe(adapterID string) (<-chan struct{}, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel == nil {
		return nil, nil, errors.New("enrollment adapter doorbell broker is not running")
	}
	previous, replacing := b.subscribers[adapterID]
	if !replacing && len(b.subscribers) >= MaxDoorbellSubscribers {
		return nil, nil, errors.New("enrollment adapter doorbell capacity reached")
	}
	if replacing {
		close(previous)
	}
	subscriber := make(chan struct{}, 1)
	b.subscribers[adapterID] = subscriber
	var once sync.Once
	return subscriber, func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if current, exists := b.subscribers[adapterID]; exists && current == subscriber {
				close(current)
				delete(b.subscribers, adapterID)
			}
		})
	}, nil
}

func (b *Broker) Stop(ctx context.Context) error {
	b.mu.Lock()
	cancel, done := b.cancel, b.done
	b.cancel = nil
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, subscriber := range b.subscribers {
		close(subscriber)
		delete(b.subscribers, id)
	}
	return nil
}
