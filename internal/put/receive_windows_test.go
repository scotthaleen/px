//go:build windows

package put

import (
	"context"
)

type windowsTestChannel struct{ send, receive chan Message }

func (c windowsTestChannel) Send(ctx context.Context, message Message) error {
	select {
	case c.send <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c windowsTestChannel) Receive(ctx context.Context) (Message, error) {
	select {
	case message := <-c.receive:
		return message, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}
}
