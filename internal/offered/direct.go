package offered

import (
	"context"

	"github.com/scotthaleen/px/internal/direct"
)

type DirectChannel struct{ session *direct.Session }

func NewDirectChannel(session *direct.Session) *DirectChannel {
	return &DirectChannel{session: session}
}

func (c *DirectChannel) Send(ctx context.Context, message Message) error {
	return c.session.Send(ctx, direct.Message{Text: message.Text, Data: message.Data})
}

func (c *DirectChannel) Receive(ctx context.Context) (Message, error) {
	message, err := c.session.Receive(ctx)
	return Message{Text: message.Text, Data: message.Data}, err
}
