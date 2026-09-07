package recent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/scotthaleen/go-toolbelt/strictjson"
	"github.com/scotthaleen/px/internal/direct"
)

type Message struct {
	Text bool
	Data []byte
}

type Channel interface {
	Send(context.Context, Message) error
	Receive(context.Context) (Message, error)
}

type request struct {
	Version int `json:"version"`
	Limit   int `json:"limit"`
}

type acknowledgement struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
}

func Request(ctx context.Context, channel Channel, limit int, expectedReporter Reporter, requesterDeviceID string) (Snapshot, error) {
	if limit <= 0 || limit > MaxLimit {
		return Snapshot{}, LimitError(limit)
	}
	if err := send(ctx, channel, request{Version: Version, Limit: limit}); err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := receive(ctx, channel, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("peer sent an invalid recent observation snapshot: %w", err)
	}
	if err := ValidateSnapshot(snapshot, true); err != nil {
		return Snapshot{}, fmt.Errorf("peer sent an invalid recent observation snapshot: %w", err)
	}
	if snapshot.Reporter != expectedReporter || len(snapshot.Observations) > limit {
		return Snapshot{}, errors.New("peer sent an incorrectly bound recent observation snapshot")
	}
	for _, observation := range snapshot.Observations {
		if observation.PeerDeviceID != requesterDeviceID {
			return Snapshot{}, errors.New("peer sent an incorrectly bound recent observation snapshot")
		}
	}
	if err := send(ctx, channel, acknowledgement{Version: Version, Type: "ack"}); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func Serve(ctx context.Context, channel Channel, reporter Reporter, peerDeviceID string, list func(context.Context, string, int) ([]Observation, error)) error {
	return ServeWithDeadline(ctx, channel, reporter, peerDeviceID, list, InboundDeadline)
}

func ServeWithDeadline(ctx context.Context, channel Channel, reporter Reporter, peerDeviceID string, list func(context.Context, string, int) ([]Observation, error), deadline time.Duration) error {
	if deadline <= 0 {
		return ErrProtocolTimeout
	}
	requestContext, cancelRequest := context.WithTimeout(ctx, deadline)
	var value request
	err := receive(requestContext, channel, &value)
	cancelRequest()
	if protocolTimedOut(ctx, err) {
		return ErrProtocolTimeout
	}
	if err != nil || value.Version != Version || value.Limit <= 0 || value.Limit > MaxLimit || reporter.Context != "" || peerDeviceID == "" {
		return errors.New("invalid recent observation request")
	}
	observations, err := list(ctx, peerDeviceID, value.Limit)
	if err != nil {
		return err
	}
	for index := range observations {
		observations[index].Context = ""
		observations[index].Sequence = 0
	}
	snapshot := Snapshot{Version: Version, Description: Description, Reporter: reporter, Observations: observations}
	if ValidateSnapshot(snapshot, true) != nil {
		return ErrCorrupt
	}
	if err := send(ctx, channel, snapshot); err != nil {
		return err
	}
	ackContext, cancelAck := context.WithTimeout(ctx, deadline)
	var ack acknowledgement
	err = receive(ackContext, channel, &ack)
	cancelAck()
	if protocolTimedOut(ctx, err) {
		return ErrProtocolTimeout
	}
	if err != nil || ack.Version != Version || ack.Type != "ack" {
		return errors.New("invalid recent observation acknowledgement")
	}
	return nil
}

func protocolTimedOut(parent context.Context, err error) bool {
	return parent.Err() == nil && errors.Is(err, context.DeadlineExceeded)
}

func send(ctx context.Context, channel Channel, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > MaxMessageBytes {
		return errors.New("recent observation message exceeds bounds")
	}
	return channel.Send(ctx, Message{Text: true, Data: data})
}

func receive(ctx context.Context, channel Channel, output any) error {
	message, err := channel.Receive(ctx)
	if err != nil {
		return err
	}
	if !message.Text || len(message.Data) == 0 || len(message.Data) > MaxMessageBytes {
		return errors.New("invalid recent observation message")
	}
	return DecodeStrict(message.Data, output)
}

func DecodeStrict(data []byte, output any) error {
	if len(data) == 0 || len(data) > MaxMessageBytes {
		return errors.New("invalid recent observation message")
	}
	if err := strictjson.Decode(data, output, strictjson.DisallowUnknownFields()); err != nil {
		return errors.New("invalid recent observation message")
	}
	return nil
}

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
