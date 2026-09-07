package stunserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/pion/stun/v3"
	"github.com/scotthaleen/go-app"
)

const maxPacketBytes = 1200

type Server struct {
	address string
	logger  *slog.Logger
	mu      sync.Mutex
	conn    net.PacketConn
	wg      sync.WaitGroup
}

func New(address string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{address: address, logger: logger}
}

func (s *Server) Component() *app.Component {
	return app.NewComponent(app.WithName("STUN server"), app.WithOnStart(s.Start), app.WithOnStop(s.Stop))
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return errors.New("STUN server already started")
	}
	conn, err := net.ListenPacket("udp", s.address)
	if err != nil {
		return err
	}
	runtimeContext := app.MustGet[app.RuntimeContext](ctx)
	s.conn = conn
	s.wg.Add(1)
	go s.serve(runtimeContext, conn)
	s.logger.Info("STUN server listening", "address", conn.LocalAddr().String())
	return nil
}

func (s *Server) Stop(context.Context) error {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn == nil {
		return nil
	}
	err := conn.Close()
	s.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *Server) serve(ctx context.Context, conn net.PacketConn) {
	defer s.wg.Done()
	buffer := make([]byte, maxPacketBytes)
	for {
		count, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:count]...)}
		if request.Decode() != nil || request.Type != stun.BindingRequest {
			continue
		}
		udpAddress, ok := remote.(*net.UDPAddr)
		if !ok {
			continue
		}
		response, err := stun.Build(
			stun.NewTransactionIDSetter(request.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: udpAddress.IP, Port: udpAddress.Port},
			stun.Fingerprint,
		)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(response.Raw, remote)
	}
}
