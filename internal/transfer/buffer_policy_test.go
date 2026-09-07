package transfer

import "testing"

func TestDirectSendBufferPolicy(t *testing.T) {
	if DefaultBufferedBytes != 4<<20 {
		t.Fatalf("default buffered bytes = %d", DefaultBufferedBytes)
	}
}
