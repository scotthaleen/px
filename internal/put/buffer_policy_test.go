package put

import "testing"

func TestDirectSendBufferPolicy(t *testing.T) {
	if MaxBufferedBytes != 4<<20 {
		t.Fatalf("max buffered bytes = %d", MaxBufferedBytes)
	}
}
