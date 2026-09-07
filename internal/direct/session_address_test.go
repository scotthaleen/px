package direct

import "testing"

func TestCandidateAddressFormatsIPv4AndIPv6(t *testing.T) {
	for _, test := range []struct {
		host string
		want string
	}{
		{host: "192.0.2.1", want: "192.0.2.1:3478"},
		{host: "2001:db8::1", want: "[2001:db8::1]:3478"},
	} {
		if got := candidateAddress(test.host, 3478); got != test.want {
			t.Fatalf("candidateAddress(%q) = %q, want %q", test.host, got, test.want)
		}
	}
}
