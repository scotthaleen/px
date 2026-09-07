package put

import (
	"context"
	"errors"
	"testing"
)

func TestPutDestinationLockSerializesAcrossContextsAndRevisions(t *testing.T) {
	type authority struct {
		contextName  string
		rootRevision int64
		parent       string
	}
	home := authority{contextName: "home", rootRevision: 7, parent: "unix1:shared-parent"}
	work := authority{contextName: "work", rootRevision: 19, parent: "unix1:shared-parent"}
	lock := func(ctx context.Context, value authority, _ string) (func(), error) {
		// Context and revision deliberately do not participate in serialization.
		return lockPutDestination(ctx, value.parent)
	}
	release, err := lock(t.Context(), home, "Result")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := lock(ctx, work, "result"); !errors.Is(err, context.Canceled) {
		t.Fatalf("shared-parent case-alias lock error=%v", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	if _, err := lock(ctx, work, "another-file"); !errors.Is(err, context.Canceled) {
		t.Fatalf("shared-parent different-basename lock error=%v", err)
	}
	otherParent := work
	otherParent.parent = "unix1:other-parent"
	other, err := lock(t.Context(), otherParent, "result")
	if err != nil {
		t.Fatal(err)
	}
	other()
	release()
}
