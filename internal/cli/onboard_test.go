package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestOnboardAllowPutPreservesChangedSemantics(t *testing.T) {
	for _, test := range []struct {
		name, value string
		set, want   bool
	}{
		{name: "omitted"},
		{name: "explicit true", value: "true", set: true, want: true},
		{name: "explicit false", value: "false", set: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := onboardOptions{}
			command := &cobra.Command{}
			command.Flags().BoolVar(&options.allowPut, "allow-put", false, "")
			if test.set {
				if err := command.Flags().Set("allow-put", test.value); err != nil {
					t.Fatal(err)
				}
			}
			captureOnboardPutFlag(command, &options)
			if options.allowPutSet != test.want {
				t.Fatalf("allowPutSet=%t want=%t", options.allowPutSet, test.want)
			}
		})
	}
}
