package cli

import "testing"

func TestReplayCommandExposesForwardAuthFlag(t *testing.T) {
	cmd := newReplayCommand()
	if cmd.Flags().Lookup("forward-auth") == nil {
		t.Fatalf("forward-auth flag missing")
	}
}
