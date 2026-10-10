package main

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestSelfTest starts the whole portal + both MCP servers on a throwaway port and a temp data directory,
// then runs every scripted check through real OAuth and MCP. `go test ./...` fails if any check fails.
func TestSelfTest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	srv := &Server{s: NewStore(filepath.Join(dir, "data.json")), adminPassword: "test-password", adminSess: map[string]time.Time{}}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()
	t.Setenv("PUBLIC_BASE_URL", ts.URL)
	srv.localBase = ts.URL
	run := srv.runSelfTest(context.Background())
	for _, c := range run.Checks {
		if !c.Pass {
			t.Errorf("FAIL [%s] %s: %s", c.Group, c.Name, c.Detail)
		}
	}
	t.Logf("%d/%d checks passed in %d ms", run.Passed, run.Total, run.DurationMS)
	if run.Total < 50 {
		t.Fatalf("expected the full suite, got only %d checks", run.Total)
	}
}
