package externalcas

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDynamicSem_ResizeDuringInFlight(t *testing.T) {
	s := newDynamicSem(1)
	if s.capacity() != 1 {
		t.Fatalf("initial capacity = %d, want 1", s.capacity())
	}

	ctx := context.Background()
	ch1, err := s.acquire(ctx)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}

	// Resize while a slot is held: the second acquire must observe the new,
	// larger channel and succeed immediately.
	s.resize(3)
	if s.capacity() != 3 {
		t.Fatalf("resized capacity = %d, want 3", s.capacity())
	}
	ch2, err := s.acquire(ctx)
	if err != nil {
		t.Fatalf("acquire 2 after resize: %v", err)
	}

	// Releasing the old token drains the OLD channel — no corruption.
	s.release(ch1)
	s.release(ch2)

	// Capacity 1 again: second acquire blocks until release.
	s.resize(1)
	a, _ := s.acquire(ctx)
	done := make(chan struct{})
	go func() {
		b, err := s.acquire(ctx)
		if err == nil {
			s.release(b)
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("acquire on full capacity-1 semaphore should block")
	case <-time.After(50 * time.Millisecond):
	}
	s.release(a)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("acquire never unblocked after release")
	}
}

func TestRestartDashboardListener_SwapsAddress(t *testing.T) {
	oldMux := dashMux
	dashMux = http.NewServeMux()
	dashMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok")) //nolint:noctx
	})
	t.Cleanup(func() {
		dashSrvMu.Lock()
		srv := dashSrv
		dashSrv = nil
		dashSrvMu.Unlock()
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}
		dashMux = oldMux
	})

	// First bind on an ephemeral port.
	if err := restartDashboardListener(dashboard{Bind: "127.0.0.1"}); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	// Rebind to a concrete port and verify it serves.
	if err := restartDashboardListener(dashboard{Port: 18443, Bind: "127.0.0.1"}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	var err error
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://127.0.0.1:18443/") //nolint:noctx
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("listener after rebind never served: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestSettingsClassificationAllApplied(t *testing.T) {
	// Previously restart-required keys must now classify as applied.
	setupSettingsEnv(t)
	applied, restart, err := saveSettings([]byte(`{
		"authority": {"config": {"http01_port": 8081, "tlsalpn01_port": 444, "max_concurrent_requests": 2}},
		"dashboard": {"port": 8444, "bind": "127.0.0.1"}
	}`))
	if err != nil {
		t.Fatalf("saveSettings: %v", err)
	}
	if len(restart) != 0 {
		t.Errorf("restart_required = %v, want empty (all settings hot-apply)", restart)
	}
	joined := strings.Join(applied, ",")
	for _, want := range []string{"http01_port", "tlsalpn01_port", "max_concurrent_requests", "dashboard.port", "dashboard.bind"} {
		if !strings.Contains(joined, want) {
			t.Errorf("applied list missing %s: %v", want, applied)
		}
	}
}
