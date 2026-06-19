package utils

import (
	"runtime"
	"testing"
	"time"
)

// TestErrGroupGoroutineLeak reproduces the goroutine leak where WaitAndCollect
// starts a new collector goroutine via defer startCollecting(), but callers never
// reuse the errGroup — so the goroutine blocks on the channel forever.
func TestErrGroupGoroutineLeak(t *testing.T) {
	// Allow goroutines from other tests to settle
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	before := runtime.NumGoroutine()

	const iterations = 50
	for i := range iterations {
		eg := ErrGroup[int](5)
		eg.Go(func() (int, error) { return i, nil })
		_, err := eg.WaitAndCollect()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Give spawned goroutines a moment to settle
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()

	leaked := after - before
	if leaked > 2 { // allow small variance for test runtime goroutines
		t.Errorf("goroutine leak detected: started with %d, ended with %d (%d leaked after %d iterations)",
			before, after, leaked, iterations)
	}
}

func TestErrGroupCorrectness(t *testing.T) {
	eg := ErrGroup[int](5)
	for i := range 10 {
		i := i
		eg.Go(func() (int, error) { return i, nil })
	}
	results, err := eg.WaitAndCollect()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}
}

func TestErrGroupReuse(t *testing.T) {
	eg := ErrGroup[int](5)

	for batch := range 3 {
		for i := range 5 {
			eg.Go(func() (int, error) { return batch*10 + i, nil })
		}
		results, err := eg.WaitAndCollect()
		if err != nil {
			t.Fatalf("batch %d: %v", batch, err)
		}
		if len(results) != 5 {
			t.Errorf("batch %d: expected 5 results, got %d", batch, len(results))
		}
	}
}
