package composition

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerComponentFailureDoesNotCancelSibling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	var sibling atomic.Int32
	done := make(chan struct{}, 2)
	go func() {
		superviseWorkerComponent(ctx, "query", func(context.Context) error { attempts.Add(1); return errors.New("owned fixture unavailable") })
		done <- struct{}{}
	}()
	go func() {
		superviseWorkerComponent(ctx, "other", func(c context.Context) error {
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-c.Done():
					return nil
				case <-tick.C:
					sibling.Add(1)
				}
			}
		})
		done <- struct{}{}
	}()
	deadline := time.After(2 * time.Second)
	for attempts.Load() < 2 || sibling.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("failed component cancelled or blocked sibling")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("component cancellation unbounded")
		}
	}
}
