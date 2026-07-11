package oidcauth

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryFlowStoreConsumesOnce(t *testing.T) {
	now := time.Now()
	store := NewMemoryFlowStore()
	store.now = func() time.Time { return now }
	flow := LoginFlow{State: "state", ExpiresAt: now.Add(time.Minute)}
	if err := store.Create(t.Context(), flow); err != nil {
		t.Fatalf("create flow: %v", err)
	}
	if _, err := store.Consume(t.Context(), flow.State); err != nil {
		t.Fatalf("consume flow: %v", err)
	}
	if _, err := store.Consume(t.Context(), flow.State); !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("expected consumed flow to be invalid, got %v", err)
	}
}

func TestMemoryFlowStoreConcurrentConsumeHasOneWinner(t *testing.T) {
	store := NewMemoryFlowStore()
	if err := store.Create(t.Context(), LoginFlow{State: "state", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("create flow: %v", err)
	}
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			if _, err := store.Consume(t.Context(), "state"); err == nil {
				winners.Add(1)
			}
		})
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("expected one winner, got %d", winners.Load())
	}
}

func TestMemoryFlowStoreRejectsExpiredFlow(t *testing.T) {
	now := time.Now()
	store := NewMemoryFlowStore()
	store.now = func() time.Time { return now }
	if err := store.Create(t.Context(), LoginFlow{State: "state", ExpiresAt: now.Add(time.Second)}); err != nil {
		t.Fatalf("create flow: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := store.Consume(t.Context(), "state"); !errors.Is(err, ErrExpiredFlow) {
		t.Fatalf("expected expired flow, got %v", err)
	}
}
