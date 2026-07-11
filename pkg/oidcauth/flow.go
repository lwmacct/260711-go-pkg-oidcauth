package oidcauth

import (
	"context"
	"sync"
	"time"
)

type LoginFlow struct {
	State     string
	Nonce     string
	Verifier  string
	ExpiresAt time.Time
}

type FlowStore interface {
	Create(context.Context, LoginFlow) error
	Consume(context.Context, string) (LoginFlow, error)
}

type MemoryFlowStore struct {
	mu    sync.Mutex
	flows map[string]LoginFlow
	now   func() time.Time
}

func NewMemoryFlowStore() *MemoryFlowStore {
	return &MemoryFlowStore{flows: make(map[string]LoginFlow), now: time.Now}
}

func (s *MemoryFlowStore) Create(ctx context.Context, flow LoginFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if flow.State == "" || flow.ExpiresAt.IsZero() {
		return ErrInvalidFlow
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for state, item := range s.flows {
		if !item.ExpiresAt.After(now) {
			delete(s.flows, state)
		}
	}
	if _, exists := s.flows[flow.State]; exists {
		return ErrInvalidFlow
	}
	s.flows[flow.State] = flow
	return nil
}

func (s *MemoryFlowStore) Consume(ctx context.Context, state string) (LoginFlow, error) {
	if err := ctx.Err(); err != nil {
		return LoginFlow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	flow, ok := s.flows[state]
	delete(s.flows, state)
	if !ok {
		return LoginFlow{}, ErrInvalidFlow
	}
	if !flow.ExpiresAt.After(s.now()) {
		return LoginFlow{}, ErrExpiredFlow
	}
	return flow, nil
}
