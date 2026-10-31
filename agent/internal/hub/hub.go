// Package hub is a tiny publish/subscribe broker for live events (SSE).
package hub

import (
	"encoding/json"
	"sync"
)

// Event is a message pushed to dashboards.
type Event struct {
	Type string
	Data []byte
}

// Hub fans events out to subscribers.
type Hub struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

// New creates a hub.
func New() *Hub { return &Hub{subs: map[chan Event]struct{}{}} }

// Subscribe returns a channel of events and a cancel func.
func (h *Hub) Subscribe() (chan Event, func()) {
	ch := make(chan Event, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Subscribers returns the number of connected clients.
func (h *Hub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// Publish marshals v and sends it to all subscribers (dropping for slow ones).
func (h *Hub) Publish(typ string, v any) {
	h.mu.RLock()
	n := len(h.subs)
	h.mu.RUnlock()
	if n == 0 {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	ev := Event{Type: typ, Data: b}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
