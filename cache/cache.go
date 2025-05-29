package cache

import (
	"sync"
	"time"
)

type Cache struct {
	entries map[string]Entry
	ttl     time.Duration
	mu      sync.RWMutex
	maxSize int
}

type Entry struct {
	Bounced   bool
	ExpiresAt time.Time
}

func New(ttl time.Duration, maxSize int) *Cache {
	return &Cache{
		ttl:     ttl,
		mu:      sync.RWMutex{},
		entries: make(map[string]Entry),
		maxSize: maxSize,
	}
}

func (c *Cache) Set(ip string, bounced bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = Entry{
		Bounced:   bounced,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

func (c *Cache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ip)
}

func (c *Cache) Get(ip string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var entry Entry
	var ok bool

	entry, ok = c.entries[ip]
	if !ok {
		return entry, false
	}

	if entry.Expired() {
		delete(c.entries, ip)
		return entry, false
	}

	return entry, ok
}

func (c *Cache) Cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			for ip, entry := range c.entries {
				if entry.Expired() {
					delete(c.entries, ip)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (e Entry) Expired() bool {
	return time.Now().After(e.ExpiresAt)
}
