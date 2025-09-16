package cache

import (
	"context"
	"sync"
	"time"
)

type Cache[T any] struct {
	entries map[string]T
	mu      sync.RWMutex
}

func New[T any]() *Cache[T] {
	return &Cache[T]{
		mu:      sync.RWMutex{},
		entries: make(map[string]T),
	}
}

func (c *Cache[T]) Set(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = value
}

func (c *Cache[T]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *Cache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	return entry, ok
}

func (c *Cache[T]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache[T]) Cleanup(ctx context.Context, shouldDelete func(key string, value T) bool) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			for key, value := range c.entries {
				if shouldDelete(key, value) {
					delete(c.entries, key)
				}
			}
			c.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}
