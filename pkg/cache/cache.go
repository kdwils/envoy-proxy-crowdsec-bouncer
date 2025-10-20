package cache

import (
	"context"
	"sync"
	"time"
)

type CleanupFunc[T any] func(key string, value T) bool

type Cache[T any] struct {
	entries         map[string]T
	mu              sync.RWMutex
	cleanupInterval time.Duration
	cleanupFunc     CleanupFunc[T]
}

type Option[T any] func(*Cache[T])

func New[T any](opts ...Option[T]) *Cache[T] {
	c := &Cache[T]{
		mu:      sync.RWMutex{},
		entries: make(map[string]T),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func WithCleanup[T any](interval time.Duration, cleanupFunc CleanupFunc[T]) Option[T] {
	return func(c *Cache[T]) {
		c.cleanupInterval = interval
		c.cleanupFunc = cleanupFunc
	}
}

func WithCleanupInterval[T any](interval time.Duration) Option[T] {
	return func(c *Cache[T]) {
		c.cleanupInterval = interval
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

func (c *Cache[T]) Keys() []string {
	keys := make([]string, len(c.entries))
	i := 0
	for k := range c.entries {
		keys[i] = k
		i++
	}

	return keys
}

func (c *Cache[T]) StartCleanup(ctx context.Context) {
	if c.cleanupInterval == 0 || c.cleanupFunc == nil {
		return
	}

	ticker := time.NewTicker(c.cleanupInterval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				var keysToDelete []string

				c.mu.RLock()
				for key, value := range c.entries {
					if c.cleanupFunc(key, value) {
						keysToDelete = append(keysToDelete, key)
					}
				}
				c.mu.RUnlock()

				if len(keysToDelete) > 0 {
					c.mu.Lock()
					for _, key := range keysToDelete {
						delete(c.entries, key)
					}
					c.mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *Cache[T]) Cleanup(ctx context.Context, shouldDelete func(key string, value T) bool) {
	if c.cleanupInterval == 0 {
		return
	}

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var keysToDelete []string

			c.mu.RLock()
			for key, value := range c.entries {
				if shouldDelete(key, value) {
					keysToDelete = append(keysToDelete, key)
				}
			}
			c.mu.RUnlock()

			if len(keysToDelete) > 0 {
				c.mu.Lock()
				for _, key := range keysToDelete {
					delete(c.entries, key)
				}
				c.mu.Unlock()
			}
		case <-ctx.Done():
			return
		}
	}
}
