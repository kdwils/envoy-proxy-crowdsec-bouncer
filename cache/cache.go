package cache

import (
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Cache struct {
	entries map[string]models.Decision
	mu      sync.RWMutex
}

func New() *Cache {
	return &Cache{
		mu:      sync.RWMutex{},
		entries: make(map[string]models.Decision),
	}
}

func (c *Cache) Set(ip string, d models.Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = d
}

func (c *Cache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ip)
}

func (c *Cache) Get(ip string) (models.Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[ip]
	return entry, ok
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
