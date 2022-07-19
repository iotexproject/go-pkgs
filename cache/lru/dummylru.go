package lru

// DummyCache is an dummy LRU cache.
type DummyCache struct {
}

// NewDummyLRU creates a new Cache.
func NewDummyLRU() *DummyCache {
	return &DummyCache{}
}

// Add adds a value to the cache.
func (c *DummyCache) Add(key Key, value interface{}) {
}

// Get looks up a key's value from the cache.
func (c *DummyCache) Get(key Key) (interface{}, bool) {
	return nil, false
}

// Remove removes the provided key from the cache.
func (c *DummyCache) Remove(key Key) {
}

// RemoveOldest removes the oldest item from the cache.
func (c *DummyCache) RemoveOldest() {
}

// Len returns the number of items in the cache.
func (c *DummyCache) Len() int {
	return 0
}

// Clear purges all stored items from the cache.
func (c *DummyCache) Clear() {
}

// Range call f on every key
func (c *DummyCache) Range(f func(key Key, value interface{}) bool) {
}
