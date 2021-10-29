/*
MIT License

Copyright (c) 2018 Microsoft GmbH

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package ttlcache

import (
	"sync"
	"time"
)

// Cache is a synchronised map of items that auto-expire once stale
type Cache struct {
	mutex sync.RWMutex
	ttl   time.Duration
	items map[string]*Item
}

// NewCache creates a instance of the Cache struct. Argument duration
// stands for the existing time of item in the cache. When no argument
// is passed, the item will persistently existed in the cache.
func NewCache(duration ...time.Duration) *Cache {
	if len(duration) == 0 {
		return &Cache{
			ttl:   0,
			items: map[string]*Item{},
		}
	}

	if len(duration) > 1 || duration[0] <= 0 {
		return nil
	}
	cache := &Cache{
		ttl:   duration[0],
		items: map[string]*Item{},
	}
	cache.startCleanupTimer()
	return cache
}

// Set is a thread-safe way to add new items to the map
func (cache *Cache) Set(key string, data interface{}) {
	cache.mutex.Lock()
	item := &Item{data: data}
	item.addTimeout(cache.ttl)
	cache.items[key] = item
	cache.mutex.Unlock()
}

// Get is a thread-safe way to lookup items
// Every lookup, also add the timeout of the item, hence extending it's life
func (cache *Cache) Get(key string) (interface{}, bool) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	item, exists := cache.items[key]
	if !exists || item.expired() {
		return "", false
	}
	item.addTimeout(cache.ttl)
	return item.data, true
}

// Count returns the number of items in the cache
// (helpful for tracking memory leaks)
func (cache *Cache) Count() int {
	cache.mutex.RLock()
	count := len(cache.items)
	cache.mutex.RUnlock()
	return count
}

// Delete removes existing item in the cache
func (cache *Cache) Delete(key string) bool {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if _, exist := cache.items[key]; !exist {
		return false
	}
	delete(cache.items, key)
	return true
}

// Reset empties the cache
func (cache *Cache) Reset() {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.items = make(map[string]*Item)
	cache.ttl = 0
}

func (cache *Cache) cleanup() {
	cache.mutex.Lock()
	for key, item := range cache.items {
		if item.expired() {
			delete(cache.items, key)
		}
	}
	cache.mutex.Unlock()
}

func (cache *Cache) startCleanupTimer() {
	ticker := time.Tick(cache.ttl)
	go (func() {
		for {
			select {
			case <-ticker:
				cache.cleanup()
			}
		}
	})()
}
