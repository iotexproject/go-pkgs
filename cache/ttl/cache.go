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

package ttl

import (
	"errors"
	"sync"
	"time"
)

type Option func(*Cache) error

func AutoExpireOption(ttl time.Duration) Option {
	return func(cache *Cache) error {
		if ttl <= 0 {
			return errors.New("time should be larger than 0")
		}
		cache.ttl = ttl
		return nil
	}
}

func EvictOnErrorOption() Option {
	return func(cache *Cache) error {
		cache.hasEvictOnError = true
		return nil
	}
}

// Cache is a synchronised map of items that auto-expire once stale
type Cache struct {
	mutex           sync.RWMutex
	items           map[interface{}]*Item
	ttl             time.Duration
	hasEvictOnError bool
}

// NewCache creates a instance of the Cache struct. Argument duration
// stands for the existing time of item in the cache. When no argument
// is passed, the item will persistently existed in the cache.
func NewCache(opts ...Option) (*Cache, error) {
	cache := &Cache{
		items: map[interface{}]*Item{},
	}
	for _, opt := range opts {
		if err := opt(cache); err != nil {
			return nil, err
		}
	}
	if cache.hasAutoExpire() {
		go cache.startCleanupTimer()
	}
	return cache, nil
}

// Set is a thread-safe way to add new items to the map
func (cache *Cache) Set(key, data interface{}) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	item := &Item{data: data}
	if cache.hasAutoExpire() {
		item.addTimeout(cache.ttl)
	}
	cache.items[key] = item
}

// Get is a thread-safe way to lookup items
// Every lookup, also add the timeout of the item, hence extending it's life
func (cache *Cache) Get(key interface{}) (interface{}, bool) {
	switch {
	case cache.hasAutoExpire():
		cache.mutex.Lock()
		defer cache.mutex.Unlock()
		item, exists := cache.items[key]
		if !exists {
			return nil, false
		}
		if item.expired() {
			delete(cache.items, key)
			return nil, false
		}
		item.addTimeout(cache.ttl)
		return item.data, true
	default:
		cache.mutex.RLock()
		defer cache.mutex.RUnlock()
		item, exists := cache.items[key]
		if !exists {
			return nil, false
		}
		return item.data, true
	}
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
func (cache *Cache) Delete(key interface{}) bool {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if _, exist := cache.items[key]; !exist {
		return false
	}
	delete(cache.items, key)
	return true
}

// Range calls f on every key in the map
// if hasEvictOnError flag is set, then a key failing f() will be deleted from the map
func (cache *Cache) Range(f func(key, value interface{}) error) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	for k, v := range cache.items {
		if cache.hasAutoExpire() && v.expired() {
			continue
		}
		if f(k, v.data) != nil && cache.hasEvictOnError {
			delete(cache.items, k)
		}
	}
}

// Reset empties the cache
func (cache *Cache) Reset() {
	cache.mutex.Lock()
	cache.items = make(map[interface{}]*Item)
	cache.mutex.Unlock()
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
	for {
		select {
		case <-ticker:
			cache.cleanup()
		}
	}
}

func (cache *Cache) hasAutoExpire() bool {
	return cache.ttl > 0
}
