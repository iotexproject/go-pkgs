// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package cache

import (
	"github.com/iotexproject/go-pkgs/cache/lru"
)

type LRUCache interface {
	// Add adds a value to the cache.
	Add(key Key, value interface{})
	// Get looks up a key's value from the cache.
	Get(key Key) (interface{}, bool)
	// Remove removes the provided key from the cache.
	Remove(key Key)
	// RemoveOldest removes the oldest item from the cache.
	RemoveOldest()
	// Len returns the number of items in the cache.
	Len() int
	// Clear purges all stored items from the cache.
	Clear()
	// Range call f on every key
	Range(f func(key Key, value interface{}) bool)
}

// Key is an alias of lru.Key
type Key = lru.Key

// NewThreadSafeLruCache returns a thread safe lru cache with fix size
func NewThreadSafeLruCache(maxEntries int) LRUCache {
	return lru.New(maxEntries)
}

// NewDummyLruCache returns a dummy lru cache
func NewDummyLruCache() LRUCache {
	return lru.NewDummyLRU()
}

// NewThreadSafeLruCacheWithOnEvicted returns a thread safe lru cache with fix size
func NewThreadSafeLruCacheWithOnEvicted(maxEntries int, onEvicted func(key Key, value interface{})) LRUCache {
	cache := lru.New(maxEntries)
	cache.OnEvicted = onEvicted
	return cache
}
