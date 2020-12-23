// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package cache

import (
	"github.com/iotexproject/go-pkgs/cache/lru"
)

// ThreadSafeLruCache defines a lru cache which is thread safe
type ThreadSafeLruCache struct {
	*lru.Cache
}

// NewThreadSafeLruCache returns a thread safe lru cache with fix size
func NewThreadSafeLruCache(maxEntries int) *ThreadSafeLruCache {
	return &ThreadSafeLruCache{
		lru.New(maxEntries),
	}
}

// NewThreadSafeLruCacheWithOnEvicted returns a thread safe lru cache with fix size
func NewThreadSafeLruCacheWithOnEvicted(maxEntries int, onEvicted func(key lru.Key, value interface{})) *ThreadSafeLruCache {
	cache := lru.New(maxEntries)
	cache.OnEvicted = onEvicted
	return &ThreadSafeLruCache{
		cache,
	}
}
