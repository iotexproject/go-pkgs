package ttlcache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	require := require.New(t)
	cache := NewCache(AutoExpireOption(time.Minute))

	data, exists := cache.Get("hello")
	require.False(exists)
	require.Empty(data)

	cache.Set("hello", "world")
	data, exists = cache.Get("hello")
	require.True(exists)
	require.Equal(data, "world")
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	cache := NewCache(AutoExpireOption(time.Minute))

	cache.Set("hello", "world")
	data, exists := cache.Get("hello")
	require.True(exists)
	require.Equal(data, "world")

	cache.Delete("hello")
	data, exists = cache.Get("hello")
	require.False(exists)
	require.Empty(data)
}

func TestNoExpiration(t *testing.T) {
	require := require.New(t)
	cache := NewCache()

	cache.Set("x", "1")
	require.Equal(1, cache.Count())

	<-time.After(time.Second * 2)
	_, exist := cache.Get("x")
	require.True(exist)

}
func TestExpiration(t *testing.T) {
	cache := NewCache(AutoExpireOption(time.Second))

	cache.Set("x", "1")
	cache.Set("y", "z")
	cache.Set("z", "3")
	cache.startCleanupTimer()

	count := cache.Count()
	if count != 3 {
		t.Errorf("Expected cache to contain 3 items")
	}

	<-time.After(500 * time.Millisecond)
	cache.mutex.Lock()
	cache.items["y"].addTimeout(time.Second)
	item, exists := cache.items["x"]
	cache.mutex.Unlock()
	if !exists || item.data != "1" || item.expired() {
		t.Errorf("Expected `x` to not have expired after 200ms")
	}

	<-time.After(time.Second)
	cache.mutex.RLock()
	_, exists = cache.items["x"]
	if exists {
		t.Errorf("Expected `x` to have expired")
	}
	_, exists = cache.items["z"]
	if exists {
		t.Errorf("Expected `z` to have expired")
	}
	_, exists = cache.items["y"]
	if !exists {
		t.Errorf("Expected `y` to not have expired")
	}
	cache.mutex.RUnlock()

	count = cache.Count()
	if count != 1 {
		t.Errorf("Expected cache to contain 1 item")
	}

	<-time.After(600 * time.Millisecond)
	cache.mutex.RLock()
	_, exists = cache.items["y"]
	if exists {
		t.Errorf("Expected `y` to have expired")
	}
	cache.mutex.RUnlock()

	count = cache.Count()
	if count != 0 {
		t.Errorf("Expected cache to be empty")
	}
}

func TestReset(t *testing.T) {
	require := require.New(t)
	cache := NewCache(AutoExpireOption(time.Minute))

	cache.Set("hello", "world")
	data, exists := cache.Get("hello")
	require.True(exists)
	require.Equal(data, "world")

	cache.Reset()
	data, exists = cache.Get("hello")
	require.False(exists)
	require.Empty(data)
	require.Equal(cache.Count(), 0)
}
