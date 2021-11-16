package ttl

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	require := require.New(t)
	cache, _ := NewCache(AutoExpireOption(time.Minute))

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
	cache, _ := NewCache(AutoExpireOption(time.Minute))

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
	cache, _ := NewCache()

	cache.Set("x", "1")
	require.Equal(1, cache.Count())

	<-time.After(time.Second * 2)
	_, exist := cache.Get("x")
	require.True(exist)

}
func TestExpiration(t *testing.T) {
	require := require.New(t)
	cache, err := NewCache(AutoExpireOption(-time.Second))
	require.Error(err)
	cache, err = NewCache(AutoExpireOption(time.Second))
	require.NoError(err)

	cache.Set("x", "1")
	cache.Set("y", "z")
	cache.Set("z", "3")
	require.Equal(3, cache.Count())

	<-time.After(200 * time.Millisecond)
	_, exists := cache.Get("y")
	require.True(exists)
	cache.mutex.RLock()
	item, exists := cache.items["x"]
	cache.mutex.RUnlock()
	require.True(exists)
	require.False(item.expired())
	require.Equal("1", item.data)

	<-time.After(900 * time.Millisecond)
	cache.mutex.RLock()
	item, exists = cache.items["x"]
	require.False(exists)
	require.Nil(item)
	item, exists = cache.items["z"]
	require.False(exists)
	require.Nil(item)
	item, exists = cache.items["y"]
	require.True(exists)
	require.False(item.expired())
	require.Equal("z", item.data)
	cache.mutex.RUnlock()
	require.Equal(1, cache.Count())

	<-time.After(100 * time.Millisecond)
	data, exists := cache.Get("y")
	require.False(exists)
	require.Nil(data)
	require.Zero(cache.Count())
}

func TestReset(t *testing.T) {
	require := require.New(t)
	cache, _ := NewCache(AutoExpireOption(time.Minute))

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

func TestRange(t *testing.T) {
	errOdd := errors.New("delete odd index")
	r := require.New(t)

	cache, err := NewCache(EvictOnErrorOption())
	r.NoError(err)
	for i := 0; i < 10000; i++ {
		cache.Set(i, i+1)
	}
	r.Equal(10000, cache.Count())

	cache.Range(func(key, val interface{}) error {
		if key.(int)&1 != 0 {
			return errOdd
		}
		return nil
	})

	r.Equal(5000, cache.Count())
	for i := 0; i < 10000; i++ {
		v, ok := cache.Get(i)
		if i&1 != 0 {
			r.False(ok)
		} else {
			r.True(ok)
			r.Equal(i+1, v.(int))
		}
	}
}

func TestFunc(t *testing.T) {
	r := require.New(t)

	cache, err := NewCache()
	r.NoError(err)
	r.Panics(func() {
		cache.Set(AutoExpireOption(time.Second), true)
	})
}
