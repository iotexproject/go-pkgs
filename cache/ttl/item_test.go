package ttlcache

import (
	"testing"
	"time"
)

func TestExpired(t *testing.T) {
	item := &Item{data: "blahblah"}
	if !item.expired() {
		t.Errorf("Expected item to be expired by default")
	}

	item.expires = time.Now().Add(time.Second)
	if item.expired() {
		t.Errorf("Expected item to not be expired")
	}

	item.expires = time.Now().Add(0 - time.Second)
	if !item.expired() {
		t.Errorf("Expected item to be expired once time has passed")
	}
}

func TestAddTimeout(t *testing.T) {
	item := &Item{data: "blahblah"}
	item.addTimeout(time.Second)
	if item.expired() {
		t.Errorf("Expected item to not be expired once touched")
	}
}
