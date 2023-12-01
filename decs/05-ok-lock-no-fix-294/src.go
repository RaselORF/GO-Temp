// Issue 294
// unlock is okay without any defer.
// No warning.

package testdata

import (
	"fmt"
	"sync"
	"time"
)

type SafeCounter struct {
	mu sync.Mutex
	v  map[string]int
}

func (c *SafeCounter) plusPlus(key string) *sync.Mutex {
	c.v[key]++
	return &c.mu
}

func (c *SafeCounter) Inc(key string) {
	c.mu.Lock()
	c.plusPlus(key).Unlock()
}

func (c *SafeCounter) Value(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.v[key]
}

func main() {
	c := SafeCounter{v: make(map[string]int)}
	for i := 0; i < 1000; i++ {
		go c.Inc("somekey")
	}
	time.Sleep(time.Second)
	fmt.Println(c.Value("somekey"))
}

//<<<<<309, 320>>>>>
