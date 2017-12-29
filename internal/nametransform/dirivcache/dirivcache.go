package dirivcache

import (
	"log"
	"strings"
	"sync"
	"time"
)

type cacheEntry struct {
	// DirIV of the directory.
	iv []byte
	// Relative ciphertext path of the directory.
	cDir string
}

// DirIVCache stores up to "maxEntries" directory IVs.
type DirIVCache struct {
	// data in the cache, indexed by relative plaintext path
	// of the directory.
	data map[string]cacheEntry

	// The DirIV of the root directory gets special treatment because it
	// cannot change (the root directory cannot be renamed or deleted).
	// It is unaffected by the expiry timer and cache clears.
	rootDirIV []byte

	// expiry is the time when the whole cache expires.
	// The cached entry may become out-of-date if the ciphertext directory is
	// modifed behind the back of gocryptfs. Having an expiry time limits the
	// inconstency to one second (by default), like attr_timeout does for the kernel
	// getattr cache.
	expiry time.Time

	// Max number of entries in the map cache (default 100)
	MaxEntries int

	// Timeout in seconds before cache is invalidated (default 1)
	MaxTime int

	sync.RWMutex
}

// Lookup - fetch entry for "dir" (relative plaintext path) from the cache.
// Returns the directory IV and the relative encrypted path, or (nil, "")
// if the entry was not found.
func (c *DirIVCache) Lookup(dir string) (iv []byte, cDir string) {
	c.RLock()
	defer c.RUnlock()
	if dir == "" {
		return c.rootDirIV, ""
	}
	if c.data == nil {
		return nil, ""
	}
	if time.Since(c.expiry) > 0 {
		c.data = nil
		return nil, ""
	}
	v := c.data[dir]
	return v.iv, v.cDir
}

// Store - write an entry for directory "dir" into the cache.
// Arguments:
// dir ... relative plaintext path
// iv .... directory IV
// cDir .. relative ciphertext path
func (c *DirIVCache) Store(dir string, iv []byte, cDir string) {
	c.Lock()
	defer c.Unlock()

	if dir == "" {
		c.rootDirIV = iv
	}
	// Sanity check: plaintext and chiphertext paths must have the same number
	// of segments
	if strings.Count(dir, "/") != strings.Count(cDir, "/") {
		log.Panicf("inconsistent number of path segments: dir=%q cDir=%q", dir, cDir)
	}
	// Clear() may have cleared c.data: re-initialize
	if c.data == nil {
		c.data = make(map[string]cacheEntry, c.MaxEntries)
		// Set expiry time c.MaxTime seconds into the future
		c.expiry = time.Now().Add(time.Duration(c.MaxTime) * time.Second)
	}
	// Delete a random entry from the map if reached MaxEntries
	if len(c.data) >= c.MaxEntries {
		for k := range c.data {
			delete(c.data, k)
			break
		}
	}
	c.data[dir] = cacheEntry{iv, cDir}
}

// Remove an entry from the cache.
// Called from fusefrontend when directories are renamed or deleted.
// dir ... relative plaintext path
func (c *DirIVCache) Remove(dir string) {
	c.Lock()
	defer c.Unlock()

	delete(c.data, dir)
}

// Clear ... clear the cache.
func (c *DirIVCache) Clear() {
	c.Lock()
	defer c.Unlock()
	// Will be re-initialized in the next Store()
	c.data = nil
}
