package dirivcache

import (
	//"fmt"
	"log"
	"strings"
	"sync"
	"bytes"

	//"time"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type treeCacheEntry struct {
	// DirIV of the directory.
	iv []byte

	// Relative ciphertext path of the directory.
	cDir string

	//folders contained in this node
	subfolders map[string] *treeCacheEntry
}

// DirIVCache stores up to "maxEntries" directory IVs.
type DirIVCache struct {
	treeCacheRoot treeCacheEntry

	sync.RWMutex
}

// Lookup - fetch entry for "dir" (relative plaintext path) from the cache.
// Returns the directory IV and the relative encrypted path, or (nil, "")
// if the entry was not found.
func (c *DirIVCache) Lookup(dir string) (iv []byte, cDir string) {
	c.RLock()
	defer c.RUnlock()

	if dir == "" {
		return c.treeCacheRoot.iv, ""
	}
	if c.treeCacheRoot.subfolders == nil {
		return nil, ""
	}

	plainSegments := strings.Split(dir, "/")
	var entry *treeCacheEntry
	entry = &c.treeCacheRoot
	var cipherPath bytes.Buffer
	for i := 0; i < len(plainSegments); i++ {
		if val, ok := entry.subfolders[plainSegments[i]]; ok {
			if i == len(plainSegments)-1 {
				tlog.Debug.Printf("Lookup found element %s in %s\n", plainSegments[i], dir)
				cipherPath.WriteString(val.cDir)
				return val.iv, cipherPath.String()
			}
			entry = val
			cipherPath.WriteString(entry.cDir)
			cipherPath.WriteString("/")
		} else {
			tlog.Debug.Printf("Lookup: not found element %s in %s\n", plainSegments[i], dir)
			return nil, ""
		}
	}

	return nil, "" //shall not get here
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
		c.treeCacheRoot.iv = iv
		c.treeCacheRoot.subfolders = make(map[string]*treeCacheEntry, 30)
	}
	// Sanity check: plaintext and chiphertext paths must have the same number
	// of segments
	if strings.Count(dir, "/") != strings.Count(cDir, "/") {
		log.Panicf("inconsistent number of path segments: dir=%q cDir=%q\n", dir, cDir)
	}

	plainSegments := strings.Split(dir, "/")
	cipherSegments := strings.Split(cDir, "/")
	var entry *treeCacheEntry
	entry = &c.treeCacheRoot
	for i := 0; i < len(plainSegments)-1; i++ {
		if val, ok := entry.subfolders[plainSegments[i]]; ok {
			entry = val
		} else {
			tlog.Debug.Printf("Store: missing intermediary element %s,%s en %s,%s\n", plainSegments[i], cipherSegments[i], dir, cDir)
			return
		}
	}

	if entry.subfolders != nil {
		var newEntry treeCacheEntry
		newEntry.iv = iv
		newEntry.cDir = cipherSegments[len(cipherSegments)-1]
		newEntry.subfolders = make(map[string]*treeCacheEntry, 10)
		entry.subfolders[plainSegments[len(plainSegments)-1]] = &newEntry
		tlog.Debug.Printf("Store: inserted %s,%s in %s,%s\n", plainSegments[len(plainSegments)-1], cipherSegments[len(cipherSegments)-1], dir, cDir)
	} else {
		tlog.Debug.Printf("Store: uninitialized map in %s,%s in %s,%s\n", plainSegments[len(plainSegments)-1], cipherSegments[len(cipherSegments)-1], dir, cDir)
		return
	}


}

// Remove an entry from the cache.
// Called from fusefrontend when directories are renamed or deleted.
// dir ... relative plaintext path
func (c *DirIVCache) Remove(dir string) {
	c.Lock()
	defer c.Unlock()

	plainSegments := strings.Split(dir, "/")
	var entry *treeCacheEntry
	entry = &c.treeCacheRoot
	for i := 0; i < len(plainSegments); i++ {
		if i == len(plainSegments)-1 {
			delete(entry.subfolders, plainSegments[i])
			tlog.Debug.Printf("Removed element %s in %s, cipher node %s\n", plainSegments[i], dir, entry.cDir)
			return
		}
		
		if val, ok := entry.subfolders[plainSegments[i]]; ok {
			entry = val
			continue
		} else {
			tlog.Debug.Printf("Remove: not found element %s in %s\n", plainSegments[i], dir)
			return
		}
	}
}

// Clear ... clear the cache.
func (c *DirIVCache) Clear() {
	c.Lock()
	defer c.Unlock()

	// Will be re-initialized in the next Store()
	c.treeCacheRoot.subfolders = nil
}
