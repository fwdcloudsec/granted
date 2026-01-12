package frecency

import (
	"encoding/json"
	"math"
	"os"
	"path"
	"sort"
	"time"

	"github.com/fwdcloudsec/granted/pkg/config"
)

// change these to play with the weights
// values between 0 and 1
// 0 will exclude the metric all together from the ordering
var FrequencyWeight float64 = 1
var DateWeight float64 = 1

type FrecencyStore struct {
	MaxFrequency int
	OldestDate   time.Time
	Entries      []*Entry
	path         string
}

type Entry struct {
	Entry                interface{}
	Frequency            int
	LastUsed             time.Time
	FrequencyScore       float64
	LastUsedScore        float64
	FrecencySortingScore float64
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Returns the cached entries stored in descending order by frecency, optionally limit the returned results
func (store *FrecencyStore) GetFrecentEntriess(optionalLimit *int) []interface{} {
	entries := []interface{}{}
	limit := len(store.Entries)
	if optionalLimit != nil && *optionalLimit >= 0 {
		limit = min(*optionalLimit, limit)
	}
	for i := 0; i < limit; i++ {
		entries = append(entries, store.Entries[i].Entry)
	}
	return entries

}

func Load(fecencyStoreKey string) (*FrecencyStore, error) {
	c := FrecencyStore{MaxFrequency: 1, OldestDate: time.Now()}
	configFolder, err := config.GrantedCacheFolder()
	if err != nil {
		return nil, err
	}
	c.path = path.Join(configFolder, fecencyStoreKey)

	// check if the providers file exists
	if _, err = os.Stat(c.path); os.IsNotExist(err) {
		err := os.MkdirAll(configFolder, 0700)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}

	file, err := os.OpenFile(c.path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	err = json.NewDecoder(file).Decode(&c)
	if err != nil {
		// if there is an error just reset the file
		return &c, nil
	}
	return &c, nil
}
func remove(slice []*Entry, s int) []*Entry {
	return append(slice[:s], slice[s+1:]...)
}

// delete a single entry from the frecency store
func (store *FrecencyStore) Delete(toRemove interface{}) error {
	index := -1
	for i, r := range store.Entries {
		if toRemove == r.Entry {
			index = i
			break
		}
	}
	if index != -1 {
		store.Entries = remove(store.Entries, index)
	}
	return store.save()
}

// deletes all elements from the frecency store
func (store *FrecencyStore) DeleteAll(toRemove []interface{}) error {
	newList := []*Entry{}
	remove := false
	for i, r := range store.Entries {
		remove = false
		for _, match := range toRemove {
			if match == r {
				remove = true
				break
			}
		}
		if !remove {
			newList = append(newList, store.Entries[i])
		}
	}
	store.Entries = newList
	return store.save()
}

// Save a new reason to the frecency cache.
// This operation will reevaluate the frecency scores after inserting the new reason
// if the reason already exists, the frequency will be increased as well as the last used date
// the newReason will always be saved at the top of the list
func (store *FrecencyStore) Upsert(newEntry interface{}) error {
	reas := Entry{Entry: newEntry, Frequency: 1, LastUsed: time.Now()}
	store.OldestDate = reas.LastUsed
	updated := false

	// First we check for the oldest date after updating the reason
	for _, r := range store.Entries {
		if newEntry == r.Entry {
			r.LastUsed = reas.LastUsed
			r.Frequency += 1
			store.MaxFrequency = max(store.MaxFrequency, r.Frequency)
			updated = true
		}
		if r.LastUsed.Before(store.OldestDate) {
			store.OldestDate = r.LastUsed
		}
	}
	if !updated {
		store.Entries = append(store.Entries, &reas)
	}
	return store.save()
}

// calculates new frecency sorting order and saves the file with a json encoding
func (store *FrecencyStore) save() error {
	// Then calculate our sorting order using frecency
	for _, r := range store.Entries {
		// I use Log10 here to get a decay effect
		// the results will be values between 0 and 1
		// elements with frequency much lower than the max frequency will score very low
		// elements that are 50% and above of the max will all score relatively close to each other
		// the same is true for the last used date
		// it would probably work just as well without the log10 it will just be a linear ordering
		r.FrequencyScore = math.Log10(float64(r.Frequency) / float64(store.MaxFrequency) * 10)
		lastUsedDiff := float64(r.LastUsed.Sub(store.OldestDate))
		if lastUsedDiff > 0 {
			r.LastUsedScore = math.Log10(lastUsedDiff / float64(time.Since(store.OldestDate)) * 10)
		} else {
			r.LastUsedScore = 1
		}
		r.FrecencySortingScore = r.FrequencyScore*FrequencyWeight + r.LastUsedScore*DateWeight
	}

	// sort by the cached value of frecencySortingScore
	sort.SliceStable(store.Entries, func(i int, j int) bool {
		return store.Entries[i].FrecencySortingScore > store.Entries[j].FrecencySortingScore
	})

	// // We limit the maximum number of cached entries
	// if len(store.Entries) > MaxRecords {
	// 	store.Entries = store.Entries[0 : len(store.Entries)-1]
	// }

	file, err := os.OpenFile(store.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return json.NewEncoder(file).Encode(store)
}
