// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kubecache

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
	"k8s.io/apimachinery/pkg/api/meta"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// reservedResourceVersionWatch is the reserved watch name used to persist
// the last synced resourceVersion for each watch.
const reservedResourceVersionWatch = "//resourceVersions"

// lazyResourceVersionSyncInterval is the maximum frequency at which watch
// resourceVersions are lazily persisted to the reserved table.
const lazyResourceVersionSyncInterval = 2 * time.Second

// DefaultOnFatal logs the fatal error at error level and exits the process.
func DefaultOnFatal(err error) {
	klog.Errorf("kubecache fatal error: %v", err)
	os.Exit(1)
}

// IndexerOptions configures an Indexer instance.
type IndexerOptions struct {
	BucketName string
	KeyFunc    toolscache.KeyFunc
	Indexers   toolscache.Indexers
	Codec      ObjectCodec
}

// IndexerOption is a functional option for configuring an Indexer.
type IndexerOption func(*IndexerOptions)

// Option is an alias for IndexerOption.
type Option = IndexerOption

// WithBucketName sets the storage bucket name.
func WithBucketName(name string) IndexerOption {
	return func(o *IndexerOptions) {
		o.BucketName = name
	}
}

// WithKeyFunc sets the key function for the indexer.
func WithKeyFunc(fn toolscache.KeyFunc) IndexerOption {
	return func(o *IndexerOptions) {
		o.KeyFunc = fn
	}
}

// WithIndexers registers secondary indexers on creation.
func WithIndexers(indexers toolscache.Indexers) IndexerOption {
	return func(o *IndexerOptions) {
		o.Indexers = indexers
	}
}

// WithIndexerCodec sets the object codec for the indexer.
func WithIndexerCodec(codec ObjectCodec) IndexerOption {
	return func(o *IndexerOptions) {
		o.Codec = codec
	}
}

// Indexer implements k8s.io/client-go/tools/cache.Indexer backed by a core database Engine.
// It implements a fail-fast error policy via an OnFatal callback.
type Indexer struct {
	eng        *engine.Engine
	bucketName string
	example    k8sruntime.Object
	keyFunc    toolscache.KeyFunc
	codec      ObjectCodec
	onFatal    func(error)

	fatalMu   sync.RWMutex
	fatalOnce sync.Once
	fatalErr  error
	closed    chan struct{}

	mu         sync.RWMutex
	indexers   toolscache.Indexers
	indices    map[string]map[string]map[string]struct{} // indexName -> indexVal -> set of keys
	revIndices map[string]map[string][]string            // key -> indexName -> []indexVal

	// persistMu serializes writes to the reserved table so concurrent flushes
	// (e.g. from the timer and watch events) never interleave or write out of order.
	// If both mutexes are held, persistMu must always be acquired before rvMu.
	persistMu sync.Mutex

	// rvMu guards the in-memory resourceVersion state (lastSyncRV, lastPersistedRV,
	// lastPersistTime) and the relisting flag.
	rvMu            sync.Mutex
	relisting       bool
	lastSyncRV      string
	lastPersistedRV string
	lastPersistTime time.Time
}

var _ toolscache.Indexer = (*Indexer)(nil)

// New creates a new Indexer for the given example object type backed by the database engine.
// Construction requires a non-nil onFatal callback (e.g. DefaultOnFatal).
func New(eng *engine.Engine, example k8sruntime.Object, onFatal func(error), opts ...IndexerOption) (*Indexer, error) {
	if eng == nil {
		return nil, errors.New("engine cannot be nil")
	}
	if example == nil {
		return nil, errors.New("example object cannot be nil")
	}
	if onFatal == nil {
		return nil, errors.New("onFatal callback is required")
	}

	options := IndexerOptions{
		BucketName: fmt.Sprintf("%T", example),
		KeyFunc:    toolscache.MetaNamespaceKeyFunc,
		Indexers:   make(toolscache.Indexers),
		Codec:      NewHybridCodec(),
	}
	for _, opt := range opts {
		opt(&options)
	}

	if options.BucketName == reservedResourceVersionWatch {
		return nil, fmt.Errorf("bucket name %q is reserved", reservedResourceVersionWatch)
	}

	d := &Indexer{
		eng:        eng,
		bucketName: options.BucketName,
		example:    example,
		keyFunc:    options.KeyFunc,
		codec:      options.Codec,
		onFatal:    onFatal,
		closed:     make(chan struct{}),
		indexers:   make(toolscache.Indexers),
		indices:    make(map[string]map[string]map[string]struct{}),
		revIndices: make(map[string]map[string][]string),
	}

	for k, v := range options.Indexers {
		d.indexers[k] = v
		d.indices[k] = make(map[string]map[string]struct{})
	}

	// If engine is already failed, fail immediately
	if err := eng.Err(); err != nil {
		d.fatal(err)
		return nil, err
	}

	payload, exists, err := eng.Get(reservedResourceVersionWatch, d.bucketName)
	if err != nil {
		d.fatal(err)
		return nil, fmt.Errorf("failed to read watch resourceVersion: %w", err)
	}
	if exists {
		d.lastSyncRV = string(payload)
		d.lastPersistedRV = d.lastSyncRV
		d.lastPersistTime = time.Now()
	}

	// Listen for asynchronous background engine failures or engine closure,
	// and periodically persist watch resourceVersions lazily.
	go func() {
		ticker := time.NewTicker(lazyResourceVersionSyncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-eng.Failed():
				d.fatal(eng.Err())
				return
			case <-eng.Closed():
				return
			case <-d.closed:
				return
			case <-ticker.C:
				d.rvMu.Lock()
				rv := d.lastSyncRV
				needsSync := !d.relisting && rv != "" && rv != d.lastPersistedRV
				d.rvMu.Unlock()
				if needsSync {
					if err := d.persistResourceVersion(rv); err != nil {
						d.fatal(err)
						return
					}
				}
			}
		}
	}()

	// Rebuild secondary indexes by scanning existing data in engine
	scanErr := d.eng.Scan(d.bucketName, func(key string, payload []byte) error {
		target := d.example.DeepCopyObject()
		if err := d.codec.Decode(payload, target); err != nil {
			return fmt.Errorf("failed to decode object %s on reopen: %w", key, err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.updateIndicesLocked(key, target)
	})
	if scanErr != nil {
		d.fatal(scanErr)
		return nil, scanErr
	}

	return d, nil
}

func (d *Indexer) fatal(err error) {
	if err == nil {
		return
	}
	d.fatalOnce.Do(func() {
		d.fatalMu.Lock()
		d.fatalErr = err
		d.fatalMu.Unlock()
		if d.onFatal != nil {
			d.onFatal(err)
		}
	})
}

func (d *Indexer) isFatal() bool {
	d.fatalMu.RLock()
	defer d.fatalMu.RUnlock()
	return d.fatalErr != nil
}

func (d *Indexer) getFatalErr() error {
	d.fatalMu.RLock()
	defer d.fatalMu.RUnlock()
	return d.fatalErr
}

// Close terminates the background failure listener and persists the last synced resourceVersion.
func (d *Indexer) Close() error {
	select {
	case <-d.closed:
		return nil
	default:
		close(d.closed)
	}

	select {
	case <-d.eng.Closed():
		return nil
	default:
	}
	if d.isFatal() || d.eng.Err() != nil {
		return nil
	}

	d.rvMu.Lock()
	rv := d.lastSyncRV
	d.rvMu.Unlock()
	return d.persistResourceVersion(rv)
}

// Invariant: Never write a resourceVersion before the Put or Delete for that
// event has returned. That ordering is what keeps a stored resourceVersion
// from ever being ahead of the stored data.
func (d *Indexer) persistResourceVersion(rv string) error {
	if rv == "" || d.isFatal() {
		return nil
	}
	d.persistMu.Lock()
	defer d.persistMu.Unlock()

	if err := d.eng.Put(reservedResourceVersionWatch, d.bucketName, []byte(rv), rv); err != nil {
		return err
	}
	d.rvMu.Lock()
	d.lastPersistedRV = rv
	d.lastPersistTime = time.Now()
	d.rvMu.Unlock()
	return nil
}

func (d *Indexer) recordEventResourceVersion(rv string) {
	if rv == "" {
		return
	}
	d.rvMu.Lock()
	d.lastSyncRV = rv
	shouldSync := d.lastPersistedRV == "" || time.Since(d.lastPersistTime) >= lazyResourceVersionSyncInterval
	d.rvMu.Unlock()

	if shouldSync {
		if err := d.persistResourceVersion(rv); err != nil {
			d.fatal(err)
		}
	}
}

func (d *Indexer) extractResourceVersion(obj any) string {
	acc, err := meta.Accessor(obj)
	if err != nil {
		if dUnknown, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
			uAcc, uErr := meta.Accessor(dUnknown.Obj)
			if uErr != nil {
				d.rvMu.Lock()
				defer d.rvMu.Unlock()
				return d.lastSyncRV
			}
			if rv := uAcc.GetResourceVersion(); rv != "" {
				return rv
			}
		}
		d.rvMu.Lock()
		defer d.rvMu.Unlock()
		return d.lastSyncRV
	}
	if rv := acc.GetResourceVersion(); rv != "" {
		return rv
	}
	d.rvMu.Lock()
	defer d.rvMu.Unlock()
	return d.lastSyncRV
}

func (d *Indexer) putObject(obj any, rv string) error {
	key, err := d.keyFunc(obj)
	if err != nil {
		keyErr := toolscache.KeyError{Obj: obj, Err: err}
		d.fatal(keyErr)
		return keyErr
	}

	runtimeObj, ok := obj.(k8sruntime.Object)
	if !ok {
		typeErr := fmt.Errorf("object %T does not implement runtime.Object", obj)
		d.fatal(typeErr)
		return typeErr
	}

	encoded, err := d.codec.Encode(runtimeObj)
	if err != nil {
		encErr := fmt.Errorf("failed to encode object: %w", err)
		d.fatal(encErr)
		return encErr
	}

	d.mu.Lock()
	if err := d.updateIndicesLocked(key, obj); err != nil {
		d.mu.Unlock()
		d.fatal(err)
		return err
	}
	d.mu.Unlock()

	if err := d.eng.Put(d.bucketName, key, encoded, rv); err != nil {
		d.fatal(err)
		return err
	}
	return nil
}

// Add inserts an object into the indexer.
func (d *Indexer) Add(obj any) error {
	return d.Update(obj)
}

// Update updates an existing object or inserts a new object.
func (d *Indexer) Update(obj any) error {
	if err := d.getFatalErr(); err != nil {
		return err
	}

	objRV := d.extractResourceVersion(obj)
	if err := d.putObject(obj, objRV); err != nil {
		return err
	}
	d.recordEventResourceVersion(objRV)
	return nil
}

// Delete removes an object from the indexer and secondary indexes.
func (d *Indexer) Delete(obj any) error {
	if err := d.getFatalErr(); err != nil {
		return err
	}

	key, err := d.keyFunc(obj)
	if err != nil {
		keyErr := toolscache.KeyError{Obj: obj, Err: err}
		d.fatal(keyErr)
		return keyErr
	}

	d.mu.Lock()
	if oldMap, ok := d.revIndices[key]; ok {
		for indexName, oldVals := range oldMap {
			for _, oldVal := range oldVals {
				if d.indices[indexName] != nil && d.indices[indexName][oldVal] != nil {
					delete(d.indices[indexName][oldVal], key)
				}
			}
		}
		delete(d.revIndices, key)
	}
	d.mu.Unlock()

	delRV := d.extractResourceVersion(obj)
	if err := d.eng.Delete(d.bucketName, key, delRV); err != nil {
		d.fatal(err)
		return err
	}
	d.recordEventResourceVersion(delRV)
	return nil
}

// Replace replaces the indexer's contents with the provided list of objects.
func (d *Indexer) Replace(list []any, rv string) error {
	if err := d.getFatalErr(); err != nil {
		return err
	}

	d.rvMu.Lock()
	d.relisting = true
	d.rvMu.Unlock()
	defer func() {
		d.rvMu.Lock()
		d.relisting = false
		d.rvMu.Unlock()
	}()

	newKeys := make(map[string]struct{}, len(list))
	for _, item := range list {
		key, err := d.keyFunc(item)
		if err != nil {
			keyErr := toolscache.KeyError{Obj: item, Err: err}
			d.fatal(keyErr)
			return keyErr
		}
		newKeys[key] = struct{}{}
	}

	existingKeys := d.ListKeys()
	if d.isFatal() {
		return d.getFatalErr()
	}

	for _, existingKey := range existingKeys {
		if _, keep := newKeys[existingKey]; !keep {
			d.mu.Lock()
			if oldMap, ok := d.revIndices[existingKey]; ok {
				for indexName, oldVals := range oldMap {
					for _, oldVal := range oldVals {
						if d.indices[indexName] != nil && d.indices[indexName][oldVal] != nil {
							delete(d.indices[indexName][oldVal], existingKey)
						}
					}
				}
				delete(d.revIndices, existingKey)
			}
			d.mu.Unlock()

			if err := d.eng.Delete(d.bucketName, existingKey, rv); err != nil {
				d.fatal(err)
				return err
			}
		}
	}

	for _, item := range list {
		if err := d.putObject(item, rv); err != nil {
			return err
		}
	}

	d.rvMu.Lock()
	d.relisting = false
	d.lastSyncRV = rv
	d.rvMu.Unlock()
	if err := d.persistResourceVersion(rv); err != nil {
		d.fatal(err)
		return err
	}
	return nil
}

// Get finds an object matching obj's key.
func (d *Indexer) Get(obj any) (item any, exists bool, err error) {
	if err := d.getFatalErr(); err != nil {
		return nil, false, err
	}
	key, err := d.keyFunc(obj)
	if err != nil {
		keyErr := toolscache.KeyError{Obj: obj, Err: err}
		d.fatal(keyErr)
		return nil, false, keyErr
	}
	return d.GetByKey(key)
}

// GetByKey retrieves an object by key.
func (d *Indexer) GetByKey(key string) (item any, exists bool, err error) {
	if err := d.getFatalErr(); err != nil {
		return nil, false, err
	}

	payload, exists, err := d.eng.Get(d.bucketName, key)
	if err != nil {
		d.fatal(err)
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}

	target := d.example.DeepCopyObject()
	if err := d.codec.Decode(payload, target); err != nil {
		decErr := fmt.Errorf("failed to decode object %s: %w", key, err)
		d.fatal(decErr)
		return nil, false, decErr
	}
	return target, true, nil
}

// List returns all objects stored in the indexer.
// On failure, it calls OnFatal and returns nil (never partial data).
func (d *Indexer) List() []any {
	if d.isFatal() {
		return nil
	}

	var items []any
	scanErr := d.eng.Scan(d.bucketName, func(key string, payload []byte) error {
		target := d.example.DeepCopyObject()
		if err := d.codec.Decode(payload, target); err != nil {
			return fmt.Errorf("failed to decode object %s: %w", key, err)
		}
		items = append(items, target)
		return nil
	})
	if scanErr != nil {
		d.fatal(scanErr)
		return nil // NEVER return partial data!
	}
	return items
}

// ListKeys returns all keys stored in the indexer.
// On failure, it calls OnFatal and returns nil (never partial data).
func (d *Indexer) ListKeys() []string {
	if d.isFatal() {
		return nil
	}

	var keys []string
	scanErr := d.eng.Scan(d.bucketName, func(key string, _ []byte) error {
		keys = append(keys, key)
		return nil
	})
	if scanErr != nil {
		d.fatal(scanErr)
		return nil // NEVER return partial data!
	}
	return keys
}

// ByIndex returns all objects indexed under indexName matching indexedValue.
// On failure, it calls OnFatal and returns nil, err (never partial data).
func (d *Indexer) ByIndex(indexName, indexedValue string) ([]any, error) {
	if err := d.getFatalErr(); err != nil {
		return nil, err
	}

	keys, err := d.IndexKeys(indexName, indexedValue)
	if err != nil {
		return nil, err
	}

	var items []any
	for _, key := range keys {
		item, exists, err := d.GetByKey(key)
		if err != nil {
			return nil, err // NEVER return partial data!
		}
		if exists {
			items = append(items, item)
		}
	}
	return items, nil
}

// IndexKeys returns keys registered under indexName matching indexedValue.
func (d *Indexer) IndexKeys(indexName, indexedValue string) ([]string, error) {
	if err := d.getFatalErr(); err != nil {
		return nil, err
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	valMap, ok := d.indices[indexName]
	if !ok {
		err := fmt.Errorf("index with name %s does not exist", indexName)
		d.fatal(err)
		return nil, err
	}

	keySet := valMap[indexedValue]
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Index returns objects registered under indexName matching obj's indexed values.
func (d *Indexer) Index(indexName string, obj any) ([]any, error) {
	if err := d.getFatalErr(); err != nil {
		return nil, err
	}

	d.mu.RLock()
	indexFunc, exists := d.indexers[indexName]
	d.mu.RUnlock()
	if !exists {
		err := fmt.Errorf("index with name %s does not exist", indexName)
		d.fatal(err)
		return nil, err
	}

	indexedValues, err := indexFunc(obj)
	if err != nil {
		d.fatal(err)
		return nil, err
	}

	d.mu.RLock()
	keySet := make(map[string]struct{})
	for _, val := range indexedValues {
		if m, ok := d.indices[indexName][val]; ok {
			for k := range m {
				keySet[k] = struct{}{}
			}
		}
	}
	d.mu.RUnlock()

	var items []any
	for k := range keySet {
		item, exists, err := d.GetByKey(k)
		if err != nil {
			return nil, err // NEVER return partial data!
		}
		if exists {
			items = append(items, item)
		}
	}
	return items, nil
}

// Bookmark records a watch bookmark resourceVersion in memory and lazily persists it.
// Callers must invoke Bookmark only after every earlier event has been applied,
// ensuring the stored resourceVersion is never ahead of queued events.
func (d *Indexer) Bookmark(rv string) {
	if d.isFatal() {
		return
	}
	d.recordEventResourceVersion(rv)
}

// AddIndexers adds new secondary indexers to the Indexer.
func (d *Indexer) AddIndexers(newIndexers toolscache.Indexers) error {
	if err := d.getFatalErr(); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for name := range newIndexers {
		if _, exists := d.indexers[name]; exists {
			err := fmt.Errorf("indexer %s already exists", name)
			d.fatal(err)
			return err
		}
	}

	for k, v := range newIndexers {
		d.indexers[k] = v
		d.indices[k] = make(map[string]map[string]struct{})
	}

	// Re-index all existing objects
	scanErr := d.eng.Scan(d.bucketName, func(key string, payload []byte) error {
		target := d.example.DeepCopyObject()
		if err := d.codec.Decode(payload, target); err != nil {
			return fmt.Errorf("failed to decode object %s: %w", key, err)
		}
		return d.updateIndicesLocked(key, target)
	})
	if scanErr != nil {
		d.fatal(scanErr)
		return scanErr
	}
	return nil
}

// GetIndexers returns the registered indexers.
func (d *Indexer) GetIndexers() toolscache.Indexers {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res := make(toolscache.Indexers, len(d.indexers))
	for k, v := range d.indexers {
		res[k] = v
	}
	return res
}

// ListIndexFuncValues returns all indexed values stored for indexName.
func (d *Indexer) ListIndexFuncValues(indexName string) []string {
	if d.isFatal() {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	valMap, ok := d.indices[indexName]
	if !ok {
		return nil
	}

	values := make([]string, 0, len(valMap))
	for v := range valMap {
		values = append(values, v)
	}
	sort.Strings(values)
	return values
}

// LastStoreSyncResourceVersion returns the last synced resourceVersion for the watch.
func (d *Indexer) LastStoreSyncResourceVersion() string {
	d.rvMu.Lock()
	defer d.rvMu.Unlock()
	return d.lastSyncRV
}

// Resync is a no-op required by cache.Indexer.
func (d *Indexer) Resync() error {
	if err := d.getFatalErr(); err != nil {
		return err
	}
	return nil
}

func (d *Indexer) updateIndicesLocked(key string, obj any) error {
	oldValsMap, hadOld := d.revIndices[key]

	newValsMap := make(map[string][]string)
	for indexName, indexFunc := range d.indexers {
		newVals, err := indexFunc(obj)
		if err != nil {
			return fmt.Errorf("index function %s failed for %s: %w", indexName, key, err)
		}
		newValsMap[indexName] = newVals
	}

	// Remove old index values that are not in new values
	if hadOld {
		for indexName, oldVals := range oldValsMap {
			newVals := newValsMap[indexName]
			newSet := make(map[string]struct{}, len(newVals))
			for _, nv := range newVals {
				newSet[nv] = struct{}{}
			}
			for _, ov := range oldVals {
				if _, kept := newSet[ov]; !kept {
					if d.indices[indexName] != nil && d.indices[indexName][ov] != nil {
						delete(d.indices[indexName][ov], key)
					}
				}
			}
		}
	}

	// Add new index values
	for indexName, newVals := range newValsMap {
		for _, nv := range newVals {
			if d.indices[indexName] == nil {
				d.indices[indexName] = make(map[string]map[string]struct{})
			}
			if d.indices[indexName][nv] == nil {
				d.indices[indexName][nv] = make(map[string]struct{})
			}
			d.indices[indexName][nv][key] = struct{}{}
		}
	}

	d.revIndices[key] = newValsMap
	return nil
}
