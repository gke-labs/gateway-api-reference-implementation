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
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

var (
	errExpired    = errors.New("watch resourceVersion expired")
	errWatchError = errors.New("watch received error event")
)

// StoreError wraps an error returned by the underlying store, indicating a fatal store failure.
type StoreError struct {
	Err error
}

func (e *StoreError) Error() string {
	return fmt.Sprintf("store error: %v", e.Err)
}

func (e *StoreError) Unwrap() error {
	return e.Err
}

// ResourceVersionStore represents the store operations needed to track
// watch resourceVersions.
//
// Upstreaming this concept to client-go is a goal.
type ResourceVersionStore interface {
	// Bookmark records a watch bookmark resourceVersion in the store.
	Bookmark(resourceVersion string)
	// LastStoreSyncResourceVersion returns the latest resource version that the store has seen.
	// Resumption from this resourceVersion succeeds as long as the API server still has history
	// for it (on the order of minutes with default etcd compaction); older resourceVersions
	// fall back to a re-list.
	LastStoreSyncResourceVersion() string
}

// Store is the interface required by WatchLoop to update cached objects.
//
// Upstreaming this interface to client-go (e.g. extending ReflectorStore) is a goal.
type Store interface {
	Add(obj any) error
	Update(obj any) error
	Delete(obj any) error
	Replace(list []any, resourceVersion string) error
	ResourceVersionStore
}

var _ Store = (*Indexer)(nil)

// WatchLoop watches a ListerWatcher and syncs events to a Store.
//
// Caveat: A watch can only resume from a resourceVersion the API server still
// has history for, which is on the order of minutes with default etcd compaction.
// Resumption therefore helps restarts and rollouts, and longer outages fall back
// to a re-list.
//
// Note: client-go's watchtools.NewRetryWatcher was considered, but does not fit here:
//  1. It swallows watch.Bookmark events internally to update its own resourceVersion
//     rather than delivering them to the consumer, preventing the store from durably
//     advancing its persisted resourceVersion during idle periods via Bookmark().
//  2. It retries indefinitely on initial watch errors (including 410 Gone / ResourceExpired)
//     rather than allowing fallback to LIST.
//  3. It rejects empty initial resourceVersions ("").
//
// Therefore, we implement a concise watch loop directly.
type WatchLoop struct {
	listerWatcher toolscache.ListerWatcherWithContext
	store         Store
	backoff       wait.Backoff
}

func defaultBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.1,
		Steps:    7,
		Cap:      10 * time.Second,
	}
}

// WatchLoopOption configures a WatchLoop instance.
type WatchLoopOption func(*WatchLoop)

// WithBackoff sets the exponential backoff parameters for the watch loop.
func WithBackoff(backoff wait.Backoff) WatchLoopOption {
	return func(w *WatchLoop) {
		w.backoff = backoff
	}
}

// NewWatchLoop creates a new WatchLoop for the given ListerWatcher and Store.
func NewWatchLoop(listerWatcher toolscache.ListerWatcher, store Store, options ...WatchLoopOption) *WatchLoop {
	loop := &WatchLoop{
		listerWatcher: toolscache.ToListerWatcherWithContext(listerWatcher),
		store:         store,
		backoff:       defaultBackoff(),
	}
	for _, option := range options {
		option(loop)
	}
	return loop
}

// Run runs the watch loop until the context is canceled or a fatal store error occurs.
// At start-up, if the store provides a stored resourceVersion, the initial LIST is skipped
// and the watch resumes from it. Resumption only works while the API server still has history
// for that resourceVersion (on the order of minutes with default compaction); if the
// resourceVersion has expired (410 Gone / Expired), the loop falls back to LIST and Replace.
// It stops cleanly on context cancellation with no goroutine leak.
func (w *WatchLoop) Run(ctx context.Context) error {
	if w.listerWatcher == nil {
		return errors.New("listerWatcher cannot be nil")
	}
	if w.store == nil {
		return errors.New("store cannot be nil")
	}

	currentBackoff := w.backoff
	resourceVersion := w.store.LastStoreSyncResourceVersion()
	fallbackToList := resourceVersion == ""

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if fallbackToList {
			newResourceVersion, err := w.listAndReplace(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				var storeErr *StoreError
				if errors.As(err, &storeErr) {
					return err
				}
				klog.FromContext(ctx).Error(err, "Failed to list and replace store contents; retrying")
				if err := w.waitBackoff(ctx, &currentBackoff); err != nil {
					return nil
				}
				continue
			}
			resourceVersion = newResourceVersion
			fallbackToList = false
			currentBackoff = w.backoff
		}

		watcher, err := w.listerWatcher.WatchWithContext(ctx, metav1.ListOptions{
			ResourceVersion:     resourceVersion,
			AllowWatchBookmarks: true,
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isExpired(err) {
				klog.FromContext(ctx).V(2).Info("Watch failed with expired resourceVersion; falling back to LIST", "resourceVersion", resourceVersion, "err", err)
				fallbackToList = true
				continue
			}
			klog.FromContext(ctx).Error(err, "Failed to start watch; retrying", "resourceVersion", resourceVersion)
			if err := w.waitBackoff(ctx, &currentBackoff); err != nil {
				return nil
			}
			continue
		}

		start := time.Now()
		nextResourceVersion, eventCount, err := w.receive(ctx, watcher, resourceVersion)
		resourceVersion = nextResourceVersion
		if err != nil {
			if errors.Is(err, errExpired) {
				fallbackToList = true
				continue
			}
			var storeErr *StoreError
			if errors.As(err, &storeErr) {
				return err
			}
			if err := w.waitBackoff(ctx, &currentBackoff); err != nil {
				return nil
			}
		} else {
			if eventCount > 0 || time.Since(start) >= currentBackoff.Duration {
				currentBackoff = w.backoff
			} else {
				if err := w.waitBackoff(ctx, &currentBackoff); err != nil {
					return nil
				}
			}
		}
	}
}

func (w *WatchLoop) waitBackoff(ctx context.Context, backoff *wait.Backoff) error {
	delay := backoff.Step()
	if delay <= 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (w *WatchLoop) listAndReplace(ctx context.Context) (string, error) {
	listObject, err := w.listerWatcher.ListWithContext(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to list: %w", err)
	}

	listAccessor, err := meta.ListAccessor(listObject)
	if err != nil {
		return "", fmt.Errorf("unable to understand list result: %w", err)
	}
	resourceVersion := listAccessor.GetResourceVersion()

	items, err := meta.ExtractList(listObject)
	if err != nil {
		return "", fmt.Errorf("unable to extract list items: %w", err)
	}

	found := make([]any, len(items))
	for i, item := range items {
		found[i] = item
	}

	if err := w.store.Replace(found, resourceVersion); err != nil {
		return "", &StoreError{Err: fmt.Errorf("failed to replace store contents: %w", err)}
	}
	return resourceVersion, nil
}

func (w *WatchLoop) receive(ctx context.Context, watcher watch.Interface, initialResourceVersion string) (string, int, error) {
	defer watcher.Stop()
	resultChan := watcher.ResultChan()

	currentResourceVersion := initialResourceVersion
	eventCount := 0

	for {
		select {
		case <-ctx.Done():
			return currentResourceVersion, eventCount, nil
		case event, ok := <-resultChan:
			if !ok {
				return currentResourceVersion, eventCount, nil
			}

			switch event.Type {
			case watch.Added:
				if err := w.store.Add(event.Object); err != nil {
					return currentResourceVersion, eventCount, &StoreError{Err: fmt.Errorf("failed to add object: %w", err)}
				}
			case watch.Modified:
				if err := w.store.Update(event.Object); err != nil {
					return currentResourceVersion, eventCount, &StoreError{Err: fmt.Errorf("failed to update object: %w", err)}
				}
			case watch.Deleted:
				if err := w.store.Delete(event.Object); err != nil {
					return currentResourceVersion, eventCount, &StoreError{Err: fmt.Errorf("failed to delete object: %w", err)}
				}
			case watch.Bookmark:
				accessor, err := meta.Accessor(event.Object)
				if err != nil {
					klog.FromContext(ctx).Error(err, "Unable to extract resourceVersion from bookmark event")
					continue
				}
				bookmarkResourceVersion := accessor.GetResourceVersion()
				if bookmarkResourceVersion != "" {
					currentResourceVersion = bookmarkResourceVersion
					w.store.Bookmark(bookmarkResourceVersion)
				}
				eventCount++
				continue
			case watch.Error:
				if isExpiredEvent(event.Object) {
					klog.FromContext(ctx).V(2).Info("Watch reported resourceVersion expired; falling back to LIST")
					return currentResourceVersion, eventCount, errExpired
				}
				err := apierrors.FromObject(event.Object)
				klog.FromContext(ctx).Error(err, "Watch received error event")
				return currentResourceVersion, eventCount, errWatchError
			default:
				klog.FromContext(ctx).V(2).Info("Watch received unrecognized event type", "type", event.Type)
				continue
			}

			accessor, err := meta.Accessor(event.Object)
			if err != nil {
				klog.FromContext(ctx).Error(err, "Unable to extract resourceVersion from event")
			} else if eventResourceVersion := accessor.GetResourceVersion(); eventResourceVersion != "" {
				currentResourceVersion = eventResourceVersion
			}
			eventCount++
		}
	}
}

func isExpired(err error) bool {
	return apierrors.IsResourceExpired(err) || apierrors.IsGone(err)
}

func isExpiredEvent(object runtime.Object) bool {
	return isExpired(apierrors.FromObject(object))
}
