package relay

import "sync"

// dirtyQueue is the event-driven work queue behind content following. Instead of
// re-scanning every content chain and re-verifying every grant on every sync tick
// — O(corpus) crypto + DB work per cycle, which pegs a small node at 100% CPU to
// maintain a static set — the sequencer records the specific contentIDs touched by
// ops that can change what needs (de)materializing, and the sweep drains just
// those. A `fullScan` flag forces a convergent whole-corpus pass (boot catch-up, a
// periodic backstop, or a broad/credential change whose blast radius is the whole
// corpus). When the queue is empty the sweep is a near-instant no-op, so a
// steady-state follower sits idle instead of burning a core.
//
// The convergence guarantee is preserved: the boot scan + the periodic full-scan
// backstop still reconcile "all granted blobs materialized" regardless of op
// ordering — the dirty path is a latency fast-path layered on top, not a
// replacement for the convergent sweep.
type dirtyQueue struct {
	mu       sync.Mutex
	ids      map[string]struct{}
	fullScan bool
}

func newDirtyQueue() *dirtyQueue {
	return &dirtyQueue{ids: make(map[string]struct{})}
}

// markID records a single contentID as needing a sweep.
func (q *dirtyQueue) markID(id string) {
	if id == "" {
		return
	}
	q.mu.Lock()
	q.ids[id] = struct{}{}
	q.mu.Unlock()
}

// markFull requests a convergent whole-corpus pass on the next drain.
func (q *dirtyQueue) markFull() {
	q.mu.Lock()
	q.fullScan = true
	q.mu.Unlock()
}

// take atomically snapshots and clears the queue, returning the dirty contentIDs
// and whether a full scan was requested. A caller that does a full scan can ignore
// the returned ids (the scan supersedes them).
func (q *dirtyQueue) take() (ids []string, full bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	full = q.fullScan
	q.fullScan = false
	if len(q.ids) > 0 {
		ids = make([]string, 0, len(q.ids))
		for id := range q.ids {
			ids = append(ids, id)
		}
		q.ids = make(map[string]struct{})
	}
	return ids, full
}

// empty reports whether there is no pending work (no dirty ids, no full scan).
func (q *dirtyQueue) empty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !q.fullScan && len(q.ids) == 0
}
