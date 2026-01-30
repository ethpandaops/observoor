package aggregated

import "sync/atomic"

// Histogram bucket boundaries in nanoseconds.
// 10 buckets: 1us, 10us, 100us, 1ms, 10ms, 100ms, 1s, 10s, 100s, +inf.
const (
	bucket1us   = 1_000           // 1 microsecond
	bucket10us  = 10_000          // 10 microseconds
	bucket100us = 100_000         // 100 microseconds
	bucket1ms   = 1_000_000       // 1 millisecond
	bucket10ms  = 10_000_000      // 10 milliseconds
	bucket100ms = 100_000_000     // 100 milliseconds
	bucket1s    = 1_000_000_000   // 1 second
	bucket10s   = 10_000_000_000  // 10 seconds
	bucket100s  = 100_000_000_000 // 100 seconds
	numBuckets  = 10
)

// Histogram is an exponential histogram with 10 buckets for latency values.
// All operations are atomic and safe for concurrent use.
type Histogram struct {
	buckets [numBuckets]atomic.Uint64
}

// Add records a value (in nanoseconds) to the appropriate bucket.
func (h *Histogram) Add(valueNs uint64) {
	idx := bucketIndex(valueNs)
	h.buckets[idx].Add(1)
}

// Snapshot returns the current bucket counts.
// Returns [1us, 10us, 100us, 1ms, 10ms, 100ms, 1s, 10s, 100s, inf].
func (h *Histogram) Snapshot() [numBuckets]uint64 {
	var result [numBuckets]uint64
	for i := range h.buckets {
		result[i] = h.buckets[i].Load()
	}

	return result
}

// Reset returns the current bucket counts and resets them to zero.
func (h *Histogram) Reset() [numBuckets]uint64 {
	var result [numBuckets]uint64
	for i := range h.buckets {
		result[i] = h.buckets[i].Swap(0)
	}

	return result
}

// bucketIndex returns the bucket index for a given value in nanoseconds.
func bucketIndex(valueNs uint64) int {
	switch {
	case valueNs < bucket1us:
		return 0 // <1us bucket
	case valueNs < bucket10us:
		return 1 // 1us-10us
	case valueNs < bucket100us:
		return 2 // 10us-100us
	case valueNs < bucket1ms:
		return 3 // 100us-1ms
	case valueNs < bucket10ms:
		return 4 // 1ms-10ms
	case valueNs < bucket100ms:
		return 5 // 10ms-100ms
	case valueNs < bucket1s:
		return 6 // 100ms-1s
	case valueNs < bucket10s:
		return 7 // 1s-10s
	case valueNs < bucket100s:
		return 8 // 10s-100s
	default:
		return 9 // 100s+
	}
}

// BucketBoundaries returns the upper bounds for each bucket in nanoseconds.
// The last bucket (index 9) is unbounded (+inf).
func BucketBoundaries() [numBuckets]uint64 {
	return [numBuckets]uint64{
		bucket1us,
		bucket10us,
		bucket100us,
		bucket1ms,
		bucket10ms,
		bucket100ms,
		bucket1s,
		bucket10s,
		bucket100s,
		0, // +inf (represented as 0)
	}
}
