// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParallelReadsBoundsWorkersAndJoinsEveryResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := make(chan struct{}, 12)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	results := make([]int, 12)
	var active, maximum atomic.Int32
	tasks := make([]func(), 0, len(results))
	for i := range results {
		tasks = append(tasks, func() {
			current := active.Add(1)
			for previous := maximum.Load(); current > previous; previous = maximum.Load() {
				if maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			results[i] = i + 1
			active.Add(-1)
		})
	}
	done := make(chan struct{})
	go func() {
		parallelReads(tasks...)
		close(done)
	}()
	for range 4 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("independent reads did not start concurrently")
		}
	}
	require.Equal(t, int32(4), active.Load())
	unblock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("reads did not join")
	}
	assert.Equal(t, int32(4), maximum.Load())
	for i, value := range results {
		assert.Equal(t, i+1, value)
	}
}
