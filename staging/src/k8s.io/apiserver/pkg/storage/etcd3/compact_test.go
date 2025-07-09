/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package etcd3

import (
	"context"
	"testing"
	"time"

	etcdrpc "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"k8s.io/apiserver/pkg/storage/etcd3/testserver"
	testingclock "k8s.io/utils/clock/testing"
)

const (
	waitDelay   = time.Millisecond
	waitTimeout = 100 * waitDelay
)

func TestCompact(t *testing.T) {
	ctx := context.Background()
	client := testserver.RunEtcd(t, nil).Client
	clock := testingclock.NewFakeClock(time.Now())
	c := newCompactor(client, time.Minute, clock)
	t.Cleanup(c.Stop)
	for !clock.HasWaiters() {
		time.Sleep(time.Millisecond)
	}
	t.Log("First saves revision before first write")
	clock.Step(time.Minute)
	waitForClockWaiters(t, clock)
	compactRev := c.CompactRevision()
	if compactRev != 0 {
		t.Errorf("CompactRevision()=%d, expected %d", compactRev, 0)
	}

	t.Log("First write")
	resp1, err := client.Put(ctx, "/somekey", "data")
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	assertNotCompacted(t, ctx, client, resp1.Header.Revision)

	t.Log("Second compaction cycle compacts before first write")
	clock.Step(time.Minute)
	waitForClockWaiters(t, clock)
	assertNotCompacted(t, ctx, client, resp1.Header.Revision)
	compactRev = c.CompactRevision()
	if compactRev != resp1.Header.Revision-1 {
		t.Errorf("CompactRevision()=%d, expected %d", compactRev, 0)
	}

	t.Log("Create second revision")
	resp2, err := client.Put(ctx, "/somekey", "data")
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	assertNotCompacted(t, ctx, client, resp2.Header.Revision)

	t.Log("Third compaction cycle compacts revision after first write")
	clock.Step(time.Minute)
	waitForClockWaiters(t, clock)
	assertCompacted(t, ctx, client, resp1.Header.Revision)
	compactRev = c.CompactRevision()
	if compactRev != resp1.Header.Revision+1 {
		t.Errorf("CompactRevision()=%d, expected %d", compactRev, resp1.Header.Revision)
	}

	assertNotCompacted(t, ctx, client, resp2.Header.Revision)

	t.Log("Fourth compaction cycle compacts second write")
	clock.Step(time.Minute)
	waitForClockWaiters(t, clock)
	assertCompacted(t, ctx, client, resp1.Header.Revision)
	assertCompacted(t, ctx, client, resp2.Header.Revision)
	compactRev = c.CompactRevision()
	if compactRev != resp2.Header.Revision+1 {
		t.Errorf("CompactRevision()=%d, expected %d", compactRev, resp2.Header.Revision)
	}
}

func assertCompacted(t *testing.T, ctx context.Context, client *clientv3.Client, rev int64) {
	t.Helper()
	_, err := client.Get(ctx, "/somekey", clientv3.WithRev(rev))
	if err != etcdrpc.ErrCompacted {
		t.Errorf("Expecting rev %d compacted, but err=%v", rev, err)
	}
}

func assertNotCompacted(t *testing.T, ctx context.Context, client *clientv3.Client, rev int64) {
	t.Helper()
	_, err := client.Get(ctx, "/somekey", clientv3.WithRev(rev))
	if err != nil {
		t.Errorf("Get on rev %d failed: %v", rev, err)
	}
}

func TestCompactIntervalZero(t *testing.T) {
	client := testserver.RunEtcd(t, nil).Client
	clock := testingclock.NewFakeClock(time.Now())
	c := newCompactor(client, 0, clock)
	t.Cleanup(c.Stop)

	t.Log("Compact loop is disabled, no goroutine is waiting on clock")
	clockNoWaiters(t, clock)
	clock.Step(time.Minute)
	clockNoWaiters(t, clock)

	t.Log("Setting inverval to non zero value should start compaction loop that waits on clock")
	c.UpdateInterval(time.Minute)
	waitForClockWaiters(t, clock)
}

func waitForClockWaiters(t *testing.T, clock *testingclock.FakeClock) {
	t.Helper()
	for start := time.Now(); time.Since(start) < waitTimeout; {
		if clock.HasWaiters() {
			return
		}
		time.Sleep(waitDelay)
	}
	t.Fatal("No waiters")
}

func clockNoWaiters(t *testing.T, clock *testingclock.FakeClock) {
	t.Helper()
	for start := time.Now(); time.Since(start) < waitTimeout; {
		if clock.Waiters() != 0 {
			t.Fatal("waiter")
		}
		time.Sleep(waitDelay)
	}
	if clock.Waiters() != 0 {
		t.Fatal("waiter")
	}
}

// TestCompactConflict tests that two compactors (Let's use C1, C2) are trying to compact etcd cluster with the same
// logical time.
// - C1 compacts first. It will succeed.
// - C2 compacts after. It will fail. But it will get latest logical time, which should be larger by one.
func TestCompactConflict(t *testing.T) {
	client := testserver.RunEtcd(t, nil).Client
	ctx := context.Background()

	putResp, err := client.Put(ctx, "/somekey", "data")
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Compact first. It would do the compaction and return compact time which is incremented by 1.
	curTime, _, _, err := compact(ctx, client, 0, putResp.Header.Revision)
	if err != nil {
		t.Fatalf("compact failed: %v", err)
	}
	if curTime != 1 {
		t.Errorf("Expect current logical time = 1, get = %v", curTime)
	}

	// Compact again with the same parameters. It won't do compaction but return the latest compact time.
	curTime2, _, _, err := compact(ctx, client, 0, putResp.Header.Revision)
	if err != nil {
		t.Fatalf("compact failed: %v", err)
	}
	if curTime != curTime2 {
		t.Errorf("Unexpected curTime (%v) != curTime2 (%v)", curTime, curTime2)
	}
}
