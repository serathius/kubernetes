/*
Copyright 2023 The Kubernetes Authors.

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

package cacher

import (
	"time"

	"k8s.io/apiserver/pkg/storage"

	"k8s.io/utils/clock"
)

const (
	// compactorPollPeriod determines period of reading compaction revision from storage.
	compactorPollPeriod = 15 * time.Second
)

func NewCompactor(store storage.Interface, wc *watchCache, clock TickerFactory) *compactor {
	pr := &compactor{
		clock: clock,
		store: store,
		wc:    wc,
	}
	return pr
}

type TickerFactory interface {
	NewTimer(time.Duration) clock.Timer
}

type compactor struct {
	clock TickerFactory
	store storage.Interface
	wc    *watchCache
}

func (c *compactor) Run(stopCh <-chan struct{}) {
	timer := c.clock.NewTimer(compactorPollPeriod)
	defer timer.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-timer.C():
			c.compact()
			timer.Reset(compactorPollPeriod)
		}
	}
}

func (c *compactor) compact() {
	rev := c.store.CompactRevision()
	if rev != 0 {
		c.wc.Compact(rev)
	}
}
