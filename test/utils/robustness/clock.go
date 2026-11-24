/*
Copyright The Kubernetes Authors.

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

package robustness

import (
	"context"
	"sync"
	"time"

	"k8s.io/utils/clock"
)

// ShiftTime advances a wrapped clock by Offset.
type ShiftTime struct {
	Offset time.Duration
}

func (a ShiftTime) ApplyClock() time.Duration {
	return a.Offset
}

// FreezeTime pins a wrapped clock at the timestamp captured on its first
// frozen read. Combining FreezeTime with ShiftTime{Offset: d} lets scenarios
// test exact timeout boundaries (e.g. Since(ts) == ExpectationsTimeout).
type FreezeTime struct{}

func (FreezeTime) ApplyClockFreeze() bool {
	return true
}

// FaultInjectingClock wraps k8s.io/utils/clock.Clock and intercepts Now() and Since().
type FaultInjectingClock struct {
	clock.Clock
	ctx      context.Context // bounds BlockingFault actions
	registry *FaultRegistry
	name     string

	mu       sync.Mutex
	frozenAt time.Time
}

// NewFaultInjectingClock creates a wrapped clock.Clock hooked to the registry.
func NewFaultInjectingClock(ctx context.Context, realClock clock.Clock, registry *FaultRegistry, name string) clock.Clock {
	return &FaultInjectingClock{
		Clock:    realClock,
		ctx:      ctx,
		registry: registry,
		name:     name,
	}
}

func (c *FaultInjectingClock) Now() time.Time {
	realNow := c.Clock.Now()
	shift, frozen := c.registry.ResolveClockState(c.ctx, ClockFacts{Clock: c.name})
	base := realNow
	c.mu.Lock()
	if frozen {
		if c.frozenAt.IsZero() {
			c.frozenAt = realNow
		}
		base = c.frozenAt
	} else if !c.frozenAt.IsZero() {
		c.frozenAt = time.Time{}
	}
	c.mu.Unlock()
	return base.Add(shift)
}

func (c *FaultInjectingClock) Since(t time.Time) time.Duration {
	return c.Now().Sub(t)
}
