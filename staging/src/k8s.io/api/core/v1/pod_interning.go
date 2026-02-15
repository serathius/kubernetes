package v1

import (
	fmt "fmt"
	io "io"
	"sync"
	"weak"

	"k8s.io/apimachinery/pkg/util/intern"
	"k8s.io/component-base/featuregate/testing"
)

var (
	podSpecCache     = make(map[string]weak.Pointer[PodSpec])
	podSpecCacheLock sync.RWMutex
)
var enablePodSpec = false

func SetInternPodSpec(tb testing.TB, new bool) {
	old := enablePodSpec
	tb.Cleanup(func() {
		enablePodSpec = old
	})
	enablePodSpec = new
}


// internPodSpec handles unmarshaling with deduplication.
// It accepts a host object (the Pod) to check if interning should be enabled.
func internPodSpec(data []byte, target *PodSpec) error {
	if !enablePodSpec {
		return target.Unmarshal(data)
	}
	// Try lock-free lookup (if map was concurrent safe, but it's not).
	// Use RLock. string(data) does not allocate when used in map lookup.
	podSpecCacheLock.RLock()
	weakPtr, ok := podSpecCache[string(data)]
	podSpecCacheLock.RUnlock()

	if ok {
		if cached := weakPtr.Value(); cached != nil {
			// Hit: Shallow copy from cached spec.
			*target = *cached
			// Deep copy maps to avoid sharing mutable state.
			deepCopyResourceRequirements(target)
			return nil
		}
	}

	// Miss: Unmarshal normally
	if err := target.Unmarshal(data); err != nil {
		return err
	}
	// Double check with lock
	podSpecCacheLock.Lock()
	defer podSpecCacheLock.Unlock()

	if weakPtr, ok := podSpecCache[string(data)]; ok {
		if cached := weakPtr.Value(); cached != nil {
			*target = *cached
			// Deep copy maps to avoid sharing mutable state.
			deepCopyResourceRequirements(target)
			return nil
		}
	}

	// Cache it.
	// We allocate a new PodSpec on the heap to keep in cache.
	heapSpec := new(PodSpec)
	*heapSpec = *target

	// Allocate key only on insert
	podSpecCache[string(data)] = weak.Make(heapSpec)

	return nil
}

func deepCopyResourceRequirements(spec *PodSpec) {
	// Helper to deep copy ResourceList
	copyResourceList := func(rl ResourceList) ResourceList {
		if rl == nil {
			return nil
		}
		out := make(ResourceList, len(rl))
		for k, v := range rl {
			out[k] = v
		}
		return out
	}

	// Helper to process a list of containers
	processContainers := func(containers []Container) []Container {
		var newContainers []Container
		for i, c := range containers {
			if len(c.Resources.Limits) > 0 || len(c.Resources.Requests) > 0 {
				if newContainers == nil {
					// Allocate new slice and copy previous elements
					newContainers = make([]Container, len(containers))
					copy(newContainers, containers)
				}
				// Deep copy Resources for this container
				newContainers[i].Resources.Limits = copyResourceList(c.Resources.Limits)
				newContainers[i].Resources.Requests = copyResourceList(c.Resources.Requests)
			}
		}
		if newContainers != nil {
			return newContainers
		}
		return containers
	}

	spec.InitContainers = processContainers(spec.InitContainers)
	spec.Containers = processContainers(spec.Containers)
	
	// EphemeralContainers are slightly different type but same structure for Resources
	processEphemeralContainers := func(containers []EphemeralContainer) []EphemeralContainer {
		var newContainers []EphemeralContainer
		for i, c := range containers {
			if len(c.Resources.Limits) > 0 || len(c.Resources.Requests) > 0 {
				if newContainers == nil {
					// Allocate new slice and copy previous elements
					newContainers = make([]EphemeralContainer, len(containers))
					copy(newContainers, containers)
				}
				// Deep copy Resources for this container
				newContainers[i].Resources.Limits = copyResourceList(c.Resources.Limits)
				newContainers[i].Resources.Requests = copyResourceList(c.Resources.Requests)
			}
		}
		if newContainers != nil {
			return newContainers
		}
		return containers
	}

	spec.EphemeralContainers = processEphemeralContainers(spec.EphemeralContainers)
}

func (m *Pod) UnmarshalIntern(dAtA []byte) error {
	defer intern.InternObjectStrings(m)
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Pod: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Pod: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ObjectMeta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ObjectMeta.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Spec", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := internPodSpec(dAtA[iNdEx:postIndex], &m.Spec); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGenerated
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}