package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

type fieldSize struct {
	name  string
	size  int
	count int
	subs  []*fieldSize
}

type flatField struct {
	segments []string
	size     int
	count    int
}

func (f *fieldSize) flatten(parentSegments []string, result *[]flatField) {
	// Create a new slice to avoid sharing backing array in recursion
	currentSegments := make([]string, len(parentSegments)+1)
	copy(currentSegments, parentSegments)
	currentSegments[len(parentSegments)] = f.name

	// Calculate self size (size excluding children)

	// Filter logic:
	// 1. If leaf (no children), show if size > 100
	// 2. If not leaf, show if selfSize > 1000 (significant overhead/content)
	// 3. Always show root? Maybe not needed if root is just a wrapper.

	show := false
	if f.size > 100 {
		show = true
	}

	if show {
		*result = append(*result, flatField{
			segments: currentSegments,
			size:     f.size,
			count:    f.count,
		})
	}

	for _, sub := range f.subs {
		sub.flatten(currentSegments, result)
	}
}

func (f *fieldSize) printTable() {
	var rows []flatField
	f.flatten(nil, &rows)

	// Sort by size descending
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].size > rows[j].size
	})

	// Find max depth
	maxDepth := 0
	for _, row := range rows {
		if len(row.segments) > maxDepth {
			maxDepth = len(row.segments)
		}
	}

	// Header
	for i := 0; i < maxDepth; i++ {
		fmt.Printf("L%d\t", i+1)
	}
	fmt.Println("Size\tCount")

	for _, row := range rows {
		for i := 0; i < maxDepth; i++ {
			if i < len(row.segments) {
				fmt.Printf("%s\t", row.segments[i])
			} else {
				fmt.Print("\t")
			}
		}
		fmt.Printf("%d\t%d\n", row.size, row.count)
	}
}

func (f *fieldSize) generateSunburst(filename string) error {
	width := 1000
	height := 1000
	cx := float64(width) / 2
	cy := float64(height) / 2
	radius := 450.0
	maxLevels := 10

	var svg strings.Builder
	svg.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n")
	svg.WriteString(fmt.Sprintf("<svg width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" xmlns=\"http://www.w3.org/2000/svg\">\n", width, height, width, height))
	svg.WriteString(fmt.Sprintf("<rect width=\"%d\" height=\"%d\" fill=\"white\"/>\n", width, height))
	svg.WriteString("<style>.label { font-family: Arial; font-size: 10px; fill: black; pointer-events: none; }</style>\n")

	colors := []string{
		"#4285F4", "#DB4437", "#F4B400", "#0F9D58", "#AB47BC",
		"#00ACC1", "#FF7043", "#9E9D24", "#5C6BC0", "#F06292",
		"#5D4037", "#E64A19", "#7B1FA2", "#1976D2", "#388E3C",
	}

	var draw func(node *fieldSize, startAngle, endAngle float64, depth int, color string)
	draw = func(node *fieldSize, startAngle, endAngle float64, depth int, color string) {
		if depth >= maxLevels {
			return
		}

		// Don't draw if angle is too small (e.g. < 0.2 degrees)
		if (endAngle - startAngle) < 0.0035 {
			return
		}

		ringWidth := radius / float64(maxLevels)
		innerR := float64(depth) * ringWidth
		outerR := float64(depth+1) * ringWidth

		// Draw current segment
		// For root (depth 0), we draw a circle
		if depth == 0 {
			svg.WriteString(fmt.Sprintf("<circle cx=\"%.2f\" cy=\"%.2f\" r=\"%.2f\" fill=\"%s\" stroke=\"white\" stroke-width=\"1\"/>\n", cx, cy, outerR, color))
			svg.WriteString(fmt.Sprintf("<text x=\"%.2f\" y=\"%.2f\" text-anchor=\"middle\" alignment-baseline=\"middle\" font-family=\"Arial\" font-size=\"12\">%s</text>\n", cx, cy, node.name))
		} else {
			x1 := cx + innerR*math.Cos(startAngle-math.Pi/2)
			y1 := cy + innerR*math.Sin(startAngle-math.Pi/2)
			x2 := cx + outerR*math.Cos(startAngle-math.Pi/2)
			y2 := cy + outerR*math.Sin(startAngle-math.Pi/2)
			x3 := cx + outerR*math.Cos(endAngle-math.Pi/2)
			y3 := cy + outerR*math.Sin(endAngle-math.Pi/2)
			x4 := cx + innerR*math.Cos(endAngle-math.Pi/2)
			y4 := cy + innerR*math.Sin(endAngle-math.Pi/2)

			largeArc := 0
			if (endAngle - startAngle) > math.Pi {
				largeArc = 1
			}

			path := fmt.Sprintf("M %.2f %.2f L %.2f %.2f A %.2f %.2f 0 %d 1 %.2f %.2f L %.2f %.2f A %.2f %.2f 0 %d 0 %.2f %.2f Z",
				x1, y1, x2, y2, outerR, outerR, largeArc, x3, y3, x4, y4, innerR, innerR, largeArc, x1, y1)

			svg.WriteString(fmt.Sprintf("<g>\n"))
			svg.WriteString(fmt.Sprintf("<path d=\"%s\" fill=\"%s\" stroke=\"white\" stroke-width=\"1\"/>\n", path, color))
			svg.WriteString(fmt.Sprintf("<title>%s: %d bytes</title>\n", node.name, node.size))

			// Label if large enough
			if (endAngle - startAngle) > 0.1 { // > ~6 degrees
				midAngle := (startAngle + endAngle) / 2
				textR := (innerR + outerR) / 2
				tx := cx + textR*math.Cos(midAngle-math.Pi/2)
				ty := cy + textR*math.Sin(midAngle-math.Pi/2)

				// Rotate text?
				// rotation := midAngle * 180 / math.Pi
				// svg.WriteString(fmt.Sprintf("<text x=\"%.2f\" y=\"%.2f\" transform=\"rotate(%.2f %.2f %.2f)\" text-anchor=\"middle\" alignment-baseline=\"middle\" class=\"label\">%s</text>\n", tx, ty, rotation, tx, ty, node.name))
				// Simple text for now
				svg.WriteString(fmt.Sprintf("<text x=\"%.2f\" y=\"%.2f\" text-anchor=\"middle\" alignment-baseline=\"middle\" class=\"label\">%s</text>\n", tx, ty, node.name))
			}
			svg.WriteString(fmt.Sprintf("</g>\n"))
		}

		// Draw children
		currentStart := startAngle
		totalSize := float64(node.size)

		// Sort subs by size
		sortedSubs := make([]*fieldSize, len(node.subs))
		copy(sortedSubs, node.subs)
		sort.Slice(sortedSubs, func(i, j int) bool {
			return sortedSubs[i].size > sortedSubs[j].size
		})

		for i, sub := range sortedSubs {
			subRatio := float64(sub.size) / totalSize
			subAngle := (endAngle - startAngle) * subRatio

			subColor := color
			if depth == 0 {
				subColor = colors[i%len(colors)]
			} else {
				// Keep parent color but maybe vary opacity or just keep it?
				// Sunbursts usually keep hue.
				// Let's just keep it for now, or cycle if we want rainbow.
				// User wants nested, so keeping hue helps identify hierarchy.
				// But if we keep exact color, borders are invisible.
				// We have white borders, so it's fine.
				// Maybe darken/lighten? Too complex for simple SVG string.
				// Let's just reuse parent color.
				// Actually, if we reuse parent color, it looks like one big block.
				// Let's try to shift color slightly or just use the palette again for contrast?
				// Using palette again makes it colorful but loses hierarchy.
				// Let's use palette for depth 1, and for depth > 1 reuse parent color.
				// Wait, if I reuse parent color for all children, they merge.
				// I need to vary them.
				// Let's just cycle colors at all levels for maximum contrast.
				subColor = colors[(i+depth)%len(colors)]
			}

			draw(sub, currentStart, currentStart+subAngle, depth+1, subColor)
			currentStart += subAngle
		}
	}

	draw(f, 0, 2*math.Pi, 0, "#CCCCCC")

	svg.WriteString("</svg>")
	return os.WriteFile(filename, []byte(svg.String()), 0644)
}

func AnalyzeObject(data []byte, chartFile string) error {
	// Skip magic header if present
	if len(data) >= 4 && string(data[:4]) == "k8s\x00" {
		data = data[4:]
	}

	// Try to detect if it's a runtime.Unknown wrapper
	// Field 1: TypeMeta (Kind, APIVersion)
	// Field 2: Raw (bytes)

	var kind string
	var rawData []byte

	offset := 0
	for offset < len(data) {
		tag, n := decodeVarint(data[offset:])
		if n == 0 {
			break
		}
		// tagStart := offset
		offset += n
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)

		if fieldNum == 1 && wireType == 2 {
			// TypeMeta
			l, n := decodeVarint(data[offset:])
			if n == 0 {
				break
			}
			length := int(l)
			metaStart := offset + n
			if metaStart+length <= len(data) {
				metaData := data[metaStart : metaStart+length]
				// Parse TypeMeta to find Kind (field 1)
				metaOffset := 0
				for metaOffset < len(metaData) {
					mTag, mN := decodeVarint(metaData[metaOffset:])
					if mN == 0 {
						break
					}
					metaOffset += mN
					mFieldNum := int(mTag >> 3)
					mWireType := int(mTag & 7)

					if mFieldNum == 1 && mWireType == 2 {
						// Kind
						kL, kN := decodeVarint(metaData[metaOffset:])
						if kN == 0 {
							break
						}
						kLength := int(kL)
						kStart := metaOffset + kN
						if kStart+kLength <= len(metaData) {
							kind = string(metaData[kStart : kStart+kLength])
						}
						break // Found Kind, stop parsing TypeMeta
					}

					// Skip other fields in TypeMeta
					switch mWireType {
					case 0:
						_, n := decodeVarint(metaData[metaOffset:])
						metaOffset += n
					case 1:
						metaOffset += 8
					case 2:
						l, n := decodeVarint(metaData[metaOffset:])
						metaOffset += n + int(l)
					case 5:
						metaOffset += 4
					default:
						metaOffset = len(metaData)
					}
				}
			}
			offset += n + length
		} else if fieldNum == 2 && wireType == 2 {
			// Raw data
			l, n := decodeVarint(data[offset:])
			if n == 0 {
				break
			}
			length := int(l)
			start := offset + n
			if start+length <= len(data) {
				rawData = data[start : start+length]
			}
			offset += n + length
		} else {
			// Skip other fields
			switch wireType {
			case 0:
				_, n := decodeVarint(data[offset:])
				offset += n
			case 1:
				offset += 8
			case 2:
				l, n := decodeVarint(data[offset:])
				offset += n + int(l)
			case 5:
				offset += 4
			default:
				// Unknown wire type, stop parsing wrapper
				offset = len(data)
			}
		}
	}

	if len(rawData) > 0 {
		data = rawData
	}

	// Default to Pod if kind not found or looks like APIVersion
	if kind == "" || strings.Contains(kind, "/") || kind == "v1" {
		if kind != "" {
			fmt.Fprintf(os.Stderr, "Warning: Detected Kind '%s' looks like APIVersion, ignoring\n", kind)
		}

		// Heuristic detection
		// Check if it looks like a StatefulSet or Pod based on Spec (Field 2)
		// Pod Spec Field 3 is RestartPolicy (String)
		// StatefulSet Spec Field 3 is Template (Message)
		// StatefulSet Spec Field 5 is ServiceName (String, Wire 2)
		// Pod Spec Field 5 is ActiveDeadlineSeconds (Varint, Wire 0)

		isStatefulSet := false
		if len(rawData) > 0 {
			// Peek into rawData (which is the object)
			// Find Field 2 (Spec)
			specData := getFieldContent(rawData, 2, 2)
			if len(specData) > 0 {
				// Check for Field 5
				// If Field 5 exists and is Wire 2, it's likely StatefulSet (ServiceName)
				// If Field 5 exists and is Wire 0, it's likely Pod (ActiveDeadlineSeconds)

				// We need to scan specData for Field 5
				f5Wire := getFieldWireType(specData, 5)
				if f5Wire == 2 {
					isStatefulSet = true
				} else if f5Wire == -1 {
					// Field 5 missing, check Field 3
					f3 := getFieldContent(specData, 3, 2)
					if len(f3) > 0 {
						// If it starts with 0x0a (Field 1, Wire 2 - metadata) or 0x12 (Field 2, Wire 2 - spec), it's likely a Template
						if f3[0] == 0x0a || f3[0] == 0x12 {
							isStatefulSet = true
						}
					}
				}
			}
		}

		if isStatefulSet {
			kind = "StatefulSet"
			fmt.Fprintf(os.Stderr, "Warning: Heuristic identified StatefulSet\n")
		} else {
			kind = "Pod"
			fmt.Fprintf(os.Stderr, "Warning: Heuristic assuming Pod\n")
		}
	} else {
		fmt.Printf("Detected Kind: %s\n", kind)
	}

	var objType reflect.Type
	switch kind {
	case "Pod":
		objType = reflect.TypeOf(v1.Pod{})
	case "StatefulSet":
		objType = reflect.TypeOf(appsv1.StatefulSet{})
	case "Deployment":
		objType = reflect.TypeOf(appsv1.Deployment{})
	case "ReplicaSet":
		objType = reflect.TypeOf(appsv1.ReplicaSet{})
	case "DaemonSet":
		objType = reflect.TypeOf(appsv1.DaemonSet{})
	case "Service":
		objType = reflect.TypeOf(v1.Service{})
	default:
		fmt.Fprintf(os.Stderr, "Warning: Unknown kind %s, using generic analysis (might be inaccurate)\n", kind)
		objType = reflect.TypeOf(v1.Pod{})
	}

	root := &fieldSize{name: kind, size: len(data), count: 1}

	if err := analyzeMessage(data, objType, root); err != nil {
		return err
	}

	if chartFile != "" {
		svgFile := chartFile
		if strings.HasSuffix(chartFile, ".png") {
			svgFile = strings.TrimSuffix(chartFile, ".png") + ".svg"
		}

		if err := root.generateSunburst(svgFile); err != nil {
			return err
		}
		fmt.Printf("Sunburst chart generated at %s\n", svgFile)

		if strings.HasSuffix(chartFile, ".png") {
			// Convert to PNG using magick
			cmd := exec.Command("magick", svgFile, chartFile)
			if output, err := cmd.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to convert SVG to PNG: %v\nOutput: %s\n", err, output)
				// Don't fail the whole operation, just warn
			} else {
				fmt.Printf("Converted to PNG at %s\n", chartFile)
				os.Remove(svgFile)
			}
		}
	}

	root.printTable()
	return nil
}

func getFieldWireType(data []byte, targetField int) int {
	offset := 0
	for offset < len(data) {
		tag, n := decodeVarint(data[offset:])
		if n == 0 {
			break
		}
		offset += n
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)

		if fieldNum == targetField {
			return wireType
		}

		switch wireType {
		case 0:
			_, n := decodeVarint(data[offset:])
			offset += n
		case 1:
			offset += 8
		case 2:
			l, n := decodeVarint(data[offset:])
			offset += n + int(l)
		case 5:
			offset += 4
		default:
			return -2 // Unknown
		}
	}
	return -1 // Not found
}

func getFieldContent(data []byte, targetField int, targetWire int) []byte {
	offset := 0
	for offset < len(data) {
		tag, n := decodeVarint(data[offset:])
		if n == 0 {
			break
		}
		offset += n
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)

		if fieldNum == targetField && wireType == targetWire {
			l, n := decodeVarint(data[offset:])
			if n == 0 {
				return nil
			}
			length := int(l)
			start := offset + n
			if start+length <= len(data) {
				return data[start : start+length]
			}
			return nil
		}

		switch wireType {
		case 0:
			_, n := decodeVarint(data[offset:])
			offset += n
		case 1:
			offset += 8
		case 2:
			l, n := decodeVarint(data[offset:])
			offset += n + int(l)
		case 5:
			offset += 4
		default:
			return nil
		}
	}
	return nil
}

func analyzeMessage(data []byte, t reflect.Type, node *fieldSize) error {
	// Map field numbers to struct fields
	fields := make(map[int]reflect.StructField)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return nil
	}

	// Helper to collect fields recursively from embedded structs
	var collectFields func(reflect.Type)
	collectFields = func(st reflect.Type) {
		// Pass 1: Collect direct fields (with tags)
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			tag := f.Tag.Get("protobuf")
			if tag != "" {
				parts := strings.Split(tag, ",")
				if len(parts) >= 2 {
					var fieldNum int
					if _, err := fmt.Sscanf(parts[1], "%d", &fieldNum); err == nil {
						if _, exists := fields[fieldNum]; !exists {
							fields[fieldNum] = f
						}
					}
				}
			}
		}

		// Pass 2: Recurse into embedded fields
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			if f.Anonymous {
				et := f.Type
				if et.Kind() == reflect.Ptr {
					et = et.Elem()
				}
				if et.Kind() == reflect.Struct {
					collectFields(et)
				}
			}
		}
	}

	collectFields(t)

	offset := 0
	for offset < len(data) {
		if offset+1 > len(data) {
			break
		}

		tag, n := decodeVarint(data[offset:])
		if n == 0 {
			break
		}
		tagStart := offset
		offset += n

		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)

		var content []byte

		switch wireType {
		case 0: // Varint
			_, n := decodeVarint(data[offset:])
			if n == 0 {
				return fmt.Errorf("error decoding varint at %d", offset)
			}
			offset += n
		case 1: // Fixed64
			offset += 8
		case 2: // Length Delimited
			l, n := decodeVarint(data[offset:])
			if n == 0 {
				return fmt.Errorf("error decoding length at %d", offset)
			}
			length := int(l)
			offset += n
			if offset+length > len(data) {
				return fmt.Errorf("length %d exceeds remaining data", length)
			}
			content = data[offset : offset+length]
			offset += length
		case 5: // Fixed32
			offset += 4
		default:
			return fmt.Errorf("unknown wire type %d at %d", wireType, offset)
		}

		totalSize := (offset - tagStart)

		fieldName := fmt.Sprintf("UnknownField-%d", fieldNum)
		var fieldType reflect.Type
		if f, ok := fields[fieldNum]; ok {
			fieldName = f.Name
			fieldType = f.Type
		} else if t == reflect.TypeOf(v1.Volume{}) && fieldNum == 17 {
			fieldName = "ManagedFields"
			// We don't have a type for it easily available, but we know it's a struct (ManagedFieldsEntry)
			// We can try to find it from metav1 package if we imported it, or just leave type nil
			// If type is nil, we won't recurse with type info, but we can still show size.
		}

		var sub *fieldSize
		for _, s := range node.subs {
			if s.name == fieldName {
				sub = s
				break
			}
		}
		if sub == nil {
			sub = &fieldSize{name: fieldName}
			node.subs = append(node.subs, sub)
		}

		sub.size += totalSize
		sub.count++

		if wireType == 2 && fieldType != nil {
			ft := fieldType
			if ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}

			if ft.Kind() == reflect.Struct {
				if err := analyzeMessage(content, ft, sub); err != nil {
					// ignore error
				}
			} else if ft.Kind() == reflect.Slice {
				// Repeated field.
				elem := ft.Elem()
				if elem.Kind() == reflect.Ptr {
					elem = elem.Elem()
				}
				if elem.Kind() == reflect.Struct {
					if err := analyzeMessage(content, elem, sub); err != nil {
						// ignore error
					}
				}
			}
		}
	}
	return nil
}

func decodeVarint(data []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range data {
		if b < 0x80 {
			if i > 9 || i == 9 && b > 1 {
				return 0, 0 // overflow
			}
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}
