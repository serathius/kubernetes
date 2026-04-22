package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/yaml"
)

func main() {
	analyze := false
	chartFile := ""
	args := os.Args[1:]
	for len(args) > 0 {
		if args[0] == "-analyze" {
			analyze = true
			args = args[1:]
		} else if args[0] == "-chart" {
			if len(args) > 1 {
				chartFile = args[1]
				args = args[2:]
			} else {
				fmt.Fprintf(os.Stderr, "Missing argument for -chart\n")
				os.Exit(1)
			}
		} else {
			break
		}
	}

	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-analyze] [-chart file.svg] [file]\n", os.Args[0])
		os.Exit(1)
	}

	var data []byte
	var err error
	if len(args) == 0 {
		config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
		if err != nil {
			fmt.Printf("failed to read kube config: %s\n", err)
			os.Exit(1)
		}
		config.ContentType = "application/vnd.kubernetes.protobuf"
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Printf("failed to create client: %s\n", err)
			os.Exit(1)
		}
		data, err = clientset.RESTClient().Get().RequestURI("/api/v1/namespaces/0/pods/999").DoRaw(context.Background())
		if err != nil {
			fmt.Printf("failed to get pod: %s\n", err)
			os.Exit(1)
		}
	} else if len(args) == 1 {
		filename := args[0]
		data, err = os.ReadFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filename, err)
			os.Exit(1)
		}
	}

	// Check if it needs unescaping (simple heuristic: ends with .txt or contains escaped nulls)
	if len(data) > 0 && bytes.Contains(data, []byte("\\000")) {
		// Trim whitespace (newlines etc) from the end
		data = bytes.TrimSpace(data)

		// Try to unquote if it looks like a quoted string, or just unescape
		s := string(data)
		// If it's not quoted, wrap it in quotes to use strconv.Unquote
		if len(s) > 0 && s[0] != '"' {
			s = "\"" + s + "\""
		}
		if unquoted, err := strconv.Unquote(s); err == nil {
			data = []byte(unquoted)
		} else {
			// Fallback: manual unescaping for common escapes if Unquote fails.
			// The input might be a mix of printable characters and escapes like \000, \n, \r.
			// It might not be a valid Go quoted string (e.g. contains unescaped newlines or quotes).
			// Let's try to replace known escapes.

			// Simple state machine to unescape
			var buf bytes.Buffer
			inEscape := false
			// We use the original string data (without added quotes) for manual unescaping
			s = string(data)
			for i := 0; i < len(s); i++ {
				if inEscape {
					if s[i] >= '0' && s[i] <= '7' {
						// Octal escape? \nnn
						if i+2 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' && s[i+2] >= '0' && s[i+2] <= '7' {
							val, _ := strconv.ParseInt(s[i:i+3], 8, 32)
							buf.WriteByte(byte(val))
							i += 2
						} else {
							// Maybe just \n (newline) or \r etc?
							// But we are in the digit branch.
							// If it's not 3 digits, maybe it's just 1 or 2?
							// Go uses \nnn for octal.
							// Let's assume standard Go escapes.
							buf.WriteByte(s[i]) // Fallback
						}
					} else {
						switch s[i] {
						case 'n':
							buf.WriteByte('\n')
						case 'r':
							buf.WriteByte('\r')
						case 't':
							buf.WriteByte('\t')
						case '\\':
							buf.WriteByte('\\')
						case '"':
							buf.WriteByte('"')
						case 'x':
							// Hex escape \xNN
							if i+2 < len(s) {
								val, err := strconv.ParseInt(s[i+1:i+3], 16, 32)
								if err == nil {
									buf.WriteByte(byte(val))
									i += 2
								} else {
									buf.WriteByte('x')
								}
							} else {
								buf.WriteByte('x')
							}
						default:
							buf.WriteByte(s[i])
						}
					}
					inEscape = false
				} else {
					if s[i] == '\\' {
						inEscape = true
					} else {
						buf.WriteByte(s[i])
					}
				}
			}
			data = buf.Bytes()
			fmt.Fprintf(os.Stderr, "Warning: failed to unquote data using strconv.Unquote: %v. Used manual unescaping.\n", err)
		}
	}

	if analyze {
		if err := AnalyzeObject(data, chartFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing pod: %v\n", err)
			os.Exit(1)
		}
		return
	}

	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding v1 to scheme: %v\n", err)
		os.Exit(1)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding appsv1 to scheme: %v\n", err)
		os.Exit(1)
	}

	codecs := serializer.NewCodecFactory(scheme)
	deserializer := codecs.UniversalDeserializer()

	obj, gvk, err := deserializer.Decode(data, nil, nil)
	if err != nil {
		// Try raw protobuf decoding
		pod := &v1.Pod{}
		if err2 := pod.Unmarshal(data); err2 == nil {
			obj = pod

			// We need to construct a GVK pointer.
			kind := v1.SchemeGroupVersion.WithKind("Pod")
			gvk = &kind
		} else {
			fmt.Fprintf(os.Stderr, "Error decoding data: %v\n", err)
			fmt.Fprintf(os.Stderr, "Error decoding as raw proto: %v\n", err2)
			os.Exit(1)
		}
	}

	if gvk.GroupVersion() != v1.SchemeGroupVersion || gvk.Kind != "Pod" {
		// fmt.Fprintf(os.Stderr, "Unexpected object type: %s\n", gvk.String())
		// We can still print it, but warn the user.
		// Actually, let's just print what we found.
	}

	yamlData, err := yaml.Marshal(obj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling to YAML: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(yamlData))
}
