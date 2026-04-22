package main

import (
	"fmt"
	"os"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "raw-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "raw",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "nginx",
					Image: "nginx:latest",
				},
			},
		},
	}

	data, err := pod.Marshal()
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("raw-pod.bin", data, 0644); err != nil {
		panic(err)
	}
	fmt.Println("Wrote raw-pod.bin")
}
