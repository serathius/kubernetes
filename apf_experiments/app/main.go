package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func main() {
	err := http.ListenAndServe(":1080", http.HandlerFunc(handle))
	fmt.Printf("Exit %s\n", err)
}

func handle(w http.ResponseWriter, r *http.Request) {
	req, err := parseRequestArguments(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(err.Error()))
		if err != nil {
			fmt.Printf("Failed to write response: %v\n", err)
			return
		}
		_, err = w.Write([]byte("\n"))
		if err != nil {
			fmt.Printf("Failed to write response: %v\n", err)
			return
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Printf("Got request %+v\n", req)
	stress(req)
	_, err = w.Write([]byte("OK\n"))
	if err != nil {
		fmt.Printf("Failed to write response: %v\n", err)
		return
	}
}

func parseRequestArguments(r *http.Request) (*Request, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	timeStr := r.Form.Get("time")
	if timeStr == "" {
		return nil, fmt.Errorf("missing time argument")
	}
	t, err := time.ParseDuration(timeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid time argument: %v", err)
	}
	if t < 0 {
		return nil, fmt.Errorf("time should be not negative")
	}
	if t < resolution {
		return nil, fmt.Errorf("time should be greater than %s", resolution)
	}
	allocateStr := r.Form.Get("allocate")
	if allocateStr == "" {
		return nil, fmt.Errorf("missing allocate argument")
	}
	allocate, err := strconv.ParseUint(allocateStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid allocate argument: %v", err)
	}
	loadStr := r.Form.Get("load")
	if loadStr == "" {
		return nil, fmt.Errorf("missing load argument")
	}
	load, err := strconv.ParseFloat(loadStr, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid load argument: %v", err)
	}
	if load < 0 {
		return nil, fmt.Errorf("load should be not negative")
	}
	if load > 1 {
		return nil, fmt.Errorf("load should be below 1")
	}
	return &Request{
		Time:     t,
		Allocate: allocate,
		Load:     load,
	}, nil

}

type Request struct {
	Time     time.Duration
	Load     float64
	Allocate uint64
}

var resolution = 10* time.Millisecond

func stress(r * Request) {
	start := time.Now()
	tmp := 0
	allocate := make([]byte, r.Allocate, r.Allocate)
	var timeLeft = r.Time
	var loadLeft = time.Duration(float64(r.Time) * r.Load)
	for time.Since(start) < r.Time {
		loadTime := time.Duration(float64(resolution) * float64(loadLeft) / float64(timeLeft))
		now := time.Now()
		for time.Since(now) < loadTime {
			tmp += 1
			allocate[tmp%len(allocate)] += 1
		}
		loadLeft -= loadTime
		time.Sleep(max(resolution - loadTime, 0))
		timeLeft -= time.Since(now)
	}
}
