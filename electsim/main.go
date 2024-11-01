package main

import (
	"context"
	"fmt"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
	"sync"
	"time"
)

var refreshDuration = 10 * time.Second
var namespace = "default"

func main() {
	klog.InitFlags(nil)
	cfg, err := clientcmd.BuildConfigFromFlags("", "/home/serathius/.kube/config")
	if err != nil {
		panic(err)
	}
	cfg.QPS = 1500
	cfg.Burst = 1500
	cfg.ContentType = "application/vnd.kubernetes.protobuf"
	ctx := context.Background()
	wg := sync.WaitGroup{}
	locks := 1000
	membersPerLock := 3
	for i := 0; i < locks; i++ {
		for j := 0; j < membersPerLock; j++ {
			wg.Add(1)
			go func(leaseName, leaderName string) {
				defer wg.Done()
				elect(ctx, cfg, leaseName, leaderName)
			}(fmt.Sprintf("lease-%d", i), fmt.Sprintf("leader-%d", j))
		}
	}
	wg.Wait()
}

func elect(ctx context.Context, cfg *rest.Config, leaseName, leaderName string) {
	lock, err := resourcelock.NewFromKubeconfig(
		resourcelock.LeasesResourceLock,
		namespace,
		leaseName,
		resourcelock.ResourceLockConfig{
			Identity:      leaderName,
			EventRecorder: nil,
		},
		cfg,
		refreshDuration,
	)
	if err != err {
		panic(err)
	}
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: 10 * time.Second,
		RenewDeadline: 5 * time.Second,
		RetryPeriod:   2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				time.Sleep(time.Hour)
			},
			OnStoppedLeading: func() {
			},
		},
		WatchDog:        nil,
		ReleaseOnCancel: true,
		Name:            leaderName,
		Coordinated:     false,
	})
}
