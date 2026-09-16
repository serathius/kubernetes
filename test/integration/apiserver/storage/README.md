# Storage Correctness Testing

Model-based correctness tests for the `storage.Interface` implementations backing the API
server: the raw etcd3 store and the watch cache (`cacher`).

Inspired by [etcd robustness testing](https://github.com/etcd-io/etcd/tree/main/tests/robustness).

## Correctness track record

Historical correctness bugs in `cacher` and `etcd3`, and whether this test suite can
reproduce them. A bug counts as reproducible once its fix has been reverted and
`TestCorrectness` has been observed to fail. All `Yes` entries were last confirmed at
[8eccbdafc25].

| Correctness / Consistency issue | Report | Component | Discovered by | Reproducible | Reproduction command |
| ------------------------------- | ------ | --------- | ------------- | ------------ | -------------------- |
| `GuaranteedUpdate` bases the update on a stale cached suggestion [#35415] | Oct 2016 | cacher | Maintainer | No, update is not covered | |
| Conflict on a stale suggestion is returned instead of retried against live data [#43152] | Mar 2017 | etcd3 | Maintainer | No, update is not covered | |
| `GuaranteedUpdate` skips the write when the stored data is not canonical [#48394] | Jul 2017 | etcd3 | Maintainer | No, update is not covered | |
| Watch events out of order when watching from RV=0 [#49745] | Jul 2017 | cacher | User | No, reason unknown | `make test-correctness-reproduction ISSUE=49745` |
| Patch of a custom resource fails against a stale cached suggestion [#54780] | Oct 2017 | etcd3 | User | No, update is not covered | |
| Delete notifications carry old ResourceVersion [#58545] | Jan 2018 | cacher | User | Yes | `make test-correctness-reproduction ISSUE=58545` |
| Re-watching from a DELETE event's RV replays events [#63356] | May 2018 | cacher | User | Yes | `make test-correctness-reproduction ISSUE=58545` |
| `validateDeletion` not re-run against live data after failing on a stale suggestion [#77619] | May 2019 | etcd3 | Maintainer | No, `validateDeletion` never fails | |
| Decoding an unstructured object from etcd loses the expected in-memory version [#78713] | Jun 2019 | etcd3 | Maintainer | No, unstructured objects are not covered | |
| Preconditioned delete on a stale suggestion returns a spurious conflict [#89828] | Apr 2020 | cacher | Maintainer | Yes | `make test-correctness-reproduction ISSUE=89828-precondition` |
| Delete of an already removed object reports success instead of NotFound [#89828] | Apr 2020 | cacher, etcd3 | Maintainer | Yes | `make test-correctness-reproduction ISSUE=89828-deleted-object` |
| Delete rewrites the ResourceVersion of the live cached object in place [#89828] | Apr 2020 | cacher | Maintainer | Yes | `make test-correctness-reproduction ISSUE=89828-deepcopy` |
| Inconsistent lists served from etcd when paging with a selector [#94002] | Aug 2020 | etcd3 | Maintainer | No, list is not covered | |
| API watch on pods misses container events [#94608] | Sep 2020 | unknown | User | No, update is not covered | |
| Missed events when watch starts during watch cache reinit [#116172] | Mar 2023 | cacher | Maintainer | No, the cache never re-initializes during a run | `make test-correctness-reproduction ISSUE=116172` |
| WatchList sends no `initial-events-end` bookmark when RV unset [#122805] | Jan 2024 | cacher | User | No, WatchList is not covered | |
| Non-recursive consistent list from the watch cache errors with "resource version too high" [#123674] | Mar 2024 | cacher | Maintainer | No, list is not covered | |
| Consistent list from the watch cache ignores `resourceVersion=0` [#123676] | Mar 2024 | cacher | Maintainer | No, list is not covered | |
| Watch of a single namespace missing all events [#125133] | May 2024 | cacher | User | Yes | `make test-correctness-reproduction ISSUE=125133` |
| Bookmark RV not synced to list RV [#125244] | May 2024 | cacher | CI flake | No, bookmarks are not requested | `make test-correctness-reproduction ISSUE=125244` |
| Non-recursive list from the watch cache returns items outside the key prefix [#125584] | Jun 2024 | cacher | Maintainer | No, list is not covered | |
| `sendInitialEvents` returns non-ADDED events before initial BOOKMARK [#134831] | Oct 2025 | cacher | User | No, WatchList is not covered | |
| Watch on an unrecognized (too large) RV hangs instead of erroring [#135452] | Nov 2025 | cacher, etcd3 | User | No, watch establishment errors are discarded | |
| Delete response carries the pre-delete ResourceVersion | n/a | cacher, etcd3 | Synthetic | Yes | `make test-correctness-reproduction ISSUE=58545-unary` |
| Get with no ResourceVersion served from a stale watch cache | n/a | cacher | Synthetic | Yes | `make test-correctness-reproduction ISSUE=stale-get` |

[8eccbdafc25]: https://github.com/kubernetes/kubernetes/tree/8eccbdafc25
[#35415]: https://github.com/kubernetes/kubernetes/pull/35415
[#43152]: https://github.com/kubernetes/kubernetes/pull/43152
[#48394]: https://github.com/kubernetes/kubernetes/pull/48394
[#49745]: https://github.com/kubernetes/kubernetes/issues/49745
[#54780]: https://github.com/kubernetes/kubernetes/pull/54780
[#58545]: https://github.com/kubernetes/kubernetes/issues/58545
[#63356]: https://github.com/kubernetes/kubernetes/issues/63356
[#77619]: https://github.com/kubernetes/kubernetes/pull/77619
[#78713]: https://github.com/kubernetes/kubernetes/pull/78713
[#89828]: https://github.com/kubernetes/kubernetes/pull/89828
[#94002]: https://github.com/kubernetes/kubernetes/pull/94002
[#94608]: https://github.com/kubernetes/kubernetes/issues/94608
[#116172]: https://github.com/kubernetes/kubernetes/pull/116172
[#122805]: https://github.com/kubernetes/kubernetes/issues/122805
[#123674]: https://github.com/kubernetes/kubernetes/pull/123674
[#123676]: https://github.com/kubernetes/kubernetes/pull/123676
[#125133]: https://github.com/kubernetes/kubernetes/issues/125133
[#125244]: https://github.com/kubernetes/kubernetes/issues/125244
[#125584]: https://github.com/kubernetes/kubernetes/pull/125584
[#134831]: https://github.com/kubernetes/kubernetes/issues/134831
[#135452]: https://github.com/kubernetes/kubernetes/issues/135452
