// Copyright 2022 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fake

func getRequest(key string) EtcdRequest {
	return rangeRequest(key, false, 0)
}

func rangeRequest(key string, withPrefix bool, limit int64) EtcdRequest {
	return EtcdRequest{Type: Txn, Txn: &TxnRequest{OperationsOnSuccess: []EtcdOperation{{Type: Range, Key: key, WithPrefix: withPrefix, Limit: limit}}}}
}

func txnRequest(conds []EtcdCondition, onSuccess, onFailure []EtcdOperation) EtcdRequest {
	return EtcdRequest{Type: Txn, Txn: &TxnRequest{Conditions: conds, OperationsOnSuccess: onSuccess, OperationsOnFailure: onFailure}}
}
