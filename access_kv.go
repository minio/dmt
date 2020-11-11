// This file is part of Direct MinIO Tunnel
// Copyright (c) 2020 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

package main

import "sync"

type tenantAccessMap struct {
	sync.RWMutex
	KV map[string]string
}

func newTenantAccessMap() *tenantAccessMap {
	return &tenantAccessMap{
		KV: map[string]string{},
	}
}

func (ta *tenantAccessMap) Update(newKV map[string]string) {
	ta.Lock()
	defer ta.Unlock()
	ta.KV = map[string]string{}
	for k, v := range newKV {
		ta.KV[k] = v
	}
}

func (ta *tenantAccessMap) Get(k string) (v string, ok bool) {
	ta.RLock()
	defer ta.RUnlock()
	v, ok = ta.KV[k]
	return v, ok
}
