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
