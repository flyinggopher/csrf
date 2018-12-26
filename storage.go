// Copyright (c) 2018. Flying Gopher Authors
// license that can be found in the LICENSE file.

package csrf

import (
	"time"
	 "github.com/bradfitz/gomemcache/memcache"
)

type Storage struct {
	mc *memcache.Client
}

func NewStorage(cacheaddr string) *Storage {
	return &Storage{memcache.New(cacheaddr)}
}

func (s *Storage) SaveCSRF(csrf *CSRF) {
	mc.Set(&memcache.Item{Key: csrf.Token, Value: []byte(csrf.SessionID),Expiration: csrf.End.Unix()})
}

func (s *Storage) GetCSRF(token string) (*CSRF, error) {
	it, err := mc.Get(token)

	if err != nil {
		&CSRF{}, err
	}
	return &CSRF{string(it.Value), it.Expiration, token}, nil
}
