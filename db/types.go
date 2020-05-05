package db

import "time"

type TokenData struct {
	Address       string
	Nonce         string
	Authenticated bool
	Timestamp     time.Time
}
